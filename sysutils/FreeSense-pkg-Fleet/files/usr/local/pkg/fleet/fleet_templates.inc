<?php
/*
 * fleet_templates.inc
 *
 * part of FreeSense (https://www.freesense.org)
 * Copyright (c) 2026 The FreeSense Project
 * All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Templates push configuration to firewalls: a template holds items for
 * some firewalls (all, groups, single firewalls). The first kind is
 * firewall aliases (host, network, port).
 *
 * Fleet owns what it pushes: an alias it wrote starts its description
 * with "[Fleet:T<template id>]". Fleet only ever changes or removes
 * aliases with its own marker; a local alias with the same name is a
 * conflict, shown and skipped, never overwritten.
 *
 * Applying: the preview shows per firewall what is created, changed,
 * removed or left; the apply is an operation with one task per firewall
 * (safety backup, the changes staged, one filter reload). Drift: each
 * firewall's newest configuration backup is compared with its templates.
 */

require_once('fleet/fleet_store.inc');

define('FLEET_TEMPLATE_ALIAS_TYPES', array('host' => 'Hosts', 'network' => 'Networks', 'port' => 'Ports'));
define('FLEET_TEMPLATE_MAX_ITEMS', 200);
define('FLEET_TEMPLATE_MAX_ENTRIES', 5000);

/* ------------------------------------------------------------------ */
/* Pure                                                                */
/* ------------------------------------------------------------------ */

/* The node ids a template's targets mean now (label order). */
function fleet_template_nodes(array $targets): array {
	return array_column(fleet_targets_now($targets)[0], 'node_id');
}

/* pure: the description marker of a template. */
function fleet_template_marker(int $tid): string {
	return "[Fleet:T{$tid}]";
}

/* pure: the template id that owns a description, or null. */
function fleet_template_owner(string $descr): ?int {
	return preg_match('/^\[Fleet:T(\d+)\]/', $descr, $m) ? (int)$m[1] : null;
}

/* pure: one entry is valid for an alias type. */
function fleet_template_entry_ok(string $type, string $address): bool {
	switch ($type) {
	case 'host':
		return (filter_var($address, FILTER_VALIDATE_IP) !== false) ||
		    (bool)preg_match('/^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/iD', $address) ||
		    (bool)preg_match('/^[A-Za-z0-9_]{1,31}$/D', $address);
	case 'network':
		if (preg_match('#^(.+)/(\d{1,3})$#D', $address, $m)) {
			$v6 = filter_var($m[1], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false;
			$v4 = filter_var($m[1], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false;
			return ($v4 && ((int)$m[2] <= 32)) || ($v6 && ((int)$m[2] <= 128));
		}
		return fleet_template_entry_ok('host', $address);
	case 'port':
		if (preg_match('/^(\d{1,5})(:(\d{1,5}))?$/D', $address, $m)) {
			return ((int)$m[1] >= 1) && ((int)$m[1] <= 65535) && (!isset($m[3]) || (((int)$m[3] >= (int)$m[1]) && ((int)$m[3] <= 65535)));
		}
		return (bool)preg_match('/^[A-Za-z0-9_]{1,31}$/D', $address);
	}
	return false;
}

/*
 * pure: an alias item from the editor: name, type, description, entries
 * as text (one per line, "address  # detail"). Returns the item
 * {name, type, description, entries: [{address, detail}]} or throws.
 */
function fleet_template_alias_from(array $in): array {
	$name = trim((string)($in['name'] ?? ''));
	if (!preg_match('/^[A-Za-z0-9_]{1,31}$/D', $name) || preg_match('/^(pkg_|_)/', $name)) {
		throw new InvalidArgumentException('Alias names are 1 to 31 letters, digits or _, and do not start with _ or pkg_' . (($name !== '') ? " ({$name})." : '.'));
	}
	$type = (string)($in['type'] ?? '');
	if (!isset(FLEET_TEMPLATE_ALIAS_TYPES[$type])) {
		throw new InvalidArgumentException("{$name}: choose hosts, networks or ports.");
	}
	$descr = mb_substr(trim(preg_replace('/[\x00-\x1f\x7f]/u', ' ', (string)($in['description'] ?? ''))), 0, 200);
	$entries = array();
	foreach (preg_split('/\r\n|\r|\n/', (string)($in['entries'] ?? '')) as $line) {
		$parts = explode('#', $line, 2);
		$address = trim($parts[0]);
		if ($address === '') {
			continue;
		}
		$detail = mb_substr(trim(preg_replace('/[\x00-\x1f\x7f|]/u', ' ', $parts[1] ?? '')), 0, 200);
		if (!fleet_template_entry_ok($type, $address)) {
			throw new InvalidArgumentException("{$name}: \"{$address}\" is not a valid " . rtrim(strtolower(FLEET_TEMPLATE_ALIAS_TYPES[$type]), 's') . '.');
		}
		$entries[] = array('address' => $address, 'detail' => $detail);
	}
	if (empty($entries) || (count($entries) > FLEET_TEMPLATE_MAX_ENTRIES)) {
		throw new InvalidArgumentException("{$name}: give 1 to " . FLEET_TEMPLATE_MAX_ENTRIES . ' entries, one per line.');
	}
	return array('name' => $name, 'type' => $type, 'description' => $descr, 'entries' => $entries);
}

/* pure: the entries text of an item for the editor. */
function fleet_template_entries_text(array $entries): string {
	return implode("\n", array_map(function ($e) {
		return $e['address'] . (($e['detail'] !== '') ? '  # ' . $e['detail'] : '');
	}, $entries));
}

/* pure: what an alias looks like on the firewall when template $tid pushes item $item. */
function fleet_template_alias_body(int $tid, array $item): array {
	return array('name' => $item['name'], 'type' => $item['type'],
	    'description' => trim(fleet_template_marker($tid) . ' ' . $item['description']), 'entries' => $item['entries']);
}

/*
 * pure: what applying template $tid ($items) to a firewall with these
 * aliases ($remote: the REST form {name, type, description, entries})
 * takes. Returns a list of {action: create | update | delete | same |
 * conflict, name, detail}; conflicts are never acted on.
 */
function fleet_template_plan(int $tid, array $items, array $remote): array {
	$have = array();
	foreach ($remote as $a) {
		if (is_array($a) && isset($a['name'])) {
			$have[strtolower((string)$a['name'])] = $a;
		}
	}
	$norm = function (array $entries) {
		return array_map(function ($e) { return array((string)($e['address'] ?? ''), (string)($e['detail'] ?? '')); }, $entries);
	};
	$out = array();
	$wanted = array();
	foreach ($items as $item) {
		$key = strtolower($item['name']);
		$wanted[$key] = true;
		$body = fleet_template_alias_body($tid, $item);
		$cur = $have[$key] ?? null;
		if ($cur === null) {
			$out[] = array('action' => 'create', 'name' => $item['name'], 'detail' => sprintf('%d entries', count($item['entries'])));
			continue;
		}
		$owner = fleet_template_owner((string)($cur['description'] ?? ''));
		if ($owner !== $tid) {
			$out[] = array('action' => 'conflict', 'name' => $item['name'], 'detail' => ($owner === null) ?
			    'The firewall has its own alias with this name' : "Template {$owner} already manages this alias");
			continue;
		}
		$changes = array();
		if ($cur['type'] !== $body['type']) {
			$changes[] = "type {$cur['type']} to {$body['type']}";
		}
		$a = $norm((array)($cur['entries'] ?? array()));
		$b = $norm($body['entries']);
		if ($a !== $b) {
			$add = count(array_diff(array_column($b, 0), array_column($a, 0)));
			$rem = count(array_diff(array_column($a, 0), array_column($b, 0)));
			$changes[] = ($add || $rem) ? sprintf('+%d -%d entries', $add, $rem) : 'entry details';
		}
		if ((string)($cur['description'] ?? '') !== $body['description']) {
			$changes[] = 'description';
		}
		$out[] = empty($changes) ? array('action' => 'same', 'name' => $item['name'], 'detail' => '') :
		    array('action' => 'update', 'name' => $item['name'], 'detail' => implode(', ', $changes));
	}
	foreach ($have as $key => $cur) {
		if (!isset($wanted[$key]) && (fleet_template_owner((string)($cur['description'] ?? '')) === $tid)) {
			$out[] = array('action' => 'delete', 'name' => (string)$cur['name'], 'detail' => 'No longer in the template');
		}
	}
	return $out;
}

/* pure: counts of a plan by action. */
function fleet_template_plan_counts(array $plan): array {
	$c = array('create' => 0, 'update' => 0, 'delete' => 0, 'same' => 0, 'conflict' => 0);
	foreach ($plan as $p) {
		$c[$p['action']]++;
	}
	return $c;
}

/* pure: the aliases in a configuration (config.xml text), in the REST form. */
function fleet_template_aliases_in_config(string $xml): ?array {
	$prev = libxml_use_internal_errors(true);
	$doc = simplexml_load_string($xml, 'SimpleXMLElement', LIBXML_NONET);
	libxml_use_internal_errors($prev);
	if ($doc === false) {
		return null;
	}
	$out = array();
	foreach ($doc->aliases->alias ?? array() as $a) {
		$addresses = ((string)$a->address === '') ? array() : explode(' ', (string)$a->address);
		$details = ((string)$a->detail === '') ? array() : explode('||', (string)$a->detail);
		$entries = array();
		foreach ($addresses as $i => $address) {
			$entries[] = array('address' => $address, 'detail' => $details[$i] ?? '');
		}
		$out[] = array('name' => (string)$a->name, 'type' => (string)$a->type, 'description' => (string)$a->descr, 'entries' => $entries);
	}
	return $out;
}

/* ------------------------------------------------------------------ */
/* Storage                                                             */
/* ------------------------------------------------------------------ */

function fleet_template_row(array $r): array {
	$r['targets'] = json_decode((string)$r['targets'], true) ?: array();
	$r['items'] = json_decode((string)$r['items'], true) ?: array();
	return $r;
}

function fleet_templates_all(): array {
	return array_map('fleet_template_row', fleet_db()->query('SELECT * FROM templates ORDER BY name COLLATE NOCASE')->fetchAll());
}

function fleet_template_get(int $id): ?array {
	$q = fleet_db()->prepare('SELECT * FROM templates WHERE id = ?');
	$q->execute(array($id));
	$r = $q->fetch();
	return is_array($r) ? fleet_template_row($r) : null;
}

/* Create or change a template from its form: name, description, targets[], alias[n][name|type|description|entries]. */
function fleet_template_save(?int $id, array $in, string $who): int {
	$name = trim((string)($in['name'] ?? ''));
	if (($name === '') || (strlen($name) > 60) || preg_match('/[<>\x00-\x1f\x7f]/', $name)) {
		throw new InvalidArgumentException('Give the template a name of 1 to 60 characters.');
	}
	$desc = mb_substr(trim(preg_replace('/[\x00-\x1f\x7f]/u', ' ', (string)($in['description'] ?? ''))), 0, 300);
	$targets = fleet_targets_from($in['targets'] ?? array());
	list(, $gone) = fleet_targets_now($targets);
	if (!empty($gone)) {
		throw new InvalidArgumentException('A chosen group or firewall does not exist any more. Choose again.');
	}
	$items = array();
	$seen = array();
	foreach ((array)($in['alias'] ?? array()) as $a) {
		if (!is_array($a) || ((trim((string)($a['name'] ?? '')) === '') && (trim((string)($a['entries'] ?? '')) === ''))) {
			continue;
		}
		$item = fleet_template_alias_from($a);
		if (isset($seen[strtolower($item['name'])])) {
			throw new InvalidArgumentException("The alias {$item['name']} is in the template twice.");
		}
		$seen[strtolower($item['name'])] = true;
		$items[] = $item;
	}
	if (empty($items) || (count($items) > FLEET_TEMPLATE_MAX_ITEMS)) {
		throw new InvalidArgumentException('Add 1 to ' . FLEET_TEMPLATE_MAX_ITEMS . ' aliases.');
	}
	$q = fleet_db()->prepare('SELECT COUNT(*) FROM templates WHERE name = ? COLLATE NOCASE AND id != ?');
	$q->execute(array($name, $id ?? 0));
	if ((int)$q->fetchColumn() > 0) {
		throw new InvalidArgumentException('There is already a template with that name.');
	}
	/* Another template must not push an alias with the same name to the same firewalls. */
	$mine = fleet_template_nodes($targets);
	foreach (fleet_templates_all() as $t) {
		if ((int)$t['id'] === (int)$id) {
			continue;
		}
		$both = array_intersect($mine, fleet_template_nodes($t['targets']));
		$dup = array_intersect(array_map('strtolower', array_column($items, 'name')), array_map('strtolower', array_column($t['items'], 'name')));
		if (!empty($both) && !empty($dup)) {
			throw new InvalidArgumentException(sprintf('The template "%s" already pushes %s to some of these firewalls.', $t['name'], implode(', ', $dup)));
		}
	}
	$args = array($name, $desc, json_encode($targets), json_encode($items), time(), $who);
	if ($id === null) {
		fleet_db()->prepare('INSERT INTO templates (name, description, targets, items, updated, who, created) VALUES (?, ?, ?, ?, ?, ?, ?)')
		    ->execute(array_merge($args, array(time())));
		$id = (int)fleet_db()->lastInsertId();
	} else {
		fleet_db()->prepare('UPDATE templates SET name = ?, description = ?, targets = ?, items = ?, updated = ?, who = ? WHERE id = ?')
		    ->execute(array_merge($args, array($id)));
	}
	fleet_audit($who, 'template', sprintf('%s: %d aliases for %s (not applied yet)', $name, count($items), fleet_targets_text($targets, fleet_target_names())));
	return $id;
}

/* Delete a template. What it pushed stays on the firewalls (Fleet stops managing it). */
function fleet_template_delete(int $id, string $who): void {
	$t = fleet_template_get($id);
	fleet_db()->prepare('DELETE FROM templates WHERE id = ?')->execute(array($id));
	fleet_db()->prepare('DELETE FROM template_state WHERE template_id = ?')->execute(array($id));
	fleet_audit($who, 'template', ($t['name'] ?? (string)$id) . ': deleted; its aliases stay on the firewalls');
}

/* ------------------------------------------------------------------ */
/* Preview, apply, drift                                               */
/* ------------------------------------------------------------------ */

/* A firewall's aliases now, over the tunnel. */
function fleet_template_remote(array $box): array {
	list($code, $json) = fleet_box_call($box, 'GET', '/api/v1/firewall/aliases');
	if (($code !== 200) || !is_array($json['data'] ?? null)) {
		throw new RuntimeException('The aliases could not be read: ' . fleet_box_error($code, $json));
	}
	return $json['data'];
}

/* Plan from the newest configuration backup (no network); null when there is none. */
function fleet_template_plan_from_backup(array $t, string $node): ?array {
	$latest = fleet_backup_latest($node);
	$text = ($latest === null) ? null : fleet_backup_read($latest);
	$aliases = ($text === null) ? null : fleet_template_aliases_in_config($text);
	return ($aliases === null) ? null : fleet_template_plan((int)$t['id'], $t['items'], $aliases);
}

/*
 * Apply a template to one firewall: safety backup, the changes staged,
 * one reload. Conflicts are skipped. $progress(text, percent). Returns
 * the words for the result; throws RuntimeException on failure.
 */
function fleet_template_apply_box(array $t, array $box, string $who, ?callable $progress = null): string {
	fleet_manage_require($box);
	$say = $progress ?? function () {};
	$say('Reading the aliases', 10);
	$plan = fleet_template_plan((int)$t['id'], $t['items'], fleet_template_remote($box));
	$c = fleet_template_plan_counts($plan);
	$todo = $c['create'] + $c['update'] + $c['delete'];
	$hash = hash('sha256', json_encode($t['items']));
	if ($todo === 0) {
		fleet_template_state_set((int)$t['id'], $box['node_id'], $hash, 'done', ($c['conflict'] > 0) ? sprintf('In sync; %d conflicts skipped', $c['conflict']) : 'In sync');
		return ($c['conflict'] > 0) ? sprintf('Nothing to change; %d conflicts skipped.', $c['conflict']) : 'Already in sync.';
	}
	$say('Safety backup', 20);
	fleet_backup_box($box, 'template', $who);
	$items = array();
	foreach ($t['items'] as $item) {
		$items[strtolower($item['name'])] = $item;
	}
	$n = 0;
	$errors = array();
	foreach ($plan as $p) {
		if (!in_array($p['action'], array('create', 'update', 'delete'), true)) {
			continue;
		}
		$n++;
		$say(ucfirst($p['action']) . ' ' . $p['name'], 20 + (int)(60 * $n / $todo));
		if ($p['action'] === 'delete') {
			list($code, $json) = fleet_box_call($box, 'DELETE', '/api/v1/firewall/aliases/' . rawurlencode($p['name']));
		} else {
			$body = fleet_template_alias_body((int)$t['id'], $items[strtolower($p['name'])]);
			list($code, $json) = ($p['action'] === 'create') ? fleet_box_call($box, 'POST', '/api/v1/firewall/aliases', $body) :
			    fleet_box_call($box, 'PUT', '/api/v1/firewall/aliases/' . rawurlencode($p['name']), $body);
		}
		if (($code < 200) || ($code >= 300)) {
			$errors[] = $p['name'] . ': ' . fleet_box_error($code, $json);
		}
	}
	$say('Reloading the filter', 85);
	list($code, $json) = fleet_box_call($box, 'POST', '/api/v1/firewall/aliases/apply');
	if (($code < 200) || ($code >= 300)) {
		$errors[] = 'Reload: ' . fleet_box_error($code, $json);
	}
	try {
		fleet_backup_box($box, 'change', $who);
	} catch (RuntimeException $e) {
	}
	$words = sprintf('%d created, %d changed, %d removed', $c['create'], $c['update'], $c['delete']) . (($c['conflict'] > 0) ? sprintf(', %d conflicts skipped', $c['conflict']) : '');
	if (!empty($errors)) {
		fleet_template_state_set((int)$t['id'], $box['node_id'], $hash, 'failed', implode('; ', $errors));
		fleet_audit($who, 'template', "{$t['name']} on {$box['label']}: " . implode('; ', $errors));
		throw new RuntimeException(implode('; ', $errors));
	}
	fleet_template_state_set((int)$t['id'], $box['node_id'], $hash, 'done', $words);
	fleet_audit($who, 'template', "{$t['name']} on {$box['label']}: {$words}");
	return $words . '.';
}

function fleet_template_state_set(int $tid, string $node, string $hash, string $result, string $detail): void {
	fleet_db()->prepare('INSERT OR REPLACE INTO template_state (template_id, node_id, hash, applied, result, detail) VALUES (?, ?, ?, ?, ?, ?)')
	    ->execute(array($tid, $node, $hash, time(), $result, $detail));
}

/* node_id => state row, for one template. */
function fleet_template_states(int $tid): array {
	$q = fleet_db()->prepare('SELECT * FROM template_state WHERE template_id = ?');
	$q->execute(array($tid));
	return array_column($q->fetchAll(), null, 'node_id');
}

/* Start applying a template to its firewalls (or $only) in the background. Returns the operation id. */
function fleet_template_launch(array $t, string $who, ?array $only = null): int {
	$nodes = fleet_template_nodes($t['targets']);
	if ($only !== null) {
		$nodes = array_values(array_intersect($nodes, $only));
	}
	if (empty($nodes)) {
		throw new RuntimeException('The template is for no firewall.');
	}
	$op = fleet_op_group_start('template', 'Apply template ' . $t['name'], $who);
	foreach ($nodes as $node) {
		$box = fleet_box_get($node);
		if ($box === null) {
			continue;
		}
		if (!fleet_manage_allowed($box)) {
			fleet_op_set(fleet_op_start($node, 'template', '', $who, $op, 'skipped'), 'skipped', 'Skipped: monitor only');
		} elseif ($box['state'] !== 'online') {
			fleet_op_set(fleet_op_start($node, 'template', '', $who, $op, 'skipped'), 'skipped', 'Skipped: the firewall is ' . $box['state']);
		} else {
			fleet_op_start($node, 'template', 'Waiting', $who, $op, 'queued');
		}
	}
	fleet_op_group_update($op);
	fleet_audit($who, 'template', sprintf('%s: applying to %d firewalls', $t['name'], count($nodes)));
	mwexec_bg('/usr/local/bin/php /usr/local/sbin/freesense-fleet-run template ' . (int)$op . ' ' . (int)$t['id']);
	return $op;
}
