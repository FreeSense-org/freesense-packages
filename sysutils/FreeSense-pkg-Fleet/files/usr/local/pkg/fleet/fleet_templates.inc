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

/*
 * Ready-made starting points: a starter fills the editor; nothing is saved
 * until the admin saves it. Entries are "address  # note" lines.
 */
function fleet_template_starters(): array {
	return array(
		'private' => array('icon' => 'fa-house-lock', 'name' => 'Private networks', 'description' => 'Every private and local address range, for rules like "block private networks on WAN" or "allow LAN only".',
		    'aliases' => array(
			array('name' => 'fleet_private_v4', 'type' => 'network', 'description' => 'Private IPv4 ranges (RFC 1918) and CGNAT',
			    'entries' => "10.0.0.0/8  # RFC 1918\n172.16.0.0/12  # RFC 1918\n192.168.0.0/16  # RFC 1918\n100.64.0.0/10  # CGNAT (RFC 6598)"),
			array('name' => 'fleet_private_v6', 'type' => 'network', 'description' => 'Unique local and link-local IPv6',
			    'entries' => "fc00::/7  # Unique local (RFC 4193)\nfe80::/10  # Link-local"),
		)),
		'mgmt' => array('icon' => 'fa-screwdriver-wrench', 'name' => 'Management access', 'description' => 'The ports used to manage firewalls, and a list for the networks admins work from (fill in yours).',
		    'aliases' => array(
			array('name' => 'fleet_mgmt_ports', 'type' => 'port', 'description' => 'Firewall management', 'entries' => "22  # SSH\n443  # WebGUI\n8443  # Fleet join"),
			array('name' => 'fleet_admin_nets', 'type' => 'network', 'description' => 'Networks admins work from', 'entries' => "192.0.2.0/24  # Replace with your admin network"),
		)),
		'web' => array('icon' => 'fa-globe', 'name' => 'Web services', 'description' => 'Ports for web servers and proxies, for publishing or allowing web traffic.',
		    'aliases' => array(
			array('name' => 'fleet_web_ports', 'type' => 'port', 'description' => 'Web', 'entries' => "80  # HTTP\n443  # HTTPS\n8080  # HTTP alternative\n8443  # HTTPS alternative"),
		)),
		'mail' => array('icon' => 'fa-envelope', 'name' => 'Mail', 'description' => 'Ports for sending and reading mail.',
		    'aliases' => array(
			array('name' => 'fleet_mail_ports', 'type' => 'port', 'description' => 'Mail', 'entries' => "25  # SMTP\n465  # SMTPS\n587  # Submission\n993  # IMAPS\n995  # POP3S"),
		)),
		'dns' => array('icon' => 'fa-signs-post', 'name' => 'Public DNS resolvers', 'description' => 'Well-known public resolvers and the DNS ports, for allowing (or blocking) DNS that bypasses your own resolver.',
		    'aliases' => array(
			array('name' => 'fleet_public_dns', 'type' => 'host', 'description' => 'Public DNS resolvers',
			    'entries' => "1.1.1.1  # Cloudflare\n1.0.0.1  # Cloudflare\n8.8.8.8  # Google\n8.8.4.4  # Google\n9.9.9.9  # Quad9\n149.112.112.112  # Quad9\n2606:4700:4700::1111  # Cloudflare\n2001:4860:4860::8888  # Google\n2620:fe::fe  # Quad9"),
			array('name' => 'fleet_dns_ports', 'type' => 'port', 'description' => 'DNS', 'entries' => "53  # DNS\n853  # DNS over TLS"),
		)),
		'ad' => array('icon' => 'fa-building', 'name' => 'Windows domain', 'description' => 'The ports Active Directory clients use to reach domain controllers (add your controllers to the host list).',
		    'aliases' => array(
			array('name' => 'fleet_ad_ports', 'type' => 'port', 'description' => 'Active Directory',
			    'entries' => "53  # DNS\n88  # Kerberos\n135  # RPC\n389  # LDAP\n445  # SMB\n464  # Kerberos password\n636  # LDAPS\n3268:3269  # Global catalog\n49152:65535  # RPC dynamic"),
			array('name' => 'fleet_ad_servers', 'type' => 'host', 'description' => 'Domain controllers', 'entries' => "192.0.2.10  # Replace with your domain controllers"),
		)),
		'voip' => array('icon' => 'fa-phone', 'name' => 'VoIP', 'description' => 'SIP signalling and the usual RTP media range for phones and PBXs.',
		    'aliases' => array(
			array('name' => 'fleet_sip_ports', 'type' => 'port', 'description' => 'SIP', 'entries' => "5060  # SIP\n5061  # SIP over TLS"),
			array('name' => 'fleet_rtp_ports', 'type' => 'port', 'description' => 'RTP media', 'entries' => "10000:20000  # RTP"),
		)),
	);
}

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
	$r['kind'] = (string)($r['kind'] ?? 'aliases');
	$r['settings'] = json_decode((string)($r['settings'] ?? ''), true) ?: array();
	return $r;
}

/* A settings template's values with its secret (the SNMP community) opened, for sending and hashing. */
function fleet_template_settings_open(array $t): array {
	$s = $t['settings'];
	if (isset($s['rocommunity']) && ($s['rocommunity'] !== '')) {
		$s['rocommunity'] = (string)fleet_unseal((string)$s['rocommunity'], fleet_master_key());
	}
	return $s;
}

/* What a template wants, as a hash (the state of each firewall keeps it, so a changed template shows as "to apply"). */
function fleet_template_hash(array $t): string {
	return hash('sha256', json_encode((($t['kind'] === 'aliases') || isset(FLEET_TLIST_KINDS[$t['kind']])) ? $t['items'] : fleet_template_settings_open($t)));
}

/* Save a settings template (time, DNS, SNMP, remote logging). */
function fleet_template_save_settings(?int $id, string $kind, string $name, string $desc, array $targets, array $in, string $who): int {
	$old = ($id !== null) ? fleet_template_get($id) : null;
	$settings = fleet_tset_from($kind, $in, ($old !== null) ? fleet_template_settings_open($old) : array());
	/* A firewall has one of each setting: two templates of a kind must not meet on a firewall. */
	$mine = fleet_template_nodes($targets);
	foreach (fleet_templates_all() as $t) {
		if (((int)$t['id'] !== (int)$id) && ($t['kind'] === $kind) && !empty(array_intersect($mine, fleet_template_nodes($t['targets'])))) {
			throw new InvalidArgumentException(sprintf('The template "%s" already sets %s on some of these firewalls. A firewall can have one of each.', $t['name'],
			    strtolower(FLEET_TSET_KINDS[$kind][0])));
		}
	}
	if (isset($settings['rocommunity'])) {
		$settings['rocommunity'] = ($settings['rocommunity'] === '') ? '' : fleet_seal($settings['rocommunity'], fleet_master_key());
	}
	$args = array($name, $desc, json_encode($targets), '[]', json_encode($settings), time(), $who);
	if ($id === null) {
		fleet_db()->prepare('INSERT INTO templates (name, description, targets, items, settings, updated, who, kind, created) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)')
		    ->execute(array_merge($args, array($kind, time())));
		$id = (int)fleet_db()->lastInsertId();
	} else {
		fleet_db()->prepare('UPDATE templates SET name = ?, description = ?, targets = ?, items = ?, settings = ?, updated = ?, who = ? WHERE id = ?')
		    ->execute(array_merge($args, array($id)));
	}
	$shown = $settings;
	unset($shown['rocommunity']);
	fleet_audit($who, 'template', sprintf('%s (%s): %s for %s (not applied yet)', $name, FLEET_TSET_KINDS[$kind][0], fleet_tset_summary($kind, $shown + array('rocommunity' => '')),
	    fleet_targets_text($targets, fleet_target_names())));
	return $id;
}

/* pure: a settings difference as plan rows (the alias plan's shape, so lists and previews show both alike). */
function fleet_template_settings_plan(string $kind, array $diff): array {
	$out = array();
	foreach ($diff as list($field, $label, $from, $to)) {
		$out[] = array('action' => 'update', 'name' => $label, 'detail' => "{$from} -> {$to}", 'field' => $field);
	}
	return empty($out) ? array(array('action' => 'same', 'name' => FLEET_TSET_KINDS[$kind][0], 'detail' => '')) : $out;
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
	/* The kind of a template never changes; a new one says it in the form. */
	$existing = ($id !== null) ? fleet_template_get($id) : null;
	$kind = ($existing !== null) ? $existing['kind'] : (string)($in['kind'] ?? 'aliases');
	if (($kind !== 'aliases') && !isset(FLEET_TSET_KINDS[$kind]) && !isset(FLEET_TLIST_KINDS[$kind])) {
		throw new InvalidArgumentException('Unknown template kind.');
	}
	$q = fleet_db()->prepare('SELECT COUNT(*) FROM templates WHERE name = ? COLLATE NOCASE AND id != ?');
	$q->execute(array($name, $id ?? 0));
	if ((int)$q->fetchColumn() > 0) {
		throw new InvalidArgumentException('There is already a template with that name.');
	}
	if (isset(FLEET_TLIST_KINDS[$kind])) {
		return fleet_template_save_list($id, $kind, $name, $desc, $targets, fleet_tlist_items_from($kind, (array)($in['row'] ?? array())), $who);
	}
	if ($kind !== 'aliases') {
		return fleet_template_save_settings($id, $kind, $name, $desc, $targets, $in, $who);
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
		if (((int)$t['id'] === (int)$id) || ($t['kind'] !== 'aliases')) {
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

/* Save a rule or port forward template. */
function fleet_template_save_list(?int $id, string $kind, string $name, string $desc, array $targets, array $items, string $who): int {
	$args = array($name, $desc, json_encode($targets), json_encode($items), time(), $who);
	if ($id === null) {
		fleet_db()->prepare('INSERT INTO templates (name, description, targets, items, updated, who, created, kind) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
		    ->execute(array_merge($args, array(time(), $kind)));
		$id = (int)fleet_db()->lastInsertId();
	} else {
		fleet_db()->prepare('UPDATE templates SET name = ?, description = ?, targets = ?, items = ?, updated = ?, who = ? WHERE id = ?')
		    ->execute(array_merge($args, array($id)));
	}
	fleet_audit($who, 'template', sprintf('%s: %d %s for %s (not applied yet)', $name, count($items), strtolower(FLEET_TLIST_KINDS[$kind][0]),
	    fleet_targets_text($targets, fleet_target_names())));
	return $id;
}

/* Delete a template. What it pushed stays on the firewalls (Fleet stops managing it). */
function fleet_template_delete(int $id, string $who): void {
	$t = fleet_template_get($id);
	fleet_db()->prepare('DELETE FROM templates WHERE id = ?')->execute(array($id));
	fleet_db()->prepare('DELETE FROM template_state WHERE template_id = ?')->execute(array($id));
	fleet_db()->prepare('DELETE FROM template_ignores WHERE template_id = ?')->execute(array($id));
	fleet_audit($who, 'template', ($t['name'] ?? (string)$id) . ': deleted; ' . ((($t['kind'] ?? 'aliases') === 'aliases') ? 'its aliases stay on the firewalls' : 'the firewalls keep their settings'));
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

/* Plan read from the firewall now, over the tunnel (either kind). */
function fleet_template_live_plan(array $t, array $box): array {
	if ($t['kind'] === 'aliases') {
		return fleet_template_plan((int)$t['id'], $t['items'], fleet_template_remote($box));
	}
	if (isset(FLEET_TLIST_KINDS[$t['kind']])) {
		return fleet_tlist_plan($t['kind'], (int)$t['id'], $t['items'], fleet_tlist_remote($t['kind'], $box));
	}
	return fleet_template_settings_plan($t['kind'], fleet_tset_diff($t['kind'], $t['settings'], fleet_template_settings_remote($t['kind'], $box)));
}

/* A firewall's settings of a kind now, over the tunnel. */
function fleet_template_settings_remote(string $kind, array $box): array {
	$need = FLEET_TSET_KINDS[$kind][4];
	$st = json_decode((string)($box['status'] ?? ''), true) ?: array();
	if ((int)($st['api_level'] ?? 0) < $need) {
		throw new RuntimeException(sprintf('FLEET-E401: This firewall is too old for %s templates (it needs the System update with API level %d).', strtolower(FLEET_TSET_KINDS[$kind][0]), $need));
	}
	list($code, $json) = fleet_box_call($box, 'GET', FLEET_TSET_KINDS[$kind][3]);
	if (($code !== 200) || !is_array($json['data'] ?? null)) {
		throw new RuntimeException('The settings could not be read: ' . fleet_box_error($code, $json));
	}
	return fleet_tset_current($kind, $json['data']);
}

/* Plan from the newest configuration backup (no network); null when there is none. */
function fleet_template_plan_from_backup(array $t, string $node): ?array {
	$latest = fleet_backup_latest($node);
	$text = ($latest === null) ? null : fleet_backup_read($latest);
	if (isset(FLEET_TLIST_KINDS[$t['kind']])) {
		$list = ($text === null) ? null : fleet_tlist_from_config($t['kind'], $text);
		return ($list === null) ? null : fleet_tlist_plan($t['kind'], (int)$t['id'], $t['items'], $list);
	}
	if ($t['kind'] !== 'aliases') {
		$cur = ($text === null) ? null : fleet_tset_from_config($t['kind'], $text);
		return ($cur === null) ? null : fleet_template_settings_plan($t['kind'], fleet_tset_diff($t['kind'], $t['settings'], $cur));
	}
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
	if (isset(FLEET_TLIST_KINDS[$t['kind']])) {
		return fleet_tlist_apply_box($t, $box, $who, $progress);
	}
	if ($t['kind'] !== 'aliases') {
		return fleet_template_apply_settings($t, $box, $who, $progress);
	}
	$say = $progress ?? function () {};
	$say('Reading the aliases', 10);
	$plan = fleet_template_plan((int)$t['id'], $t['items'], fleet_template_remote($box));
	$c = fleet_template_plan_counts($plan);
	$todo = $c['create'] + $c['update'] + $c['delete'];
	$hash = fleet_template_hash($t);
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
	$ignored = fleet_template_ignores((int)$t['id']);
	foreach ($nodes as $node) {
		$box = fleet_box_get($node);
		if ($box === null) {
			continue;
		}
		if (isset($ignored[$node]) && ($only === null)) {
			fleet_op_set(fleet_op_start($node, 'template', '', $who, $op, 'skipped'), 'skipped', 'Skipped: ignored (' . $ignored[$node]['reason'] . ')');
		} elseif (!fleet_manage_allowed($box)) {
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

/*
 * Apply a settings template to one firewall: read, compare, safety
 * backup, one PUT with the template's values. A secret that cannot be
 * read back (the SNMP community) is sent whenever the template changed
 * since it was last applied here. Returns the words for the result.
 */
function fleet_template_apply_settings(array $t, array $box, string $who, ?callable $progress = null): string {
	$say = $progress ?? function () {};
	$kind = $t['kind'];
	$want = fleet_template_settings_open($t);
	$hash = fleet_template_hash($t);
	$say('Reading the settings', 15);
	$diff = fleet_tset_diff($kind, $want, fleet_template_settings_remote($kind, $box));
	$applied = fleet_template_states((int)$t['id'])[$box['node_id']] ?? null;
	$secret_changed = isset($want['rocommunity']) && !empty($want['enable']) && (($applied === null) || ($applied['hash'] !== $hash) || ($applied['result'] !== 'done'));
	if (empty($diff) && !$secret_changed) {
		fleet_template_state_set((int)$t['id'], $box['node_id'], $hash, 'done', 'In sync');
		return 'Already in sync.';
	}
	$say('Safety backup', 30);
	fleet_backup_box($box, 'template', $who);
	$say('Changing ' . strtolower(FLEET_TSET_KINDS[$kind][0]), 60);
	list($code, $json) = fleet_box_call($box, 'PUT', FLEET_TSET_KINDS[$kind][3], fleet_tset_body($kind, $want));
	if (($code < 200) || ($code >= 300)) {
		$err = fleet_box_error($code, $json);
		fleet_template_state_set((int)$t['id'], $box['node_id'], $hash, 'failed', $err);
		fleet_audit($who, 'template', "{$t['name']} on {$box['label']}: {$err}");
		throw new RuntimeException($err);
	}
	try {
		fleet_backup_box($box, 'change', $who);
	} catch (RuntimeException $e) {
	}
	$words = empty($diff) ? 'The community was sent' : implode('; ', array_map(function ($d) { return "{$d[1]}: {$d[2]} -> {$d[3]}"; }, $diff));
	fleet_template_state_set((int)$t['id'], $box['node_id'], $hash, 'done', $words);
	fleet_audit($who, 'template', "{$t['name']} on {$box['label']}: {$words}");
	return $words . '.';
}

/* ------------------------------------------------------------------ */
/* Drift: adopt the firewall's version, or ignore the firewall         */
/* ------------------------------------------------------------------ */

/* node_id => {reason, who, time} for the firewalls a template leaves alone. */
function fleet_template_ignores(int $tid): array {
	$q = fleet_db()->prepare('SELECT node_id, reason, who, time FROM template_ignores WHERE template_id = ?');
	$q->execute(array($tid));
	return array_column($q->fetchAll(), null, 'node_id');
}

/* Leave a firewall alone (its local values win) until someone stops ignoring it. Applying "here" still works. */
function fleet_template_ignore(array $t, string $node, string $reason, string $who): void {
	$reason = mb_substr(trim(preg_replace('/[\x00-\x1f\x7f]/u', ' ', $reason)), 0, 200);
	if ($reason === '') {
		throw new InvalidArgumentException('Say why this firewall keeps its own values (for the next person).');
	}
	fleet_db()->prepare('INSERT OR REPLACE INTO template_ignores (template_id, node_id, reason, who, time) VALUES (?, ?, ?, ?, ?)')
	    ->execute(array((int)$t['id'], $node, $reason, $who, time()));
	$label = fleet_box_get($node)['label'] ?? $node;
	fleet_audit($who, 'template', "{$t['name']}: {$label} ignored ({$reason})");
}

function fleet_template_unignore(array $t, string $node, string $who): void {
	fleet_db()->prepare('DELETE FROM template_ignores WHERE template_id = ? AND node_id = ?')->execute(array((int)$t['id'], $node));
	$label = fleet_box_get($node)['label'] ?? $node;
	fleet_audit($who, 'template', "{$t['name']}: {$label} no longer ignored");
}

/*
 * pure: a template with one firewall's version taken in. Aliases: the
 * template's aliases that differ on the firewall get its entries and
 * description (aliases it does not have are kept; the firewall's other
 * aliases are not taken). Settings: the firewall's values (a secret the
 * firewall cannot show is kept). Returns array(template fields, what
 * changed).
 */
function fleet_template_adopted(array $t, array $remote): array {
	$changed = array();
	if (isset(FLEET_TLIST_KINDS[$t['kind']])) {
		$by = array();
		foreach ($remote as $r) {
			$o = is_array($r) ? fleet_tlist_owner((string)($r['descr'] ?? '')) : null;
			if (($o !== null) && ($o[0] === (int)$t['id'])) {
				$by[$o[1]] = $r;
			}
		}
		$items = $t['items'];
		foreach ($items as &$item) {
			$now = isset($by[$item['key']]) ? fleet_tlist_item_from_raw($t['kind'], $item['key'], $by[$item['key']]) : null;
			if (($now !== null) && ($now !== $item)) {
				$item = $now;
				$changed[] = $item['key'];
			}
		}
		unset($item);
		return array(array('items' => $items), $changed);
	}
	if ($t['kind'] === 'aliases') {
		$by = array();
		foreach ($remote as $a) {
			$by[strtolower((string)($a['name'] ?? ''))] = $a;
		}
		$items = $t['items'];
		foreach ($items as &$item) {
			$r = $by[strtolower($item['name'])] ?? null;
			if (($r === null) || (fleet_template_owner((string)($r['description'] ?? '')) !== (int)$t['id'])) {
				continue;
			}
			$entries = array_map(function ($e) {
				return array('address' => (string)($e['address'] ?? ''), 'detail' => (string)($e['detail'] ?? ''));
			}, array_values((array)($r['entries'] ?? array())));
			$descr = trim(substr((string)$r['description'], strlen(fleet_template_marker((int)$t['id']))));
			if (($entries !== $item['entries']) || ($descr !== $item['description'])) {
				$item['entries'] = $entries;
				$item['description'] = $descr;
				$changed[] = $item['name'];
			}
		}
		unset($item);
		return array(array('items' => $items), $changed);
	}
	$settings = $t['settings'];
	foreach ($remote as $k => $v) {
		if (array_key_exists($k, $settings) && ($settings[$k] !== $v)) {
			$settings[$k] = $v;
			$changed[] = fleet_tset_labels($t['kind'])[$k] ?? $k;
		}
	}
	return array(array('settings' => $settings), $changed);
}

/*
 * Adopt: read the firewall now and take its version into the template.
 * The template then differs from its other firewalls, which the preview
 * shows before anything is applied there. Returns what changed.
 */
function fleet_template_adopt(array $t, array $box, string $who): array {
	$remote = ($t['kind'] === 'aliases') ? fleet_template_remote($box) : (isset(FLEET_TLIST_KINDS[$t['kind']]) ? fleet_tlist_remote($t['kind'], $box) :
	    fleet_template_settings_remote($t['kind'], $box));
	list($fields, $changed) = fleet_template_adopted($t, $remote);
	if (empty($changed)) {
		return array();
	}
	if (isset($fields['items'])) {
		fleet_db()->prepare('UPDATE templates SET items = ?, updated = ?, who = ? WHERE id = ?')->execute(array(json_encode($fields['items']), time(), $who, (int)$t['id']));
	} else {
		fleet_db()->prepare('UPDATE templates SET settings = ?, updated = ?, who = ? WHERE id = ?')->execute(array(json_encode($fields['settings']), time(), $who, (int)$t['id']));
	}
	$t2 = fleet_template_get((int)$t['id']);
	fleet_template_state_set((int)$t['id'], $box['node_id'], fleet_template_hash($t2), 'done', 'Adopted from this firewall');
	fleet_audit($who, 'template', sprintf('%s: adopted %s from %s', $t['name'], implode(', ', $changed), $box['label']));
	return $changed;
}
