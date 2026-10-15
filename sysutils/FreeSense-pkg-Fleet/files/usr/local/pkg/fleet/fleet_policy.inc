<?php
/*
 * fleet_policy.inc
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
 * Policy Manager. A policy is a set of rules from the catalog (each with
 * its settings and a mode) for some firewalls: all, groups, or single
 * firewalls. A firewall's effective rules: for each rule, the setting of
 * the most specific policy that covers it (firewall > group > all); two
 * policies at the same level that disagree are a conflict, shown and
 * never resolved silently (the first by name is used meanwhile).
 *
 * Rules are checked against what the controller knows: the status the
 * firewall reports, its update check, its backups, and its newest
 * configuration backup (config.xml). Custom rules are config-path
 * predicates only, never code. Modes: audit (report) and lock (the
 * firewall itself refuses a local save that would break the rule; only
 * configuration rules). Lock rules travel to each firewall as a bundle
 * signed with the controller's key; the firewall keeps it, so Lock holds
 * while the controller is offline, and a console administrator can
 * suspend it with break-glass (System, fleet_guard.inc).
 */

require_once('fleet/fleet_store.inc');

/*
 * The rule catalog. kind decides how it is checked; params: name =>
 * array(type, label, default). Types: version, versions (comma list),
 * text, regex, int, choice:<a|b>, path.
 */
function fleet_policy_catalog(): array {
	return array(
		'VER-001' => array('area' => 'Versions', 'title' => 'Minimum version', 'kind' => 'version_min', 'severity' => 'high',
		    'help' => 'The firewall runs at least this version.', 'params' => array('version' => array('version', 'Lowest allowed version', '1.1.5'))),
		'VER-002' => array('area' => 'Versions', 'title' => 'Pinned version', 'kind' => 'version_pin', 'severity' => 'medium',
		    'help' => 'The firewall stays on exactly this version; updates and rollouts leave it alone.', 'params' => array('version' => array('version', 'Version', '1.1.5'))),
		'VER-003' => array('area' => 'Versions', 'title' => 'Allowed versions', 'kind' => 'version_allowed', 'severity' => 'medium',
		    'help' => 'The firewall runs one of these versions; updates go only to one of them.', 'params' => array('versions' => array('versions', 'Versions (comma-separated)', '1.1.5, 1.1.6'))),
		'VER-004' => array('area' => 'Versions', 'title' => 'Update channel', 'kind' => 'channel', 'severity' => 'medium',
		    'help' => 'The firewall follows this update channel.', 'params' => array('channel' => array('choice:stable|testing|development', 'Channel', 'stable'))),
		'OPS-010' => array('area' => 'Operations', 'title' => 'Recent backup', 'kind' => 'backup_age', 'severity' => 'high',
		    'help' => 'The controller has a backup of the firewall no older than this.', 'params' => array('days' => array('int', 'At most days old', '2'))),
		'OPS-020' => array('area' => 'Operations', 'title' => 'Rollback protection (ZFS)', 'kind' => 'rollback', 'severity' => 'low',
		    'help' => 'The firewall runs on ZFS boot environments, so a failed update rolls back by itself.', 'params' => array()),
		'OPS-001' => array('area' => 'Operations', 'title' => 'NTP servers set', 'kind' => 'config', 'severity' => 'medium',
		    'help' => 'The firewall has time servers configured.', 'params' => array(), 'path' => 'system/timeservers', 'op' => 'nonempty'),
		'OPS-002' => array('area' => 'Operations', 'title' => 'Remote syslog', 'kind' => 'config', 'severity' => 'medium',
		    'help' => 'The firewall sends its logs to a remote syslog server.', 'params' => array(), 'path' => 'syslog/enable', 'op' => 'present'),
		'OPS-003' => array('area' => 'Operations', 'title' => 'Time zone', 'kind' => 'config', 'severity' => 'low',
		    'help' => 'The firewall uses this time zone.', 'params' => array('value' => array('text', 'Time zone', 'Etc/UTC')), 'path' => 'system/timezone', 'op' => 'equals'),
		'SEC-001' => array('area' => 'Security', 'title' => 'SSH by key only', 'kind' => 'ssh_keyonly', 'severity' => 'high',
		    'help' => 'SSH is off, or allows key logins only (no passwords).', 'params' => array()),
		'SEC-002' => array('area' => 'Security', 'title' => 'WebGUI over HTTPS', 'kind' => 'config', 'severity' => 'high',
		    'help' => 'The WebGUI uses HTTPS.', 'params' => array(), 'path' => 'system/webgui/protocol', 'op' => 'equals', 'value' => 'https'),
		'SEC-003' => array('area' => 'Security', 'title' => 'WebGUI login protection', 'kind' => 'config', 'severity' => 'medium',
		    'help' => 'Login protection (blocking repeated failed logins) is not turned off.', 'params' => array(), 'path' => 'system/webgui/noantilockout', 'op' => 'absent'),
		'NAME-001' => array('area' => 'Naming', 'title' => 'Hostname pattern', 'kind' => 'config', 'severity' => 'low',
		    'help' => 'The hostname matches the naming pattern.', 'params' => array('regex' => array('regex', 'Pattern (regular expression)', '^[a-z]{2}-[a-z0-9]+-[a-z]+[0-9]{2}$')),
		    'path' => 'system/hostname', 'op' => 'regex'),
		'NAME-002' => array('area' => 'Naming', 'title' => 'Domain', 'kind' => 'config', 'severity' => 'low',
		    'help' => 'The firewall uses this domain.', 'params' => array('value' => array('text', 'Domain', 'example.net')), 'path' => 'system/domain', 'op' => 'equals'),
		'CUSTOM' => array('area' => 'Custom', 'title' => 'Configuration setting', 'kind' => 'config', 'severity' => 'medium',
		    'help' => 'A configuration path has a value. Paths are like system/ssh/port.', 'custom' => true,
		    'params' => array('path' => array('path', 'Path', 'system/ssh/port'), 'op' => array('choice:equals|not_equals|regex|present|absent|nonempty|min|max', 'Test', 'equals'),
		    'value' => array('text', 'Value', ''), 'title' => array('text', 'Name of the rule', 'SSH port'))),
	);
}

define('FLEET_POLICY_MODES', array('audit' => 'Audit', 'lock' => 'Lock'));

/* ------------------------------------------------------------------ */
/* Pure: rules                                                         */
/* ------------------------------------------------------------------ */

/*
 * pure: one rule of a policy from a form: array(rule id, params, mode) or
 * InvalidArgumentException. Custom rules get the key CUSTOM:<n>.
 */
function fleet_policy_rule_from(string $id, array $in): array {
	$cat = fleet_policy_catalog();
	$base = preg_replace('/:\d+$/', '', $id);
	if (!isset($cat[$base]) || (($base === 'CUSTOM') === ($base === $id))) {
		throw new InvalidArgumentException("Unknown rule {$id}.");
	}
	$params = array();
	foreach ($cat[$base]['params'] as $name => list($type, $label)) {
		$v = trim((string)($in[$name] ?? ''));
		$bad = function () use ($id, $label) {
			throw new InvalidArgumentException("{$id}: check \"{$label}\".");
		};
		if ($type === 'version') {
			fleet_version_number($v) === '' ? $bad() : null;
		} elseif ($type === 'versions') {
			$list = array_values(array_filter(array_map('trim', explode(',', $v)), 'strlen'));
			(empty($list) || in_array('', array_map('fleet_version_number', $list), true)) ? $bad() : null;
			$v = implode(', ', $list);
		} elseif ($type === 'int') {
			(!ctype_digit($v) || ((int)$v < 1) || ((int)$v > 3650)) ? $bad() : null;
		} elseif ($type === 'regex') {
			(($v === '') || (@preg_match('/' . str_replace('/', '\/', $v) . '/', '') === false)) ? $bad() : null;
		} elseif ($type === 'path') {
			!preg_match('#^[a-z0-9_-]+(/[a-z0-9_-]+){0,7}$#i', $v) ? $bad() : null;
		} elseif (strncmp($type, 'choice:', 7) === 0) {
			!in_array($v, explode('|', substr($type, 7)), true) ? $bad() : null;
		} elseif ((strlen($v) > 200) || preg_match('/[\x00-\x1f]/', $v)) {
			$bad();
		}
		$params[$name] = $v;
	}
	if (($base === 'CUSTOM') && in_array($params['op'], array('equals', 'not_equals', 'regex', 'min', 'max'), true) && ($params['value'] === '')) {
		throw new InvalidArgumentException("{$id}: this test needs a value.");
	}
	$mode = (string)($in['mode'] ?? 'audit');
	if (!isset(FLEET_POLICY_MODES[$mode])) {
		throw new InvalidArgumentException("{$id}: unknown mode.");
	}
	if (($mode === 'lock') && !fleet_policy_lockable($base)) {
		throw new InvalidArgumentException("{$id}: only configuration rules can be locked.");
	}
	return array($id, $params, $mode);
}

/* pure: can a rule be locked on the firewall? (configuration rules only: the firewall checks them itself) */
function fleet_policy_lockable(string $base): bool {
	return (fleet_policy_catalog()[$base]['kind'] ?? '') === 'config';
}

/*
 * pure: the firewall's form of a lock rule: {id, title, mode, path, op,
 * value} as System's fleet_guard.inc checks it. Custom rules get ids
 * CUS-<n>; "set and not empty" becomes a regex.
 */
function fleet_policy_node_rule(string $rid, array $params): array {
	$base = preg_replace('/:\d+$/', '', $rid);
	$rule = fleet_policy_catalog()[$base];
	$op = $rule['op'] ?? $params['op'];
	$value = (string)($rule['value'] ?? ($params['value'] ?? ($params['regex'] ?? '')));
	$out = array('id' => ($base === 'CUSTOM') ? sprintf('CUS-%03d', (int)substr($rid, 7) % 1000) : $rid, 'title' => fleet_policy_rule_title($rid, $params),
	    'mode' => 'lock', 'path' => $rule['path'] ?? $params['path'], 'op' => ($op === 'nonempty') ? 'regex' : $op);
	if ($op === 'nonempty') {
		$out['value'] = '.';
	} elseif (!in_array($op, array('present', 'absent'), true)) {
		$out['value'] = $value;
	}
	return $out;
}

/* pure: a firewall's lock rules from its effective rules, in a stable order. */
function fleet_policy_lock_rules(array $effective): array {
	$out = array();
	foreach ($effective as $rid => list($params, $mode)) {
		if (($mode === 'lock') && fleet_policy_lockable(preg_replace('/:\d+$/', '', $rid))) {
			$out[] = fleet_policy_node_rule($rid, $params);
		}
	}
	return $out;
}

/* pure: the text values at a path in a configuration (SimpleXML), or null when the configuration is not known. */
function fleet_config_values(?SimpleXMLElement $xml, string $path): ?array {
	if ($xml === null) {
		return null;
	}
	$nodes = array($xml);
	foreach (explode('/', $path) as $part) {
		$next = array();
		foreach ($nodes as $n) {
			foreach ($n->{$part} as $child) {
				$next[] = $child;
			}
		}
		$nodes = $next;
	}
	return array_map(function ($n) { return trim((string)$n); }, $nodes);
}

/*
 * pure: check one rule for one firewall. $facts: version, channel,
 * rollback (bool|null), last_backup (time|null), config (SimpleXMLElement
 * |null), now. Returns array(state: pass|fail|unknown, detail).
 */
function fleet_policy_check(string $id, array $params, array $facts): array {
	$cat = fleet_policy_catalog();
	$rule = $cat[preg_replace('/:\d+$/', '', $id)];
	$v = fleet_version_number((string)($facts['version'] ?? ''));
	switch ($rule['kind']) {
	case 'version_min':
		if ($v === '') {
			return array('unknown', 'Version not known yet');
		}
		return version_compare($v, fleet_version_number($params['version']), '>=') ? array('pass', "Runs {$v}") :
		    array('fail', "Runs {$v}, needs at least " . fleet_version_number($params['version']));
	case 'version_pin':
		if ($v === '') {
			return array('unknown', 'Version not known yet');
		}
		return fleet_version_same($v, $params['version']) ? array('pass', "Runs {$v}") : array('fail', "Runs {$v}, pinned to " . fleet_version_number($params['version']));
	case 'version_allowed':
		if ($v === '') {
			return array('unknown', 'Version not known yet');
		}
		$allowed = array_map('fleet_version_number', explode(',', $params['versions']));
		return in_array($v, $allowed, true) ? array('pass', "Runs {$v}") : array('fail', "Runs {$v}, allowed: " . implode(', ', $allowed));
	case 'channel':
		$c = (string)($facts['channel'] ?? '');
		if ($c === '') {
			return array('unknown', 'Channel not known yet (no update check)');
		}
		return (strcasecmp($c, $params['channel']) === 0) ? array('pass', "Follows {$c}") : array('fail', "Follows {$c}, should follow {$params['channel']}");
	case 'backup_age':
		if (empty($facts['last_backup'])) {
			return array('fail', 'No backup on the controller');
		}
		$days = ($facts['now'] - $facts['last_backup']) / 86400;
		return ($days <= (int)$params['days']) ? array('pass', sprintf('Last backup %.1f days ago', $days)) :
		    array('fail', sprintf('Last backup %.1f days ago (at most %d)', $days, $params['days']));
	case 'rollback':
		if (($facts['rollback'] ?? null) === null) {
			return array('unknown', 'Not reported yet');
		}
		return $facts['rollback'] ? array('pass', 'ZFS boot environments') : array('fail', 'UFS: a failed update cannot roll back');
	case 'ssh_keyonly':
		$on = fleet_config_values($facts['config'] ?? null, 'system/ssh/enable');
		if ($on === null) {
			return array('unknown', 'No configuration backup yet');
		}
		if (empty($on)) {
			return array('pass', 'SSH is off');
		}
		$keyonly = fleet_config_values($facts['config'], 'system/ssh/sshdkeyonly');
		return in_array((string)($keyonly[0] ?? ''), array('enabled', 'both'), true) ? array('pass', 'SSH allows keys only') : array('fail', 'SSH allows password logins');
	case 'config':
		$path = $rule['path'] ?? $params['path'];
		$op = $rule['op'] ?? $params['op'];
		$want = (string)($rule['value'] ?? ($params['value'] ?? ($params['regex'] ?? '')));
		$vals = fleet_config_values($facts['config'] ?? null, $path);
		if ($vals === null) {
			return array('unknown', 'No configuration backup yet');
		}
		$first = $vals[0] ?? null;
		$shown = ($first === null) ? 'not set' : (($first === '') ? 'set' : '"' . mb_substr($first, 0, 60) . '"');
		switch ($op) {
		case 'present':
			$ok = ($first !== null);
			break;
		case 'absent':
			$ok = ($first === null);
			break;
		case 'nonempty':
			$ok = ($first !== null) && ($first !== '');
			break;
		case 'equals':
			$ok = ($first === $want);
			break;
		case 'not_equals':
			$ok = ($first !== $want);
			break;
		case 'regex':
			$ok = ($first !== null) && (preg_match('/' . str_replace('/', '\/', $want) . '/', $first) === 1);
			break;
		case 'min':
			$ok = is_numeric($first) && ((float)$first >= (float)$want);
			break;
		case 'max':
			$ok = is_numeric($first) && ((float)$first <= (float)$want);
			break;
		default:
			return array('unknown', 'Unknown test');
		}
		return $ok ? array('pass', "{$path}: {$shown}") : array('fail', "{$path}: {$shown}" . (in_array($op, array('equals', 'regex', 'min', 'max'), true) ? " ({$op} {$want})" : ''));
	}
	return array('unknown', 'Unknown rule');
}

/*
 * pure: a firewall's effective rules. $policies: id, name, targets,
 * rules (id => array(params, mode)), enabled. $groups: the firewall's
 * group ids. Returns rule id => array(params, mode, policy id, policy
 * name, conflict: null or the other policy's name).
 */
function fleet_policy_effective(array $policies, string $node, array $groups): array {
	$level = function (array $targets) use ($node, $groups) {
		if (in_array('n:' . $node, $targets, true)) {
			return 3;
		}
		foreach ($groups as $g) {
			if (in_array('g:' . $g, $targets, true)) {
				return 2;
			}
		}
		return in_array('all', $targets, true) ? 1 : 0;
	};
	usort($policies, function ($a, $b) { return strcasecmp($a['name'], $b['name']); });
	$out = array();
	$lv = array();
	foreach ($policies as $p) {
		if (empty($p['enabled'])) {
			continue;
		}
		$l = $level($p['targets']);
		if ($l === 0) {
			continue;
		}
		foreach ($p['rules'] as $rid => list($params, $mode)) {
			if (!isset($out[$rid]) || ($l > $lv[$rid])) {
				$out[$rid] = array($params, $mode, (int)$p['id'], $p['name'], null);
				$lv[$rid] = $l;
			} elseif (($l === $lv[$rid]) && ($params !== $out[$rid][0]) && ($out[$rid][4] === null)) {
				$out[$rid][4] = $p['name'];
			}
		}
	}
	ksort($out);
	return $out;
}

/* pure: is there an exception for this firewall and rule that has not expired? */
function fleet_policy_excepted(array $exceptions, string $node, string $rid, int $now): ?array {
	foreach ($exceptions as $e) {
		if (($e['node_id'] === $node) && ($e['rule_id'] === $rid) && ((int)$e['expires'] > $now)) {
			return $e;
		}
	}
	return null;
}

/*
 * pure: what policies allow for updates: array(pinned version or null,
 * allowed versions or null), from a firewall's effective rules.
 */
function fleet_policy_version_limits(array $effective): array {
	$pin = isset($effective['VER-002']) ? fleet_version_number($effective['VER-002'][0]['version']) : null;
	$allowed = isset($effective['VER-003']) ? array_map('fleet_version_number', explode(',', $effective['VER-003'][0]['versions'])) : null;
	return array($pin, $allowed);
}

/* pure: may a firewall update to $target ('' = not known) under its limits? null or why not. A pin blocks every update. */
function fleet_policy_update_block(array $limits, string $target): ?string {
	list($pin, $allowed) = $limits;
	$t = fleet_version_number($target);
	if ($pin !== null) {
		return "Pinned to {$pin} by policy";
	}
	if (($allowed !== null) && ($t === '')) {
		return 'Policy allows only ' . implode(', ', $allowed) . ', and the offered version is not known yet';
	}
	if (($allowed !== null) && !in_array($t, $allowed, true)) {
		return "Policy allows only " . implode(', ', $allowed);
	}
	return null;
}

/* ------------------------------------------------------------------ */
/* Storage                                                             */
/* ------------------------------------------------------------------ */

function fleet_policy_row(array $r): array {
	$r['targets'] = json_decode((string)$r['targets'], true) ?: array();
	$r['rules'] = json_decode((string)$r['rules'], true) ?: array();
	$r['enabled'] = (bool)$r['enabled'];
	return $r;
}

function fleet_policies_all(): array {
	return array_map('fleet_policy_row', fleet_db()->query('SELECT * FROM policies ORDER BY name COLLATE NOCASE')->fetchAll());
}

function fleet_policy_get(int $id): ?array {
	$q = fleet_db()->prepare('SELECT * FROM policies WHERE id = ?');
	$q->execute(array($id));
	$r = $q->fetch();
	return is_array($r) ? fleet_policy_row($r) : null;
}

/*
 * Create or change a policy from its form: name, description, targets[],
 * enabled, use[<rule>] and rule[<rule>][<param>|mode]. Returns its id.
 */
function fleet_policy_save(?int $id, array $in, string $who): int {
	$name = trim((string)($in['name'] ?? ''));
	if (($name === '') || (strlen($name) > 60) || preg_match('/[<>\x00-\x1f\x7f]/', $name)) {
		throw new InvalidArgumentException('Give the policy a name of 1 to 60 characters.');
	}
	$desc = mb_substr(trim(preg_replace('/[\x00-\x1f\x7f]/u', ' ', (string)($in['description'] ?? ''))), 0, 300);
	$targets = fleet_targets_from($in['targets'] ?? array());
	list(, $gone) = fleet_targets_now($targets);
	if (!empty($gone)) {
		throw new InvalidArgumentException('A chosen group or firewall does not exist any more. Choose again.');
	}
	$rules = array();
	foreach (array_keys((array)($in['use'] ?? array())) as $rid) {
		list($rid, $params, $mode) = fleet_policy_rule_from((string)$rid, (array)($in['rule'][$rid] ?? array()));
		$rules[$rid] = array($params, $mode);
	}
	if (empty($rules)) {
		throw new InvalidArgumentException('Choose at least one rule.');
	}
	$q = fleet_db()->prepare('SELECT COUNT(*) FROM policies WHERE name = ? COLLATE NOCASE AND id != ?');
	$q->execute(array($name, $id ?? 0));
	if ((int)$q->fetchColumn() > 0) {
		throw new InvalidArgumentException('There is already a policy with that name.');
	}
	$args = array($name, $desc, json_encode($targets), json_encode($rules), empty($in['enabled']) ? 0 : 1, time(), $who);
	if ($id === null) {
		fleet_db()->prepare('INSERT INTO policies (name, description, targets, rules, enabled, updated, who, created) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
		    ->execute(array_merge($args, array(time())));
		$id = (int)fleet_db()->lastInsertId();
	} else {
		fleet_db()->prepare('UPDATE policies SET name = ?, description = ?, targets = ?, rules = ?, enabled = ?, updated = ?, who = ? WHERE id = ?')
		    ->execute(array_merge($args, array($id)));
	}
	fleet_audit($who, 'policy', sprintf('%s: %d rules for %s%s', $name, count($rules), fleet_targets_text($targets, fleet_target_names()), empty($in['enabled']) ? ' (off)' : ''));
	fleet_compliance_refresh();
	return $id;
}

function fleet_policy_delete(int $id, string $who): void {
	$p = fleet_policy_get($id);
	fleet_db()->prepare('DELETE FROM policies WHERE id = ?')->execute(array($id));
	fleet_audit($who, 'policy', ($p['name'] ?? (string)$id) . ': deleted');
	fleet_compliance_refresh();
}

function fleet_policy_exceptions(): array {
	return fleet_db()->query('SELECT * FROM policy_exceptions ORDER BY expires')->fetchAll();
}

function fleet_policy_exception_add(string $node, string $rid, string $reason, string $until, string $who): void {
	if (fleet_box_get($node) === null) {
		throw new InvalidArgumentException('Choose a firewall.');
	}
	if (!isset(fleet_policy_catalog()[preg_replace('/:\d+$/', '', $rid)])) {
		throw new InvalidArgumentException('Choose a rule.');
	}
	$reason = mb_substr(trim(preg_replace('/[\x00-\x1f\x7f]/u', ' ', $reason)), 0, 300);
	if (mb_strlen($reason) < 5) {
		throw new InvalidArgumentException('Say why (at least a few words): the exception is reviewed later.');
	}
	$d = DateTimeImmutable::createFromFormat('!Y-m-d', $until, new DateTimeZone(fleet_tz()));
	if (($d === false) || ($d->getTimestamp() <= time()) || ($d->getTimestamp() > time() + 366 * 86400)) {
		throw new InvalidArgumentException('An exception ends on a date within the next year.');
	}
	fleet_db()->prepare('INSERT INTO policy_exceptions (node_id, rule_id, reason, who, created, expires) VALUES (?, ?, ?, ?, ?, ?)')
	    ->execute(array($node, $rid, $reason, $who, time(), $d->modify('+1 day')->getTimestamp()));
	fleet_audit($who, 'policy_exception', sprintf('%s, %s until %s: %s', $node, $rid, $until, $reason));
	fleet_compliance_refresh($node);
}

function fleet_policy_exception_delete(int $id, string $who): void {
	$q = fleet_db()->prepare('SELECT * FROM policy_exceptions WHERE id = ?');
	$q->execute(array($id));
	$e = $q->fetch();
	if (!is_array($e)) {
		return;
	}
	fleet_db()->prepare('DELETE FROM policy_exceptions WHERE id = ?')->execute(array($id));
	fleet_audit($who, 'policy_exception', sprintf('%s, %s: exception ended', $e['node_id'], $e['rule_id']));
	fleet_compliance_refresh($e['node_id']);
}

/* node_id => group ids */
function fleet_box_group_ids(): array {
	$out = array();
	foreach (fleet_db()->query('SELECT node_id, group_id FROM box_groups')->fetchAll() as $m) {
		$out[$m['node_id']][] = (int)$m['group_id'];
	}
	return $out;
}

/* What the controller knows about a firewall, for the checks. */
function fleet_box_facts(array $box): array {
	$st = json_decode((string)($box['status'] ?? ''), true) ?: array();
	$info = fleet_update_info($box);
	$latest = fleet_backup_latest($box['node_id']);
	$xml = null;
	if ($latest !== null) {
		$text = fleet_backup_read($latest);
		$prev = libxml_use_internal_errors(true);
		$xml = ($text === null) ? null : (simplexml_load_string($text, 'SimpleXMLElement', LIBXML_NONET) ?: null);
		libxml_use_internal_errors($prev);
	}
	return array('version' => (string)($st['version'] ?? ''), 'channel' => (string)($info['channel'] ?? ''),
	    'rollback' => isset($st['rollback_protection']) ? (bool)$st['rollback_protection'] : null,
	    'last_backup' => ($latest === null) ? null : (int)$latest['time'], 'config' => $xml, 'now' => time());
}

/* A firewall's effective rules right now. */
function fleet_box_effective(string $node, ?array $policies = null, ?array $groups = null): array {
	return fleet_policy_effective($policies ?? fleet_policies_all(), $node, ($groups ?? fleet_box_group_ids())[$node] ?? array());
}

/* Check every firewall (or one) against its effective rules and keep the result. Exceptions turn a failure into "excepted". */
function fleet_compliance_refresh(?string $only = null): void {
	$policies = fleet_policies_all();
	$groups = fleet_box_group_ids();
	$exceptions = fleet_policy_exceptions();
	$now = time();
	$boxes = fleet_db()->query('SELECT * FROM boxes')->fetchAll();
	foreach ($boxes as $box) {
		if (($only !== null) && ($box['node_id'] !== $only)) {
			continue;
		}
		$eff = fleet_box_effective($box['node_id'], $policies, $groups);
		$facts = empty($eff) ? array() : fleet_box_facts($box);
		fleet_db()->prepare('DELETE FROM compliance WHERE node_id = ?')->execute(array($box['node_id']));
		$ins = fleet_db()->prepare('INSERT INTO compliance (node_id, rule_id, state, detail, policy_id, conflict, checked) VALUES (?, ?, ?, ?, ?, ?, ?)');
		foreach ($eff as $rid => list($params, $mode, $pid, $pname, $conflict)) {
			list($state, $detail) = fleet_policy_check($rid, $params, $facts);
			if (($state === 'fail') && (($e = fleet_policy_excepted($exceptions, $box['node_id'], $rid, $now)) !== null)) {
				$state = 'excepted';
				$detail .= ' (exception until ' . date('Y-m-d', (int)$e['expires'] - 1) . ')';
			}
			$ins->execute(array($box['node_id'], $rid, $state, $detail, $pid, $conflict, $now));
		}
	}
	if ($only === null) {
		fleet_setting_set('compliance_checked', (string)$now);
	}
	fleet_bundles_push(($only === null) ? null : array($only));
}

/* node_id => array(pass, fail, unknown, excepted, conflicts) */
function fleet_compliance_counts(): array {
	$out = array();
	foreach (fleet_db()->query('SELECT node_id, state, conflict FROM compliance')->fetchAll() as $r) {
		$out[$r['node_id']] = ($out[$r['node_id']] ?? array('pass' => 0, 'fail' => 0, 'unknown' => 0, 'excepted' => 0, 'conflicts' => 0));
		$out[$r['node_id']][$r['state']]++;
		$out[$r['node_id']]['conflicts'] += ($r['conflict'] !== null) ? 1 : 0;
	}
	return $out;
}

/* The title of a rule for people (custom rules carry their own). */
function fleet_policy_rule_title(string $rid, array $params = array()): string {
	$base = preg_replace('/:\d+$/', '', $rid);
	$cat = fleet_policy_catalog();
	if ($base === 'CUSTOM') {
		return ($params['title'] ?? '') !== '' ? $params['title'] : 'Custom: ' . ($params['path'] ?? '');
	}
	return $cat[$base]['title'] ?? $rid;
}

/* node_id => why the policy does not allow updating to $target (or to each firewall's offered version). */
function fleet_policy_update_blocks(array $boxes, array $infos, ?string $target = null): array {
	$policies = fleet_policies_all();
	if (empty($policies)) {
		return array();
	}
	$groups = fleet_box_group_ids();
	$out = array();
	foreach ($boxes as $b) {
		$to = $target ?? (string)($infos[$b['node_id']]['latest'] ?? '');
		$why = fleet_policy_update_block(fleet_policy_version_limits(fleet_box_effective($b['node_id'], $policies, $groups)), $to);
		if ($why !== null) {
			$out[$b['node_id']] = $why;
		}
	}
	return $out;
}

/* ------------------------------------------------------------------ */
/* Lock bundles                                                        */
/* ------------------------------------------------------------------ */

/* node_id => {hash, version, sent, error, rules} of the last bundle Fleet tried to send. */
function fleet_bundle_state(): array {
	return json_decode((string)fleet_setting('bundles', '{}'), true) ?: array();
}

/* The signed bundle text for a firewall: array(text, signature base64). Versions only grow (time-based). */
function fleet_bundle_make(string $node, array $rules, int $version): array {
	$text = json_encode(array('version' => $version, 'node_id' => $node, 'issued' => time(), 'rules' => $rules), JSON_UNESCAPED_SLASHES);
	$sig = '';
	if (!openssl_sign($text, $sig, openssl_pkey_get_private(fleet_signing_pem()), OPENSSL_ALGO_SHA256)) {
		throw new RuntimeException('The bundle could not be signed.');
	}
	return array($text, base64_encode($sig));
}

/*
 * Send each online managed firewall its lock rules when they changed (or
 * the last try failed). A firewall that never had lock rules gets nothing.
 */
function fleet_bundles_push(?array $only = null): void {
	$state = fleet_bundle_state();
	$policies = fleet_policies_all();
	$groups = fleet_box_group_ids();
	foreach (fleet_db()->query('SELECT * FROM boxes')->fetchAll() as $box) {
		if ((($only !== null) && !in_array($box['node_id'], $only, true)) || !fleet_manage_allowed($box)) {
			continue;
		}
		$rules = fleet_policy_lock_rules(fleet_box_effective($box['node_id'], $policies, $groups));
		$hash = hash('sha256', json_encode($rules));
		$prev = $state[$box['node_id']] ?? null;
		if ((($prev === null) && empty($rules)) || (($prev !== null) && ($prev['hash'] === $hash) && empty($prev['error']))) {
			continue;
		}
		if ($box['state'] !== 'online') {
			$state[$box['node_id']] = array('hash' => $hash, 'version' => $prev['version'] ?? 0, 'sent' => $prev['sent'] ?? null,
			    'error' => 'Waiting for the firewall to come online', 'rules' => count($rules));
			continue;
		}
		$version = max(time(), (int)($prev['version'] ?? 0) + 1);
		try {
			list($text, $sig) = fleet_bundle_make($box['node_id'], $rules, $version);
			list($code, $json) = fleet_box_call($box, 'PUT', '/api/v1/management/policy-bundle', array('bundle' => $text, 'signature' => $sig));
			if ($code !== 200) {
				throw new RuntimeException('FLEET-E320: The firewall refused the lock rules: ' . fleet_box_error($code, $json));
			}
			$state[$box['node_id']] = array('hash' => $hash, 'version' => $version, 'sent' => time(), 'error' => null, 'rules' => count($rules));
			fleet_audit('fleet', 'policy', sprintf('%s: %d lock rules sent (bundle %d)', $box['label'], count($rules), $version));
		} catch (RuntimeException $e) {
			$state[$box['node_id']] = array('hash' => $hash, 'version' => $prev['version'] ?? 0, 'sent' => $prev['sent'] ?? null,
			    'error' => $e->getMessage(), 'rules' => count($rules));
		}
	}
	fleet_setting_set('bundles', json_encode($state));
}

/*
 * After each poll: a break-glass the firewall did not have before raises
 * FLEET-E321 at once; a firewall holding an older bundle than Fleet sent
 * (restored, reinstalled) gets it again with the next push.
 */
function fleet_lock_follow(array $box, array $status): void {
	$old = json_decode((string)($box['status'] ?? ''), true) ?: array();
	$bg = $status['breakglass'] ?? null;
	if (is_array($bg) && ((int)($bg['since'] ?? 0) !== (int)($old['breakglass']['since'] ?? 0))) {
		$text = sprintf('FLEET-E321: Lock suspended on %s until %s by %s: %s', $box['label'], date('Y-m-d H:i', (int)($bg['until'] ?? 0)),
		    (string)($bg['by'] ?? '?'), (string)($bg['reason'] ?? ''));
		fleet_audit('poll', 'policy', $text);
		if (function_exists('file_notice')) {
			file_notice('fleet', $text, 'FreeSense Fleet', '');
		}
	} elseif (($bg === null) && is_array($old['breakglass'] ?? null)) {
		fleet_audit('poll', 'policy', sprintf('%s: Lock is in force again (break-glass ended)', $box['label']));
	}
	$state = fleet_bundle_state();
	$sent = $state[$box['node_id']] ?? null;
	$held = (int)($status['policy_bundle']['version'] ?? 0);
	if (($sent !== null) && empty($sent['error']) && ($held < (int)$sent['version'])) {
		$state[$box['node_id']]['error'] = 'The firewall holds an older bundle; sending again';
		fleet_setting_set('bundles', json_encode($state));
	}
}

