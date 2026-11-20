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
 * configuration rules) and remediate (the controller has the firewall fix
 * the setting, for the few rules one value can fix; inside the firewall's
 * maintenance window, after a safety backup, never in a loop). Lock and
 * remediate rules travel to each firewall as a bundle
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
		    'help' => 'The firewall has time servers configured.', 'params' => array('fix' => array('text', 'Time servers to set when fixing', 'pool.ntp.org')),
		    'path' => 'system/timeservers', 'op' => 'nonempty'),
		'OPS-002' => array('area' => 'Operations', 'title' => 'Remote syslog', 'kind' => 'config', 'severity' => 'medium',
		    'help' => 'The firewall sends its logs to a remote syslog server.', 'params' => array(), 'path' => 'syslog/enable', 'op' => 'present'),
		'OPS-003' => array('area' => 'Operations', 'title' => 'Time zone', 'kind' => 'config', 'severity' => 'low',
		    'help' => 'The firewall uses this time zone.', 'params' => array('value' => array('text', 'Time zone', 'Etc/UTC')), 'path' => 'system/timezone', 'op' => 'equals'),
		'SEC-001' => array('area' => 'Security', 'title' => 'SSH by key only', 'kind' => 'ssh_keyonly', 'severity' => 'high',
		    'help' => 'SSH is off, or allows key logins only (no passwords).', 'params' => array()),
		'SEC-002' => array('area' => 'Security', 'title' => 'WebGUI over HTTPS', 'kind' => 'config', 'severity' => 'high',
		    'help' => 'The WebGUI uses HTTPS.', 'params' => array(), 'path' => 'system/webgui/protocol', 'op' => 'equals', 'value' => 'https'),
		'SEC-003' => array('area' => 'Security', 'title' => 'WebGUI login protection', 'kind' => 'login_protection', 'severity' => 'medium',
		    'help' => 'Login protection (blocking addresses after repeated failed logins) is not weakened: its pass list does not cover every address and it blocks after at most this many failures.',
		    'params' => array('threshold' => array('int', 'Blocks after at most (attack score)', '30'))),
		'NAME-001' => array('area' => 'Naming', 'title' => 'Hostname pattern', 'kind' => 'config', 'severity' => 'low',
		    'help' => 'The hostname matches the naming pattern.', 'params' => array('regex' => array('regex', 'Pattern (regular expression)', '^[a-z]{2}-[a-z0-9]+-[a-z]+[0-9]{2}$')),
		    'path' => 'system/hostname', 'op' => 'regex'),
		'NAME-002' => array('area' => 'Naming', 'title' => 'Domain', 'kind' => 'config', 'severity' => 'low',
		    'help' => 'The firewall uses this domain.', 'params' => array('value' => array('text', 'Domain', 'example.net')), 'path' => 'system/domain', 'op' => 'equals'),
		'NAME-003' => array('area' => 'Naming', 'title' => 'Domain of its group', 'kind' => 'config', 'severity' => 'low', 'group_naming' => 'domain',
		    'help' => 'The firewall uses the domain its group names (Firewalls > Groups > Naming).', 'params' => array(), 'path' => 'system/domain', 'op' => 'equals'),
		'NAME-004' => array('area' => 'Naming', 'title' => 'Hostname follows its group', 'kind' => 'config', 'severity' => 'low', 'group_naming' => 'pattern',
		    'help' => 'The hostname follows the pattern of its group, e.g. cph-fw01 for {site}-fw{nn}.', 'params' => array(), 'path' => 'system/hostname', 'op' => 'regex'),
		'CUSTOM' => array('area' => 'Custom', 'title' => 'Configuration setting', 'kind' => 'config', 'severity' => 'medium',
		    'help' => 'A configuration path has a value. Paths are like system/ssh/port.', 'custom' => true,
		    'params' => array('path' => array('path', 'Path', 'system/ssh/port'), 'op' => array('choice:equals|not_equals|regex|present|absent|nonempty|min|max', 'Test', 'equals'),
		    'value' => array('text', 'Value', ''), 'title' => array('text', 'Name of the rule', 'SSH port'))),
	);
}

define('FLEET_POLICY_MODES', array('audit' => 'Audit', 'remediate' => 'Remediate', 'lock' => 'Lock'));
/* Rules one value can fix; the firewall keeps its own allow-list too (System, fleet_guard.inc). */
define('FLEET_POLICY_REMEDIABLE', array('OPS-001', 'OPS-003', 'NAME-002', 'NAME-003'));

/* ------------------------------------------------------------------ */
/* Pure: rules                                                         */
/* ------------------------------------------------------------------ */

/*
 * pure: one rule of a policy from a form: array(rule id, params, mode) or
 * InvalidArgumentException. Custom rules get the key CUSTOM:<n> (n fleet-wide, see fleet_policy_custom_next()).
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
	if (($mode === 'remediate') && !in_array($base, FLEET_POLICY_REMEDIABLE, true)) {
		throw new InvalidArgumentException("{$id}: Fleet cannot fix this rule by itself.");
	}
	if (isset($params['fix']) && ($params['fix'] !== '') && !preg_match('/^[A-Za-z0-9.:-]{1,253}( [A-Za-z0-9.:-]{1,253}){0,9}$/D', $params['fix'])) {
		throw new InvalidArgumentException("{$id}: time servers are host names or addresses separated by spaces.");
	}
	return array($id, $params, $mode);
}

/* pure: one name for an update channel, whatever spelling a firewall or policy uses (devel = development). */
function fleet_channel_name(string $c): string {
	$c = strtolower(trim($c));
	return array('devel' => 'development', 'dev' => 'development', 'release' => 'stable')[$c] ?? $c;
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
function fleet_policy_node_rule(string $rid, array $params, string $mode = 'lock'): array {
	$base = preg_replace('/:\d+$/', '', $rid);
	$rule = fleet_policy_catalog()[$base];
	$op = $rule['op'] ?? $params['op'];
	$value = (string)($rule['value'] ?? ($params['value'] ?? ($params['regex'] ?? '')));
	$out = array('id' => ($base === 'CUSTOM') ? sprintf('CUS-%03d', (int)substr($rid, 7) % 1000) : $rid, 'title' => fleet_policy_rule_title($rid, $params),
	    'mode' => $mode, 'path' => $rule['path'] ?? $params['path'], 'op' => ($op === 'nonempty') ? 'regex' : $op);
	if (($params['fix'] ?? '') !== '') {
		$out['fix'] = $params['fix'];
	}
	if ($op === 'nonempty') {
		$out['value'] = '.';
	} elseif (!in_array($op, array('present', 'absent'), true)) {
		$out['value'] = $value;
	}
	return $out;
}

/* pure: the rules a firewall holds in its bundle (lock and remediate), from its effective rules, in a stable order. */
function fleet_policy_lock_rules(array $effective): array {
	$out = array();
	foreach ($effective as $rid => list($params, $mode)) {
		$base = preg_replace('/:\d+$/', '', $rid);
		if (!empty($params['_none'])) {
			continue;
		}
		if ((($mode === 'lock') && fleet_policy_lockable($base)) || (($mode === 'remediate') && in_array($base, FLEET_POLICY_REMEDIABLE, true))) {
			$out[] = fleet_policy_node_rule($rid, $params, $mode);
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
	if (!empty($params['_none'])) {
		return array('unknown', 'Its groups name no ' . (($id === 'NAME-003') ? 'domain' : 'hostname pattern'));
	}
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
		return (fleet_channel_name($c) === fleet_channel_name($params['channel'])) ? array('pass', "Follows {$c}") : array('fail', "Follows {$c}, should follow {$params['channel']}");
	case 'login_protection':
		$pass = fleet_config_values($facts['config'] ?? null, 'system/sshguard_whitelist');
		if ($pass === null) {
			return array('unknown', 'No configuration backup yet');
		}
		foreach (preg_split('/[\s,]+/', (string)($pass[0] ?? ''), -1, PREG_SPLIT_NO_EMPTY) as $net) {
			if (in_array(strtolower($net), array('any', '0.0.0.0/0', '::/0', '0.0.0.0/1', '128.0.0.0/1'), true)) {
				return array('fail', "The pass list contains {$net}: login protection never blocks");
			}
		}
		$t = fleet_config_values($facts['config'], 'system/sshguard_threshold');
		$t = (string)($t[0] ?? '');
		$max = (int)($params['threshold'] ?? 30);
		if (($t !== '') && ((int)$t > $max)) {
			return array('fail', "Blocks after an attack score of {$t} (at most {$max})");
		}
		return array('pass', ($t === '') ? 'Default threshold, no open pass list' : "Threshold {$t}, no open pass list");
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
			} elseif (($l === $lv[$rid]) && (($params !== $out[$rid][0]) || ($mode !== $out[$rid][1]))) {
				/* The same level disagrees (what to check, or how hard): shown as a conflict; the stricter mode is the one enforced. */
				$strict = array_flip(array('audit', 'remediate', 'lock'));
				if (($strict[$mode] ?? 0) > ($strict[$out[$rid][1]] ?? 0)) {
					$out[$rid] = array($params, $mode, (int)$p['id'], $p['name'], $out[$rid][4] ?? $out[$rid][3]);
				} elseif ($out[$rid][4] === null) {
					$out[$rid][4] = $p['name'];
				}
			}
		}
	}
	ksort($out);
	return $out;
}

/*
 * pure: the number for a new custom rule: the lowest free one across every policy
 * (rule ids are fleet-wide: the compliance table, exceptions and the firewall's
 * own rule list all key on them, and the firewall accepts CUS-001 to CUS-999).
 * $policies: policy rows. Throws when all 999 are taken.
 */
function fleet_policy_custom_next(array $policies): int {
	$used = array();
	foreach ($policies as $p) {
		foreach (array_keys((array)$p['rules']) as $rid) {
			if (strncmp((string)$rid, 'CUSTOM:', 7) === 0) {
				$used[(int)substr((string)$rid, 7)] = true;
			}
		}
	}
	for ($n = 1; $n <= 999; $n++) {
		if (!isset($used[$n])) {
			return $n;
		}
	}
	throw new InvalidArgumentException('All 999 custom rules are in use. Remove some first.');
}

/* pure: the effective rules of a firewall without those it has an exception for (they must not be locked or fixed on it either). */
function fleet_policy_without_exceptions(array $eff, array $exceptions, string $node, int $now): array {
	foreach (array_keys($eff) as $rid) {
		if (fleet_policy_excepted($exceptions, $node, (string)$rid, $now) !== null) {
			unset($eff[$rid]);
		}
	}
	return $eff;
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
	/* A custom rule number belongs to one policy (two forms open at once could pick the same one). */
	foreach (fleet_policies_all() as $other) {
		foreach (array_keys($rules) as $rid) {
			if ((strncmp($rid, 'CUSTOM:', 7) === 0) && ((int)$other['id'] !== (int)$id) && isset($other['rules'][$rid])) {
				throw new InvalidArgumentException(sprintf('Custom rule %d is already used by the policy "%s". Open the policy again and add the rule again.', (int)substr($rid, 7), $other['name']));
			}
		}
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
	/* Checking every firewall and sending the lock rules takes minutes on a big fleet: the poll does it (within a minute), not this page. */
	fleet_compliance_queue();
	return $id;
}

/* Ask the poll to check every firewall and send the lock rules now (it does within a minute). */
function fleet_compliance_queue(): void {
	fleet_setting_set('compliance_due', (string)time());
}

/* Is a full check due: asked for (a policy changed) or the last one is 15 minutes old? */
function fleet_compliance_due(int $now): bool {
	return ((int)fleet_setting('compliance_due', '0') > 0) || (($now - (int)fleet_setting('compliance_checked', '0')) >= 900);
}

function fleet_policy_delete(int $id, string $who): void {
	$p = fleet_policy_get($id);
	fleet_db()->prepare('DELETE FROM policies WHERE id = ?')->execute(array($id));
	fleet_audit($who, 'policy', ($p['name'] ?? (string)$id) . ': deleted');
	fleet_compliance_queue();
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
function fleet_box_facts(array $box, bool $with_config = true): array {
	$st = json_decode((string)($box['status'] ?? ''), true) ?: array();
	$info = fleet_update_info($box);
	$latest = fleet_backup_latest($box['node_id']);
	$xml = null;
	/* Decrypting and parsing the newest backup is the expensive part: only for firewalls with a rule that reads the configuration. */
	if (($latest !== null) && $with_config) {
		$text = fleet_backup_read($latest);
		$prev = libxml_use_internal_errors(true);
		$xml = ($text === null) ? null : (simplexml_load_string($text, 'SimpleXMLElement', LIBXML_NONET) ?: null);
		libxml_use_internal_errors($prev);
	}
	return array('version' => (string)($st['version'] ?? ''), 'channel' => (string)($info['channel'] ?? ''),
	    'rollback' => isset($st['rollback_protection']) ? (bool)$st['rollback_protection'] : null,
	    'last_backup' => ($latest === null) ? null : (int)$latest['time'], 'config' => $xml, 'now' => time());
}

/* A firewall's effective rules right now (rules that take their value from its naming group get it here). */
function fleet_box_effective(string $node, ?array $policies = null, ?array $groups = null): array {
	$eff = fleet_policy_effective($policies ?? fleet_policies_all(), $node, ($groups ?? fleet_box_group_ids())[$node] ?? array());
	if (isset($eff['NAME-003']) || isset($eff['NAME-004'])) {
		foreach (array('NAME-003' => 'domain', 'NAME-004' => 'pattern') as $rid => $what) {
			if (isset($eff[$rid])) {
				$eff[$rid][0] = fleet_policy_group_params($what, fleet_naming_group_of($node, $what)[0]);
			}
		}
	}
	return $eff;
}

/* pure: the parameters of a "from its group" rule: the group's domain or pattern, or none. */
function fleet_policy_group_params(string $what, ?array $group): array {
	$v = (string)($group['naming_' . $what] ?? '');
	if ($v === '') {
		return array('_none' => 1);
	}
	return ($what === 'domain') ? array('value' => $v, '_group' => $group['name']) : array('regex' => fleet_naming_regex($v), '_group' => $group['name']);
}

/* pure: does this check result start a "failing a High rule" alert? $was: the rule ids that failed at the last check. */
function fleet_policy_fail_alerts(string $rid, string $state, array $was): bool {
	$base = preg_replace('/:\d+$/', '', $rid);
	return ($state === 'fail') && !in_array($rid, $was, true) && ((fleet_policy_catalog()[$base]['severity'] ?? '') === 'high');
}

/* Check every firewall (or one) against its effective rules and keep the result. Exceptions turn a failure into "excepted". */
function fleet_compliance_refresh(?string $only = null, bool $push = true): void {
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
		$needs_config = !empty(array_filter(array_keys($eff), function ($rid) { return fleet_policy_lockable((string)preg_replace('/:\d+$/', '', (string)$rid)); }));
		$facts = empty($eff) ? array() : fleet_box_facts($box, $needs_config);
		$alerts = array();
		/* One transaction per firewall: a reader never sees its results half replaced, and it costs one disk sync, not one per rule. */
		fleet_transaction(function () use ($box, $eff, $facts, $exceptions, $now, &$alerts): void {
			$was = fleet_db()->prepare("SELECT rule_id FROM compliance WHERE node_id = ? AND state = 'fail'");
			$was->execute(array($box['node_id']));
			$was = $was->fetchAll(PDO::FETCH_COLUMN);
			fleet_db()->prepare('DELETE FROM compliance WHERE node_id = ?')->execute(array($box['node_id']));
			$ins = fleet_db()->prepare('INSERT INTO compliance (node_id, rule_id, state, detail, policy_id, conflict, checked) VALUES (?, ?, ?, ?, ?, ?, ?)');
			foreach ($eff as $rid => list($params, $mode, $pid, $pname, $conflict)) {
				list($state, $detail) = fleet_policy_check($rid, $params, $facts);
				if (($state === 'fail') && (($e = fleet_policy_excepted($exceptions, $box['node_id'], $rid, $now)) !== null)) {
					$state = 'excepted';
					$detail .= ' (exception until ' . date('Y-m-d', (int)$e['expires'] - 1) . ')';
				}
				$ins->execute(array($box['node_id'], $rid, $state, $detail, $pid, $conflict, $now));
				if (fleet_policy_fail_alerts($rid, $state, $was)) {
					$alerts[] = sprintf('%s fails %s (%s): %s', $box['label'], fleet_policy_rule_title($rid, $params), $pname, $detail);
				}
			}
		});
		foreach ($alerts as $text) {
			fleet_alert('policy_fail', $box['node_id'], $text);
		}
	}
	if ($only === null) {
		fleet_setting_set('compliance_checked', (string)$now);
	}
	if ($push) {
		fleet_bundles_push(($only === null) ? null : array($only));
	}
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

/* A bundle_state row as the pages and the push read it. */
function fleet_bundle_state_row(array $r): array {
	return array('hash' => (string)$r['hash'], 'version' => (int)$r['version'], 'sent' => ($r['sent'] === null) ? null : (int)$r['sent'],
	    'error' => ($r['error'] === null) ? null : (string)$r['error'], 'rules' => (int)$r['rules'], 'lock_accounts' => !empty($r['lock_accounts']));
}

/* node_id => {hash, version, sent, error, rules, lock_accounts} of the last bundle Fleet tried to send (one row per firewall). */
function fleet_bundle_state(): array {
	$out = array();
	foreach (fleet_db()->query('SELECT * FROM bundle_state')->fetchAll() as $r) {
		$out[$r['node_id']] = fleet_bundle_state_row($r);
	}
	return $out;
}

/* One firewall's bundle state, or null when none was ever tried. */
function fleet_bundle_state_get(string $node): ?array {
	$q = fleet_db()->prepare('SELECT * FROM bundle_state WHERE node_id = ?');
	$q->execute(array($node));
	$r = $q->fetch();
	return is_array($r) ? fleet_bundle_state_row($r) : null;
}

/* Record one firewall's bundle state (a single statement: parallel pushes and the poll never overwrite each other's firewalls). */
function fleet_bundle_state_set(string $node, array $s): void {
	fleet_db()->prepare('INSERT INTO bundle_state (node_id, hash, version, sent, error, rules, lock_accounts) VALUES (?, ?, ?, ?, ?, ?, ?)
	    ON CONFLICT(node_id) DO UPDATE SET hash = excluded.hash, version = excluded.version, sent = excluded.sent, error = excluded.error,
	    rules = excluded.rules, lock_accounts = excluded.lock_accounts')
	    ->execute(array($node, (string)$s['hash'], (int)($s['version'] ?? 0), isset($s['sent']) ? (int)$s['sent'] : null, $s['error'] ?? null,
	    (int)($s['rules'] ?? 0), empty($s['lock_accounts']) ? 0 : 1));
}

/* The signed bundle text for a firewall: array(text, signature base64). Versions only grow (time-based). */
function fleet_bundle_make(string $node, array $rules, int $version, bool $lock_accounts = false): array {
	$text = json_encode(array('version' => $version, 'node_id' => $node, 'issued' => time(), 'rules' => $rules) + ($lock_accounts ? array('lock_accounts' => true) : array()),
	    JSON_UNESCAPED_SLASHES);
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
	$policies = fleet_policies_all();
	$groups = fleet_box_group_ids();
	$lock_users = fleet_users_locked() ? array_flip(fleet_users_nodes()) : array();
	$exceptions = fleet_policy_exceptions();
	foreach (fleet_db()->query('SELECT * FROM boxes')->fetchAll() as $box) {
		if ((($only !== null) && !in_array($box['node_id'], $only, true)) || !fleet_manage_allowed($box)) {
			continue;
		}
		/* A rule with an exception on this firewall is neither locked nor fixed there: the firewall must accept what the exception allows. */
		$rules = fleet_policy_lock_rules(fleet_policy_without_exceptions(fleet_box_effective($box['node_id'], $policies, $groups), $exceptions, $box['node_id'], time()));
		$lock_acc = isset($lock_users[$box['node_id']]);
		$hash = hash('sha256', json_encode($rules) . ($lock_acc ? '+accounts' : ''));
		$prev = fleet_bundle_state_get($box['node_id']);
		if ((($prev === null) && empty($rules) && !$lock_acc) || (($prev !== null) && ($prev['hash'] === $hash) && empty($prev['error']))) {
			continue;
		}
		if ($box['state'] !== 'online') {
			fleet_bundle_state_set($box['node_id'], array('hash' => $hash, 'version' => $prev['version'] ?? 0, 'sent' => $prev['sent'] ?? null,
			    'error' => 'Waiting for the firewall to come online', 'rules' => count($rules)));
			continue;
		}
		$version = max(time(), (int)($prev['version'] ?? 0) + 1);
		try {
			list($text, $sig) = fleet_bundle_make($box['node_id'], $rules, $version, $lock_acc);
			list($code, $json) = fleet_box_call($box, 'PUT', '/api/v1/management/policy-bundle', array('bundle' => $text, 'signature' => $sig));
			if ($code !== 200) {
				throw new RuntimeException('FLEET-E320: The firewall refused the lock rules: ' . fleet_box_error($code, $json));
			}
			fleet_bundle_state_set($box['node_id'], array('hash' => $hash, 'version' => $version, 'sent' => time(), 'error' => null, 'rules' => count($rules), 'lock_accounts' => $lock_acc));
			fleet_audit('fleet', 'policy', sprintf('%s: %d lock and fix rules sent%s (bundle %d)', $box['label'], count($rules), $lock_acc ? ', Fleet users locked' : '', $version), $box['node_id']);
		} catch (RuntimeException $e) {
			fleet_bundle_state_set($box['node_id'], array('hash' => $hash, 'version' => $prev['version'] ?? 0, 'sent' => $prev['sent'] ?? null,
			    'error' => $e->getMessage(), 'rules' => count($rules)));
		}
	}
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
		fleet_audit('poll', 'policy', $text, $box['node_id']);
		if (function_exists('file_notice')) {
			file_notice('fleet', $text, 'FreeSense Fleet', '');
		}
	} elseif (($bg === null) && is_array($old['breakglass'] ?? null)) {
		fleet_audit('poll', 'policy', sprintf('%s: Lock is in force again (break-glass ended)', $box['label']), $box['node_id']);
	}
	$sent = fleet_bundle_state_get($box['node_id']);
	$held = (int)($status['policy_bundle']['version'] ?? 0);
	if (($sent !== null) && empty($sent['error']) && ($held < (int)$sent['version'])) {
		fleet_db()->prepare('UPDATE bundle_state SET error = ? WHERE node_id = ?')->execute(array('The firewall holds an older bundle; sending again', $box['node_id']));
	}
}

/* ------------------------------------------------------------------ */
/* Remediate                                                           */
/* ------------------------------------------------------------------ */

/* The window in which fixes of one rule on one firewall are counted, and how many are made automatically in it. */
define('FLEET_AUTOFIX_WINDOW', 86400);
define('FLEET_AUTOFIX_MAX', 3);

/* rule id => {time, hash, result, detail, fixed_count, fixed_since} of the last fix Fleet tried on a firewall (one row per firewall and rule). */
function fleet_remediations_for(string $node): array {
	$q = fleet_db()->prepare('SELECT rule_id, time, hash, result, detail, fixed_count, fixed_since FROM remediation_state WHERE node_id = ?');
	$q->execute(array($node));
	$out = array();
	foreach ($q->fetchAll() as $r) {
		$out[$r['rule_id']] = array('time' => (int)$r['time'], 'hash' => $r['hash'], 'result' => $r['result'], 'detail' => $r['detail'],
		    'fixed_count' => (int)$r['fixed_count'], 'fixed_since' => (int)$r['fixed_since']);
	}
	return $out;
}

/* Record the last fix tried for one rule on one firewall. */
function fleet_remediation_record(string $node, string $rid, string $hash, string $result, string $detail): int {
	$now = time();
	$q = fleet_db()->prepare('SELECT fixed_count, fixed_since FROM remediation_state WHERE node_id = ? AND rule_id = ?');
	$q->execute(array($node, $rid));
	$prev = $q->fetch() ?: array('fixed_count' => 0, 'fixed_since' => 0);
	/* Fixes that worked, counted over a day: a rule somebody keeps changing back is not fixed again and again. */
	if ($result !== 'fixed') {
		$count = (int)$prev['fixed_count'];
		$since = (int)$prev['fixed_since'];
	} elseif (($now - (int)$prev['fixed_since']) < FLEET_AUTOFIX_WINDOW) {
		$count = (int)$prev['fixed_count'] + 1;
		$since = (int)$prev['fixed_since'];
	} else {
		$count = 1;
		$since = $now;
	}
	fleet_db()->prepare('INSERT INTO remediation_state (node_id, rule_id, time, hash, result, detail, fixed_count, fixed_since) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	    ON CONFLICT(node_id, rule_id) DO UPDATE SET time = excluded.time, hash = excluded.hash, result = excluded.result, detail = excluded.detail,
	    fixed_count = excluded.fixed_count, fixed_since = excluded.fixed_since')
	    ->execute(array($node, $rid, $now, $hash, $result, $detail, $count, $since));
	return $count;
}

/* Is a firewall inside a maintenance window now? (No window on any of its groups: always.) */
function fleet_box_window_open(string $node, int $now): bool {
	$q = fleet_db()->prepare('SELECT g.window_id FROM box_groups bg JOIN fleet_groups g ON g.id = bg.group_id WHERE bg.node_id = ? AND g.window_id IS NOT NULL');
	$q->execute(array($node));
	$ids = array_map('intval', $q->fetchAll(PDO::FETCH_COLUMN));
	if (empty($ids)) {
		return true;
	}
	foreach ($ids as $id) {
		$w = fleet_window_get($id);
		if (($w !== null) && fleet_window_state($w, $now, fleet_tz())[0]) {
			return true;
		}
	}
	return false;
}

/*
 * pure: which failing rules to fix now. $failing: rule id => params of
 * failing remediate rules; $last: this firewall's last attempts. A rule
 * whose fix failed or could not be done is not tried again until its
 * settings change; a fix that worked waits an hour for the next backup to
 * show it.
 */
function fleet_remediate_due(array $failing, array $last, int $now, bool $manual): array {
	$out = array();
	foreach ($failing as $rid => $params) {
		$hash = hash('sha256', json_encode($params));
		$prev = $last[$rid] ?? null;
		if (!$manual && ($prev !== null) && ($prev['hash'] === $hash) &&
		    (($prev['result'] !== 'fixed') || (($now - (int)$prev['time']) < 3600))) {
			continue;
		}
		/* Fixed and changed back again too often in a day: somebody or something undoes it, so stop and let a person look. */
		if (!$manual && ($prev !== null) && ((int)($prev['fixed_count'] ?? 0) >= FLEET_AUTOFIX_MAX) && (($now - (int)($prev['fixed_since'] ?? 0)) < FLEET_AUTOFIX_WINDOW)) {
			continue;
		}
		$out[$rid] = $hash;
	}
	return $out;
}

/*
 * Have one firewall fix its failing remediate rules. $manual: an admin
 * pressed "Fix now" (outside the window too, and again after a failure).
 * Returns the words for the result.
 */
function fleet_remediate_box(array $box, string $who, bool $manual = false): string {
	fleet_manage_require($box);
	$eff = fleet_box_effective($box['node_id']);
	$q = fleet_db()->prepare("SELECT rule_id FROM compliance WHERE node_id = ? AND state = 'fail'");
	$q->execute(array($box['node_id']));
	$failing = array();
	foreach ($q->fetchAll(PDO::FETCH_COLUMN) as $rid) {
		if ((($eff[$rid][1] ?? '') === 'remediate')) {
			$failing[$rid] = $eff[$rid][0];
		}
	}
	$due = fleet_remediate_due($failing, fleet_remediations_for($box['node_id']), time(), $manual);
	if (empty($due)) {
		return 'Nothing to fix.';
	}
	if (!$manual && !fleet_box_window_open($box['node_id'], time())) {
		return 'Waiting for the maintenance window.';
	}
	$bundle = fleet_bundle_state_get($box['node_id']);
	if (($bundle === null) || !empty($bundle['error'])) {
		fleet_bundles_push(array($box['node_id']));
		$bundle = fleet_bundle_state_get($box['node_id']);
		if (($bundle === null) || !empty($bundle['error'])) {
			return 'The firewall does not have the policy rules yet.';
		}
	}
	$node_ids = array();
	foreach (array_keys($due) as $rid) {
		$node_ids[fleet_policy_node_rule($rid, $failing[$rid], 'remediate')['id']] = $rid;
	}
	$record = function (string $rid, string $result, string $detail) use ($box, $due): int {
		return fleet_remediation_record($box['node_id'], $rid, $due[$rid], $result, $detail);
	};
	try {
		fleet_backup_box($box, 'remediation', $who);
		list($code, $json) = fleet_box_call($box, 'POST', '/api/v1/management/remediate', array('rules' => array_keys($node_ids)));
		if ($code !== 200) {
			throw new RuntimeException(fleet_box_error($code, $json));
		}
	} catch (RuntimeException $e) {
		foreach ($due as $rid => $h) {
			$record($rid, 'failed', $e->getMessage());
		}
		fleet_audit($who, 'policy', "FLEET-E320: {$box['label']}: the fix failed: " . $e->getMessage(), $box['node_id']);
		return 'FLEET-E320: The fix failed: ' . $e->getMessage();
	}
	$fixed = array();
	$words = array();
	foreach ((array)($json['data'] ?? array()) as $r) {
		$rid = $node_ids[(string)($r['id'] ?? '')] ?? null;
		if ($rid === null) {
			continue;
		}
		$res = in_array($r['result'] ?? '', array('fixed', 'compliant'), true) ? 'fixed' : 'cannot';
		$fixes = $record($rid, $res, (string)($r['detail'] ?? ''));
		if (($res === 'fixed') && ($fixes >= FLEET_AUTOFIX_MAX)) {
			fleet_audit($who, 'policy', sprintf('FLEET-E320: %s: %s was changed back on the firewall %d times within a day; automatic fixes of it stop until you press Fix now.',
			    $box['label'], fleet_policy_rule_title($rid, $failing[$rid]), $fixes), $box['node_id']);
		}
		$words[] = fleet_policy_rule_title($rid, $failing[$rid]) . ': ' . (string)($r['detail'] ?? '');
		if ($res === 'fixed') {
			$fixed[] = $rid;
		} else {
			fleet_audit($who, 'policy', "FLEET-E320: {$box['label']}: " . fleet_policy_rule_title($rid, $failing[$rid]) . ': ' . (string)($r['detail'] ?? ''), $box['node_id']);
		}
	}
	fleet_audit($who, 'policy', "{$box['label']}: remediation: " . implode('; ', $words), $box['node_id']);
	if (!empty($fixed)) {
		/* A fresh backup shows the fix in compliance at once. */
		try {
			fleet_backup_box($box, 'change', $who);
		} catch (RuntimeException $e) {
		}
		fleet_compliance_refresh($box['node_id'], false);
	}
	return implode(' ', $words);
}

/* From the poll: fix what is due on every online managed firewall. */
function fleet_remediate_tick(): void {
	foreach (fleet_db()->query("SELECT * FROM boxes WHERE state = 'online'")->fetchAll() as $box) {
		if (!fleet_manage_allowed($box)) {
			continue;
		}
		try {
			fleet_remediate_box($box, 'fleet');
		} catch (RuntimeException $e) {
		}
	}
}

