<?php
/*
 * fleet_naming.inc
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
 * Naming per group: a firewall group can carry a hostname pattern and a
 * domain, e.g. "{site}-fw{nn}" and "shops.example.local". An invitation
 * for that group gets the next name (counters never go back, so a number
 * is never used twice) and the firewall takes the name and domain when
 * it joins. Policy rules NAME-003/NAME-004 check firewalls already in the
 * fleet against their group's naming.
 *
 * Tokens: {site} {role} {group} (letters, digits and - only), {nn} {nnn}
 * (the counter, 2 or 3 digits).
 */

require_once('fleet/fleet_store.inc');

define('FLEET_NAMING_TOKENS', array('site', 'role', 'group', 'nn', 'nnn'));

/* pure: a pattern is usable (known tokens, one counter at most, valid characters). Returns null or the problem. */
function fleet_naming_pattern_problem(string $pattern): ?string {
	if ($pattern === '') {
		return null;
	}
	if (strlen($pattern) > 63) {
		return 'A hostname pattern is at most 63 characters.';
	}
	preg_match_all('/\{([a-z]+)\}/', $pattern, $m);
	foreach ($m[1] as $t) {
		if (!in_array($t, FLEET_NAMING_TOKENS, true)) {
			return "Unknown token {{$t}}: use {site}, {role}, {group}, {nn} or {nnn}.";
		}
	}
	if (count(array_intersect($m[1], array('nn', 'nnn'))) > 1) {
		return 'Use one counter ({nn} or {nnn}).';
	}
	$rest = preg_replace('/\{[a-z]+\}/', '', $pattern);
	if (!preg_match('/^[a-z0-9-]*$/D', $rest)) {
		return 'Between tokens use lower-case letters, digits and - only.';
	}
	return null;
}

/* pure: a domain is usable (empty: the group sets no domain). */
function fleet_naming_domain_ok(string $domain): bool {
	return ($domain === '') || (bool)preg_match('/^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/D', $domain);
}

/* pure: one token value as it may appear in a hostname. */
function fleet_naming_slug(string $s): string {
	return trim(preg_replace('/-+/', '-', preg_replace('/[^a-z0-9-]+/', '-', strtolower($s))), '-');
}

/* pure: the name for counter $n, or null when it is not a valid hostname. */
function fleet_naming_render(string $pattern, array $vars, int $n): ?string {
	$out = preg_replace_callback('/\{([a-z]+)\}/', function ($m) use ($vars, $n) {
		if ($m[1] === 'nn') {
			return sprintf('%02d', $n);
		}
		if ($m[1] === 'nnn') {
			return sprintf('%03d', $n);
		}
		return fleet_naming_slug((string)($vars[$m[1]] ?? ''));
	}, $pattern);
	return preg_match('/^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/D', $out) ? $out : null;
}

/* pure: the counter's scope: the pattern with everything but the counter filled in. */
function fleet_naming_scope(int $gid, string $pattern, array $vars): string {
	return $gid . ':' . preg_replace_callback('/\{([a-z]+)\}/', function ($m) use ($vars) {
		return in_array($m[1], array('nn', 'nnn'), true) ? '#' : fleet_naming_slug((string)($vars[$m[1]] ?? ''));
	}, $pattern);
}

/*
 * pure: the next free name from counter $start: skips names in $taken.
 * Returns array(name, the counter used) or null.
 */
function fleet_naming_next(string $pattern, array $vars, int $start, array $taken): ?array {
	$taken = array_flip(array_map('strtolower', $taken));
	$counted = (bool)preg_match('/\{nnn?\}/', $pattern);
	for ($n = max(1, $start); $n < $start + 1000; $n++) {
		$name = fleet_naming_render($pattern, $vars, $n);
		if ($name === null) {
			return null;
		}
		if (!isset($taken[$name])) {
			return array($name, $n);
		}
		if (!$counted) {
			return null;
		}
	}
	return null;
}

/* pure: a regular expression a hostname following the pattern matches (tokens other than the counter: any slug). */
function fleet_naming_regex(string $pattern): string {
	$parts = preg_split('/(\{[a-z]+\})/', $pattern, -1, PREG_SPLIT_DELIM_CAPTURE);
	$re = '';
	foreach ($parts as $p) {
		if ($p === '{nn}') {
			$re .= '[0-9]{2,}';
		} elseif ($p === '{nnn}') {
			$re .= '[0-9]{3,}';
		} elseif (preg_match('/^\{[a-z]+\}$/', $p)) {
			$re .= '[a-z0-9]+(-[a-z0-9]+)*';
		} else {
			$re .= preg_quote($p, '/');
		}
	}
	return '^' . $re . '$';
}

/* ------------------------------------------------------------------ */
/* Storage                                                             */
/* ------------------------------------------------------------------ */

function fleet_naming_set(int $gid, string $pattern, string $domain, string $who): void {
	$pattern = strtolower(trim($pattern));
	$domain = strtolower(trim($domain));
	$problem = fleet_naming_pattern_problem($pattern);
	if ($problem !== null) {
		throw new InvalidArgumentException($problem);
	}
	if (!fleet_naming_domain_ok($domain)) {
		throw new InvalidArgumentException('The domain is a name like shops.example.local.');
	}
	$g = fleet_group_get($gid);
	if (($g !== null) && ((string)($g['naming_pattern'] ?? '') === $pattern) && ((string)($g['naming_domain'] ?? '') === $domain)) {
		return;
	}
	fleet_db()->prepare('UPDATE fleet_groups SET naming_pattern = ?, naming_domain = ? WHERE id = ?')->execute(array($pattern, $domain, $gid));
	fleet_audit($who, 'group_change', sprintf('group %d naming: %s%s', $gid, ($pattern === '') ? 'no pattern' : $pattern, ($domain === '') ? '' : ' . ' . $domain));
}

/* Every hostname in the fleet now and every name an open invitation holds. */
function fleet_naming_taken(): array {
	$names = fleet_db()->query('SELECT name FROM boxes')->fetchAll(PDO::FETCH_COLUMN);
	$names = array_merge($names, fleet_db()->query("SELECT hostname FROM invitations WHERE hostname != '' AND state = 'open'")->fetchAll(PDO::FETCH_COLUMN));
	return array_values(array_filter(array_map(function ($n) { return strtolower(strtok((string)$n, '.')); }, $names), 'strlen'));
}

/* The next name for a group (and keep the counter): array(hostname, domain), or array('', '') when the group names nothing. */
function fleet_naming_take(int $gid, array $vars): array {
	$g = fleet_group_get($gid);
	if (($g === null) || ((string)($g['naming_pattern'] ?? '') === '')) {
		return array('', (string)($g['naming_domain'] ?? ''));
	}
	$vars['group'] = $vars['group'] ?? $g['name'];
	$scope = fleet_naming_scope($gid, $g['naming_pattern'], $vars);
	$q = fleet_db()->prepare('SELECT next FROM name_counters WHERE scope = ?');
	$q->execute(array($scope));
	$start = (int)($q->fetchColumn() ?: 1);
	$got = fleet_naming_next($g['naming_pattern'], $vars, $start, fleet_naming_taken());
	if ($got === null) {
		throw new InvalidArgumentException(sprintf('The group\'s pattern %s gives no free hostname here. Fill in the site, or write the hostname yourself.', $g['naming_pattern']));
	}
	fleet_db()->prepare('INSERT OR REPLACE INTO name_counters (scope, next) VALUES (?, ?)')->execute(array($scope, $got[1] + 1));
	return array($got[0], (string)$g['naming_domain']);
}

/* The next name without taking it (for previews). */
function fleet_naming_peek(int $gid, array $vars): ?string {
	$g = fleet_group_get($gid);
	if (($g === null) || ((string)($g['naming_pattern'] ?? '') === '')) {
		return null;
	}
	$vars['group'] = $vars['group'] ?? $g['name'];
	$q = fleet_db()->prepare('SELECT next FROM name_counters WHERE scope = ?');
	$q->execute(array(fleet_naming_scope($gid, $g['naming_pattern'], $vars)));
	$got = fleet_naming_next($g['naming_pattern'], $vars, (int)($q->fetchColumn() ?: 1), fleet_naming_taken());
	return ($got === null) ? null : $got[0] . (((string)$g['naming_domain'] !== '') ? '.' . $g['naming_domain'] : '');
}

/*
 * A firewall's naming group: the first of its groups (by name) with a
 * domain or pattern, and the other groups that name it differently.
 * Returns array(group row or null, conflicting group names).
 */
function fleet_naming_group_of(string $node): array {
	$q = fleet_db()->prepare("SELECT g.* FROM box_groups bg JOIN fleet_groups g ON g.id = bg.group_id WHERE bg.node_id = ?
	    AND (g.naming_pattern != '' OR g.naming_domain != '') ORDER BY g.name COLLATE NOCASE");
	$q->execute(array($node));
	$rows = $q->fetchAll();
	if (empty($rows)) {
		return array(null, array());
	}
	$first = $rows[0];
	$other = array();
	foreach (array_slice($rows, 1) as $r) {
		if (($r['naming_pattern'] !== $first['naming_pattern']) || ($r['naming_domain'] !== $first['naming_domain'])) {
			$other[] = $r['name'];
		}
	}
	return array($first, $other);
}

/*
 * Name an invitation: the firewall joins group $gid and takes the name.
 * $hostname: typed by the admin (wins), or blank for the group's next
 * name. Returns array(hostname, domain) ('' when nothing is set).
 */
function fleet_invite_set_name(string $token_id, int $gid, string $site, string $role, string $hostname, string $who): array {
	if ($gid <= 0) {
		return array('', '');
	}
	if (fleet_group_get($gid) === null) {
		throw new InvalidArgumentException('That group no longer exists.');
	}
	$hostname = strtolower(trim($hostname));
	if ($hostname !== '') {
		if (!preg_match('/^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/D', $hostname)) {
			throw new InvalidArgumentException('A hostname is letters, digits and -, up to 63 characters.');
		}
		if (in_array($hostname, fleet_naming_taken(), true)) {
			throw new InvalidArgumentException("Another firewall or invitation already has the name {$hostname}.");
		}
		$domain = (string)fleet_group_get($gid)['naming_domain'];
	} else {
		list($hostname, $domain) = fleet_naming_take($gid, array('site' => $site, 'role' => $role));
	}
	fleet_db()->prepare('UPDATE invitations SET group_id = ?, hostname = ?, domain = ? WHERE token_id = ?')->execute(array($gid, $hostname, $domain, $token_id));
	if ($hostname !== '') {
		fleet_audit($who, 'invite', "{$token_id} named {$hostname}" . (($domain !== '') ? ".{$domain}" : ''));
	}
	return array($hostname, $domain);
}

