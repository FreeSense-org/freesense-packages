<?php
/*
 * fleet_users.inc
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
 * Central users and user groups, synced to firewalls. A user group holds
 * privileges and says which firewalls it is for (all, groups, single
 * firewalls); a user reaches a firewall through the user groups that are
 * for it. Each firewall gets its own set (format fleet-users-v1) and
 * keeps its local accounts; System's fleet_accounts.inc does the work on
 * the firewall and leaves out privileges its version does not know.
 * Passwords are stored and sent only as bcrypt hashes.
 */

require_once('fleet/fleet_store.inc');

define('FLEET_USERS_FORMAT', 'fleet-users-v1');

/* ------------------------------------------------------------------ */
/* Pure                                                                */
/* ------------------------------------------------------------------ */

/* pure: a valid account name (the firewall checks the same). */
function fleet_users_valid_name(string $name): bool {
	return (bool)preg_match('/^[a-z_][a-z0-9._-]{0,31}$/iD', $name) &&
	    !in_array(strtolower($name), array('root', 'admin', 'fleet-controller', 'nobody', 'toor', 'daemon', 'operator', 'www', 'sshd', 'uucp', 'unbound', 'dhcpd',
	    'admins', 'all', 'wheel', 'nogroup'), true);
}

/*
 * pure: the set one firewall gets. $users: rows with groups (ids);
 * $groups: id => row with privs; $for: the user group ids that are for
 * this firewall.
 */
function fleet_users_desired(array $users, array $groups, array $for): array {
	$out = array('format' => FLEET_USERS_FORMAT, 'groups' => array(), 'users' => array());
	foreach ($for as $gid) {
		if (isset($groups[$gid])) {
			$g = $groups[$gid];
			$out['groups'][] = array('name' => $g['name'], 'description' => $g['description'], 'privs' => array_values($g['privs']));
		}
	}
	foreach ($users as $u) {
		$mine = array_values(array_intersect($u['groups'], $for));
		if (empty($mine)) {
			continue;
		}
		$out['users'][] = array('name' => $u['name'], 'fullname' => $u['fullname'], 'bcrypt_hash' => $u['hash'], 'ssh_keys' => $u['ssh_keys'],
		    'expires' => $u['expires'], 'disabled' => (bool)$u['disabled'],
		    'groups' => array_values(array_map(function ($gid) use ($groups) { return $groups[$gid]['name']; }, $mine)));
	}
	return $out;
}

/* pure: counts of a firewall's plan (System's fleet_accounts_plan). */
function fleet_users_plan_counts(array $plan): array {
	$c = array('create' => 0, 'update' => 0, 'delete' => 0, 'same' => 0);
	foreach (array_merge(array_values((array)($plan['users'] ?? array())), array_values((array)($plan['groups'] ?? array()))) as $a) {
		$c[$a] = ($c[$a] ?? 0) + 1;
	}
	$c['clashes'] = count((array)($plan['clashes'] ?? array()));
	$c['skipped'] = array_sum(array_map('count', (array)($plan['skipped_privs'] ?? array())));
	return $c;
}

/* ------------------------------------------------------------------ */
/* Storage                                                             */
/* ------------------------------------------------------------------ */

function fleet_ugroups_all(): array {
	$out = array();
	foreach (fleet_db()->query('SELECT * FROM ugroups ORDER BY name COLLATE NOCASE')->fetchAll() as $r) {
		$r['privs'] = json_decode((string)$r['privs'], true) ?: array();
		$r['targets'] = json_decode((string)$r['targets'], true) ?: array();
		$out[(int)$r['id']] = $r;
	}
	return $out;
}

function fleet_fusers_all(): array {
	$members = array();
	foreach (fleet_db()->query('SELECT user_id, group_id FROM ugroup_members')->fetchAll() as $m) {
		$members[(int)$m['user_id']][] = (int)$m['group_id'];
	}
	$out = array();
	foreach (fleet_db()->query('SELECT * FROM fusers ORDER BY name COLLATE NOCASE')->fetchAll() as $r) {
		$r['groups'] = $members[(int)$r['id']] ?? array();
		$out[(int)$r['id']] = $r;
	}
	return $out;
}

/* The privileges a user group can hold: the controller's own catalog, plus those firewalls of other versions reported. name => description. */
function fleet_users_catalog(): array {
	$out = array();
	if (is_file('/etc/inc/fleet_accounts.inc')) {
		require_once('fleet_accounts.inc');
		$out = fleet_accounts_catalog();
	}
	foreach (fleet_users_version_catalogs() as $names) {
		foreach ($names as $n) {
			$out[$n] = $out[$n] ?? $n;
		}
	}
	ksort($out);
	return $out;
}

/* version => privilege names, as firewalls of that version reported them. */
function fleet_users_version_catalogs(): array {
	return json_decode((string)fleet_setting('priv_catalogs', '{}'), true) ?: array();
}

function fleet_ugroup_save(?int $id, array $in, string $who): int {
	$name = trim((string)($in['name'] ?? ''));
	if (!fleet_users_valid_name($name)) {
		throw new InvalidArgumentException('Group names are 1 to 32 letters, digits, ., - or _, start with a letter, and are not a name the firewall uses itself (admins, all...).');
	}
	$desc = mb_substr(trim(preg_replace('/[\x00-\x1f\x7f]/u', ' ', (string)($in['description'] ?? ''))), 0, 200);
	$catalog = fleet_users_catalog();
	$privs = array_values(array_unique(array_filter(array_map('strval', (array)($in['privs'] ?? array())), function ($p) use ($catalog) { return isset($catalog[$p]); })));
	if (empty($privs)) {
		throw new InvalidArgumentException('Choose at least one privilege.');
	}
	$targets = fleet_targets_from($in['targets'] ?? array());
	list(, $gone) = fleet_targets_now($targets);
	if (!empty($gone)) {
		throw new InvalidArgumentException('A chosen group or firewall does not exist any more. Choose again.');
	}
	$q = fleet_db()->prepare('SELECT COUNT(*) FROM ugroups WHERE name = ? COLLATE NOCASE AND id != ?');
	$q->execute(array($name, $id ?? 0));
	if ((int)$q->fetchColumn() > 0) {
		throw new InvalidArgumentException('There is already a user group with that name.');
	}
	$args = array($name, $desc, json_encode($privs), json_encode($targets), time());
	if ($id === null) {
		fleet_db()->prepare('INSERT INTO ugroups (name, description, privs, targets, updated, created) VALUES (?, ?, ?, ?, ?, ?)')->execute(array_merge($args, array(time())));
		$id = (int)fleet_db()->lastInsertId();
	} else {
		fleet_db()->prepare('UPDATE ugroups SET name = ?, description = ?, privs = ?, targets = ?, updated = ? WHERE id = ?')->execute(array_merge($args, array($id)));
	}
	fleet_audit($who, 'users', sprintf('User group %s: %d privileges for %s (sync to apply)', $name, count($privs), fleet_targets_text($targets, fleet_target_names())));
	return $id;
}

function fleet_ugroup_delete(int $id, string $who): void {
	$g = fleet_ugroups_all()[$id] ?? null;
	fleet_db()->prepare('DELETE FROM ugroup_members WHERE group_id = ?')->execute(array($id));
	fleet_db()->prepare('DELETE FROM ugroups WHERE id = ?')->execute(array($id));
	fleet_audit($who, 'users', 'User group ' . ($g['name'] ?? $id) . ': deleted (removed from the firewalls with the next sync)');
}

/*
 * Create or change a user from its form: name, fullname, groups[],
 * ssh_keys, expires, disabled, password + password_again (blank keeps the
 * old one; a new user without a password can sign in with SSH keys only).
 */
function fleet_fuser_save(?int $id, array $in, string $who): int {
	$name = trim((string)($in['name'] ?? ''));
	if (!fleet_users_valid_name($name)) {
		throw new InvalidArgumentException('User names are 1 to 32 letters, digits, ., - or _, start with a letter, and are not a name the firewall uses itself.');
	}
	$full = mb_substr(trim(preg_replace('/[\x00-\x1f\x7f]/u', ' ', (string)($in['fullname'] ?? ''))), 0, 100);
	$keys = trim(str_replace("\r", '', (string)($in['ssh_keys'] ?? '')));
	foreach (array_filter(explode("\n", $keys), 'strlen') as $line) {
		if (!preg_match('~^(ssh-(ed25519|rsa)|ecdsa-sha2-nistp(256|384|521)|sk-[a-z0-9@.-]+) [A-Za-z0-9+/=]{20,}( [^\x00-\x1f]{0,200})?$~D', trim($line))) {
			throw new InvalidArgumentException('SSH keys are public keys (ssh-ed25519 AAAA... name), one per line.');
		}
	}
	$expires = trim((string)($in['expires'] ?? ''));
	if (($expires !== '') && (!preg_match('/^\d{4}-\d{2}-\d{2}$/D', $expires) || (strtotime($expires) < time() - 86400))) {
		throw new InvalidArgumentException('The account ends on a date in the future, or never (leave it empty).');
	}
	$pw = (string)($in['password'] ?? '');
	if ($pw !== '') {
		if ($pw !== (string)($in['password_again'] ?? '')) {
			throw new InvalidArgumentException('The two passwords are not the same.');
		}
		if (strlen($pw) < 10) {
			throw new InvalidArgumentException('A password has at least 10 characters.');
		}
	}
	$groups = array_values(array_intersect(array_map('intval', (array)($in['groups'] ?? array())), array_keys(fleet_ugroups_all())));
	$q = fleet_db()->prepare('SELECT COUNT(*) FROM fusers WHERE name = ? COLLATE NOCASE AND id != ?');
	$q->execute(array($name, $id ?? 0));
	if ((int)$q->fetchColumn() > 0) {
		throw new InvalidArgumentException('There is already a user with that name.');
	}
	if ($id === null) {
		/* No password: a random one nobody knows, so only SSH keys work. */
		$hash = password_hash(($pw !== '') ? $pw : bin2hex(random_bytes(32)), PASSWORD_BCRYPT);
		fleet_db()->prepare('INSERT INTO fusers (name, fullname, hash, ssh_keys, expires, disabled, created, updated) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
		    ->execute(array($name, $full, $hash, $keys, $expires, empty($in['disabled']) ? 0 : 1, time(), time()));
		$id = (int)fleet_db()->lastInsertId();
	} else {
		fleet_db()->prepare('UPDATE fusers SET name = ?, fullname = ?, ssh_keys = ?, expires = ?, disabled = ?, updated = ? WHERE id = ?')
		    ->execute(array($name, $full, $keys, $expires, empty($in['disabled']) ? 0 : 1, time(), $id));
		if ($pw !== '') {
			fleet_db()->prepare('UPDATE fusers SET hash = ? WHERE id = ?')->execute(array(password_hash($pw, PASSWORD_BCRYPT), $id));
		}
	}
	fleet_db()->prepare('DELETE FROM ugroup_members WHERE user_id = ?')->execute(array($id));
	$ins = fleet_db()->prepare('INSERT INTO ugroup_members (user_id, group_id) VALUES (?, ?)');
	foreach ($groups as $gid) {
		$ins->execute(array($id, $gid));
	}
	fleet_audit($who, 'users', sprintf('User %s: %d groups%s%s (sync to apply)', $name, count($groups), empty($in['disabled']) ? '' : ', disabled', ($pw !== '') ? ', password set' : ''));
	return $id;
}

function fleet_fuser_delete(int $id, string $who): void {
	$u = fleet_fusers_all()[$id] ?? null;
	fleet_db()->prepare('DELETE FROM ugroup_members WHERE user_id = ?')->execute(array($id));
	fleet_db()->prepare('DELETE FROM fusers WHERE id = ?')->execute(array($id));
	fleet_audit($who, 'users', 'User ' . ($u['name'] ?? $id) . ': deleted (removed from the firewalls with the next sync)');
}

/* ------------------------------------------------------------------ */
/* Sync                                                                */
/* ------------------------------------------------------------------ */

/* node_id => user group ids that are for it. */
function fleet_users_for_boxes(array $ugroups): array {
	$out = array();
	foreach ($ugroups as $gid => $g) {
		foreach (array_column(fleet_targets_now($g['targets'])[0], 'node_id') as $node) {
			$out[$node][] = $gid;
		}
	}
	return $out;
}

/* The set one firewall gets now. */
function fleet_users_desired_for(string $node): array {
	$ug = fleet_ugroups_all();
	return fleet_users_desired(fleet_fusers_all(), $ug, fleet_users_for_boxes($ug)[$node] ?? array());
}

/* Ask a firewall what a sync would change (nothing changes). Also keeps its version's privilege catalog. */
function fleet_users_preview_box(array $box): array {
	fleet_manage_require($box);
	list($code, $json) = fleet_box_call($box, 'GET', '/api/v1/management/accounts');
	if ($code === 404) {
		throw new RuntimeException('FLEET-E440: This firewall\'s version cannot sync users yet; update it first.');
	}
	if ($code === 200) {
		$st = json_decode((string)($box['status'] ?? ''), true) ?: array();
		$ver = fleet_version_number((string)($st['version'] ?? ''));
		if ($ver !== '') {
			$cats = fleet_users_version_catalogs();
			$cats[$ver] = array_keys((array)($json['data']['privileges'] ?? array()));
			fleet_setting_set('priv_catalogs', json_encode($cats));
		}
	}
	list($code, $json) = fleet_box_call($box, 'PUT', '/api/v1/management/accounts', array('dry_run' => true) + fleet_users_desired_for($box['node_id']));
	if ($code !== 200) {
		throw new RuntimeException(fleet_box_error($code, $json));
	}
	return (array)$json['data'];
}

/* Sync one firewall. Returns the words for the result. */
function fleet_users_sync_box(array $box, string $who, ?callable $progress = null): string {
	$say = $progress ?? function () {};
	$say('Comparing', 15);
	$plan = fleet_users_preview_box($box);
	$c = fleet_users_plan_counts($plan);
	$notes = array();
	if ($c['clashes'] > 0) {
		$notes[] = 'FLEET-E441: skipped ' . implode(', ', $plan['clashes']) . ' (the firewall has its own account with that name)';
	}
	if ($c['skipped'] > 0) {
		$parts = array();
		foreach ((array)$plan['skipped_privs'] as $g => $privs) {
			$parts[] = $g . ': ' . implode(', ', $privs);
		}
		$notes[] = 'FLEET-E442: not on this version: ' . implode('; ', $parts);
	}
	if ($c['create'] + $c['update'] + $c['delete'] === 0) {
		fleet_users_state_set($box['node_id'], 'done', 'In sync' . (empty($notes) ? '' : '. ' . implode('. ', $notes)));
		return 'Already in sync.' . (empty($notes) ? '' : ' ' . implode('. ', $notes) . '.');
	}
	$say('Safety backup', 35);
	fleet_backup_box($box, 'users', $who);
	$say('Syncing users and groups', 65);
	list($code, $json) = fleet_box_call($box, 'PUT', '/api/v1/management/accounts', fleet_users_desired_for($box['node_id']));
	if ($code !== 200) {
		$err = fleet_box_error($code, $json);
		fleet_users_state_set($box['node_id'], 'failed', $err);
		throw new RuntimeException($err);
	}
	try {
		fleet_backup_box($box, 'change', $who);
	} catch (RuntimeException $e) {
	}
	$words = sprintf('%d added, %d changed, %d removed', $c['create'], $c['update'], $c['delete']) . (empty($notes) ? '' : '. ' . implode('. ', $notes));
	fleet_users_state_set($box['node_id'], 'done', $words);
	fleet_audit($who, 'users', "Sync to {$box['label']}: {$words}");
	return $words . '.';
}

function fleet_users_state_set(string $node, string $result, string $detail): void {
	$all = json_decode((string)fleet_setting('users_sync', '{}'), true) ?: array();
	$all[$node] = array('time' => time(), 'result' => $result, 'detail' => $detail);
	fleet_setting_set('users_sync', json_encode($all));
}

function fleet_users_states(): array {
	return json_decode((string)fleet_setting('users_sync', '{}'), true) ?: array();
}

/* Start syncing every firewall a user group is for (or $only) in the background. Returns the operation id. */
function fleet_users_launch(string $who, ?array $only = null): int {
	$nodes = array_keys(fleet_users_for_boxes(fleet_ugroups_all()));
	/* Firewalls that had Fleet users before but no longer get any must be cleaned too. */
	$nodes = array_values(array_unique(array_merge($nodes, array_keys(fleet_users_states()))));
	if ($only !== null) {
		$nodes = array_values(array_intersect($nodes, $only));
	}
	if (empty($nodes)) {
		throw new RuntimeException('No user group is for any firewall yet.');
	}
	$op = fleet_op_group_start('users', 'Sync users', $who);
	foreach (fleet_ha_sort($nodes) as $node) {
		$box = fleet_box_get($node);
		if ($box === null) {
			continue;
		}
		$synced = fleet_ha_sync_source($node, 'users');
		if ($synced !== null) {
			fleet_op_set(fleet_op_start($node, 'users', '', $who, $op, 'skipped'), 'skipped', sprintf('Skipped: HA sync brings the users from %s', $synced));
		} elseif (!fleet_manage_allowed($box)) {
			fleet_op_set(fleet_op_start($node, 'users', '', $who, $op, 'skipped'), 'skipped', 'Skipped: monitor only');
		} elseif ($box['state'] !== 'online') {
			fleet_op_set(fleet_op_start($node, 'users', '', $who, $op, 'skipped'), 'skipped', 'Skipped: the firewall is ' . $box['state'] . '; it is synced with the next sync');
		} else {
			fleet_op_start($node, 'users', 'Waiting', $who, $op, 'queued');
		}
	}
	fleet_op_group_update($op);
	fleet_audit($who, 'users', sprintf('Syncing users to %d firewalls', count($nodes)));
	mwexec_bg('/usr/local/bin/php /usr/local/sbin/freesense-fleet-run users ' . (int)$op);
	return $op;
}

/* ------------------------------------------------------------------ */
/* Lock, re-sync after updates, drift                                  */
/* ------------------------------------------------------------------ */

/* Do firewalls refuse local edits to Fleet users? */
function fleet_users_locked(): bool {
	return fleet_setting('users_lock', '0') === '1';
}

function fleet_users_lock_set(bool $on, string $who): void {
	fleet_setting_set('users_lock', $on ? '1' : '0');
	fleet_audit($who, 'users', $on ? 'Fleet users locked on the firewalls (local edits are refused)' : 'Fleet users no longer locked on the firewalls');
	fleet_bundles_push();
}

/* Firewalls that get (or had) Fleet users. */
function fleet_users_nodes(): array {
	return array_values(array_unique(array_merge(array_keys(fleet_users_for_boxes(fleet_ugroups_all())), array_keys(fleet_users_states()))));
}

/*
 * After each poll: a firewall that came back on another version is synced
 * again, so privileges its new version knows arrive (and old ones are
 * dropped cleanly).
 */
function fleet_users_follow(array $box, array $status): void {
	$old = json_decode((string)($box['status'] ?? ''), true) ?: array();
	$was = fleet_version_number((string)($old['version'] ?? ''));
	$now = fleet_version_number((string)($status['version'] ?? ''));
	if (($was === '') || ($now === '') || ($was === $now) || !in_array($box['node_id'], fleet_users_nodes(), true) || !fleet_manage_allowed($box)) {
		return;
	}
	try {
		fleet_users_launch('fleet', array($box['node_id']));
		fleet_audit('fleet', 'users', "{$box['label']}: updated from {$was} to {$now}; users synced again");
	} catch (RuntimeException $e) {
	}
}

/* pure: a Fleet user from the firewall's config entry (for Adopt). */
function fleet_users_from_entry(array $e): array {
	$exp = (string)($e['expires'] ?? '');
	$d = ($exp === '') ? false : DateTimeImmutable::createFromFormat('!m/d/Y', $exp);
	return array('fullname' => (string)($e['descr'] ?? ''), 'hash' => (string)($e['bcrypt-hash'] ?? ''),
	    'ssh_keys' => (($e['authorizedkeys'] ?? '') === '') ? '' : trim((string)base64_decode((string)$e['authorizedkeys'])),
	    'expires' => ($d === false) ? '' : $d->format('Y-m-d'), 'disabled' => isset($e['disabled']) ? 1 : 0);
}

/* The users and groups in a firewall's newest backup, or null. */
function fleet_users_backup_accounts(string $node): ?array {
	$latest = fleet_backup_latest($node);
	$text = ($latest === null) ? null : fleet_backup_read($latest);
	if ($text === null) {
		return null;
	}
	require_once('xmlparse.inc');
	$tmp = tempnam(sys_get_temp_dir(), 'fleetcfg');
	file_put_contents($tmp, $text);
	$cfg = parse_xml_config($tmp, array('freesense', 'pfsense'));
	@unlink($tmp);
	if (!is_array($cfg)) {
		return null;
	}
	return array((array)($cfg['system']['user'] ?? array()), (array)($cfg['system']['group'] ?? array()));
}

/*
 * Drift from a firewall's newest backup: what a sync would change now,
 * or null when not known. Ignored drift (the same plan as when Ignore was
 * pressed) comes back as no drift.
 */
function fleet_users_drift(string $node): ?array {
	if (!is_file('/etc/inc/fleet_accounts.inc')) {
		return null;
	}
	require_once('fleet_accounts.inc');
	$acc = fleet_users_backup_accounts($node);
	if ($acc === null) {
		return null;
	}
	$box = fleet_box_get($node);
	$st = json_decode((string)($box['status'] ?? ''), true) ?: array();
	$known = fleet_users_version_catalogs()[fleet_version_number((string)($st['version'] ?? ''))] ?? array_keys(fleet_users_catalog());
	try {
		$plan = fleet_accounts_plan(fleet_accounts_desired(fleet_users_desired_for($node)), $acc[0], $acc[1], $known);
	} catch (InvalidArgumentException $e) {
		return null;
	}
	$changes = array_filter(array_merge($plan['users'], $plan['groups']), function ($a) { return $a !== 'same'; });
	$ignored = (json_decode((string)fleet_setting('users_drift_ignored', '{}'), true) ?: array())[$node] ?? null;
	if (empty($changes) || ($ignored === hash('sha256', json_encode($changes)))) {
		return array();
	}
	return array('changes' => $changes, 'plan' => $plan);
}

function fleet_users_drift_ignore(string $node, string $who): void {
	$d = fleet_users_drift($node);
	if (empty($d)) {
		return;
	}
	$all = json_decode((string)fleet_setting('users_drift_ignored', '{}'), true) ?: array();
	$all[$node] = hash('sha256', json_encode($d['changes']));
	fleet_setting_set('users_drift_ignored', json_encode($all));
	fleet_audit($who, 'users', "{$node}: drift ignored until it changes");
}

/*
 * Adopt what a firewall changed locally: users changed there are taken
 * into Fleet as they are (name, keys, password hash, end date, disabled).
 * Removed accounts cannot be adopted (sync puts them back). Returns how
 * many users were adopted.
 */
function fleet_users_drift_adopt(string $node, string $who): int {
	$d = fleet_users_drift($node);
	$acc = fleet_users_backup_accounts($node);
	if (empty($d) || ($acc === null)) {
		return 0;
	}
	$byname = array();
	foreach ($acc[0] as $e) {
		if (is_array($e) && !empty($e['fleet'])) {
			$byname[strtolower((string)$e['name'])] = $e;
		}
	}
	$n = 0;
	foreach ($d['plan']['users'] as $name => $action) {
		$e = $byname[strtolower($name)] ?? null;
		if (($action !== 'update') || ($e === null)) {
			continue;
		}
		$u = fleet_users_from_entry($e);
		if (!preg_match('~^\$2[aby]\$\d\d\$~', $u['hash'])) {
			continue;
		}
		fleet_db()->prepare('UPDATE fusers SET fullname = ?, hash = ?, ssh_keys = ?, expires = ?, disabled = ?, updated = ? WHERE name = ? COLLATE NOCASE')
		    ->execute(array($u['fullname'], $u['hash'], $u['ssh_keys'], $u['expires'], $u['disabled'], time(), $name));
		$n++;
	}
	if ($n > 0) {
		$box = fleet_box_get($node);
		fleet_audit($who, 'users', sprintf('Adopted %d users as changed on %s; sync to give the other firewalls the same', $n, $box['label'] ?? $node));
	}
	return $n;
}

