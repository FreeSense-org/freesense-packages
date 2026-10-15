<?php
/*
 * fleet_replicas.inc
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
 * Copies of the fleet's backups on other firewalls, so the fleet survives
 * losing its controller.
 *
 * - Every backup is already sealed with the controller's master key; the
 *   copies are those files as they are, so a firewall that holds them
 *   cannot read them (System: /v1/management/vault, a quota per box).
 * - The recovery key (FRK-..., shown once) seals an envelope holding the
 *   master key. With the recovery key and any copy of the vault, a new
 *   controller gets everything back (Recover fleet).
 * - The self-backup is the controller itself: its database, its keys and
 *   its Fleet settings, sealed with the master key, taken every night.
 * - Peers (the copy targets, a setting) each hold every backup, the newest
 *   self-backup and the envelope. A sync after the nightly backup uploads
 *   what is missing and removes copies the clean-up removed.
 *
 * Vault ids: cfg.<node>.<backup id> (label: the backup's file),
 * ctl.self.<time>, ctl.recovery.
 *
 * Off-site: the same items go to storage targets set up in System >
 * Backup > Remote (S3, WebDAV, SFTP; System keeps the credentials), as
 * fleet-<id>.<sha12>.blob and .json, so they never mix with System's own
 * remote backups.
 */

require_once('fleet/fleet_store.inc');

define('FLEET_SELF_DIR', FLEET_DATA . '/self');
define('FLEET_RECOVERY_ENVELOPE', FLEET_DATA . '/recovery.env');
define('FLEET_CROCKFORD', '0123456789ABCDEFGHJKMNPQRSTVWXYZ');

/* ------------------------------------------------------------------ */
/* Pure: recovery key                                                  */
/* ------------------------------------------------------------------ */

/* pure: a new recovery key: FRK- and 32 Crockford base32 characters (160 bits) in groups of four. */
function fleet_recovery_key_new(?string $bytes = null): string {
	$bytes = $bytes ?? random_bytes(20);
	$bits = '';
	foreach (str_split($bytes) as $c) {
		$bits .= str_pad(decbin(ord($c)), 8, '0', STR_PAD_LEFT);
	}
	$out = '';
	foreach (str_split($bits, 5) as $chunk) {
		$out .= FLEET_CROCKFORD[bindec(str_pad($chunk, 5, '0'))];
	}
	return 'FRK-' . implode('-', str_split($out, 4));
}

/* pure: the 20 bytes behind a typed recovery key (spaces, dashes, case, O/0 and I/L/1 forgiven), or null. */
function fleet_recovery_key_bytes(string $typed): ?string {
	$s = strtoupper(preg_replace('/[\s-]+/', '', $typed));
	$s = preg_replace('/^FRK/', '', $s);
	$s = strtr($s, array('O' => '0', 'I' => '1', 'L' => '1'));
	if (!preg_match('/^[0-9A-HJKMNP-TV-Z]{32}$/', $s)) {
		return null;
	}
	$bits = '';
	foreach (str_split($s) as $c) {
		$bits .= str_pad(decbin(strpos(FLEET_CROCKFORD, $c)), 5, '0', STR_PAD_LEFT);
	}
	$bytes = '';
	foreach (str_split($bits, 8) as $b) {
		$bytes .= chr(bindec($b));
	}
	return $bytes;
}

/* pure: the key that seals the envelope, from the recovery key's bytes. */
function fleet_recovery_kek(string $bytes): string {
	return hash_hkdf('sha256', $bytes, 32, 'FreeSense-Fleet-Recovery-v1');
}

/* ------------------------------------------------------------------ */
/* Pure: what the copies should be                                     */
/* ------------------------------------------------------------------ */

/* pure: a vault id for a backup row. */
function fleet_replica_id(array $backup): string {
	return 'cfg.' . $backup['node_id'] . '.' . (int)$backup['id'];
}

/*
 * pure: id => array(sha256, kind, owner, created, label) for everything a
 * peer should hold. $self: the newest self-backup (id, sha256, created) or
 * null; $envelope_sha: the envelope's hash or null.
 */
function fleet_replica_wanted(array $backups, ?array $self, ?string $envelope_sha, int $now): array {
	$out = array();
	foreach ($backups as $b) {
		if ((string)($b['file_sha'] ?? '') === '') {
			continue;
		}
		$out[fleet_replica_id($b)] = array('sha256' => $b['file_sha'], 'kind' => 'config', 'owner' => $b['node_id'], 'created' => (int)$b['time'],
		    'label' => $b['file']);
	}
	if ($self !== null) {
		$out[$self['id']] = array('sha256' => $self['sha256'], 'kind' => 'controller', 'owner' => 'controller', 'created' => (int)$self['created'], 'label' => 'self-backup');
	}
	if ($envelope_sha !== null) {
		$out['ctl.recovery'] = array('sha256' => $envelope_sha, 'kind' => 'controller', 'owner' => 'controller', 'created' => $now, 'label' => 'recovery envelope');
	}
	return $out;
}

/*
 * pure: what to do on one peer. $held: id => sha256 now on the peer.
 * Only ids Fleet writes (cfg.*, ctl.*) are ever removed. Returns
 * array(ids to upload, ids to remove).
 */
function fleet_replica_plan(array $wanted, array $held): array {
	$put = array();
	foreach ($wanted as $id => $w) {
		if (!isset($held[$id]) || !hash_equals((string)$w['sha256'], (string)$held[$id])) {
			$put[] = $id;
		}
	}
	$del = array();
	foreach ($held as $id => $sha) {
		if (!isset($wanted[$id]) && preg_match('/^(cfg|ctl)\./', (string)$id)) {
			$del[] = (string)$id;
		}
	}
	return array($put, $del);
}

/* ------------------------------------------------------------------ */
/* Recovery key, envelope and self-backup                              */
/* ------------------------------------------------------------------ */

/* Make a new recovery key; the envelope is replaced, so only this key works for copies made from now on. Returns the key (shown once). */
function fleet_recovery_create(string $who): string {
	$key = fleet_recovery_key_new();
	$env = fleet_seal(fleet_master_key(), fleet_recovery_kek(fleet_recovery_key_bytes($key)));
	$tmp = FLEET_RECOVERY_ENVELOPE . '.tmp';
	if ((@file_put_contents($tmp, $env) === false) || !@chmod($tmp, 0600) || !@rename($tmp, FLEET_RECOVERY_ENVELOPE)) {
		throw new RuntimeException('The recovery envelope could not be written.');
	}
	fleet_setting_set('recovery_created', (string)time());
	fleet_setting_set('recovery_by', $who);
	fleet_audit($who, 'recovery_key', 'A new recovery key was made; earlier recovery keys stop working once the copies are synced');
	return $key;
}

function fleet_recovery_ready(): bool {
	return is_file(FLEET_RECOVERY_ENVELOPE);
}

/* The controller's own state as one sealed file: database, keys and settings. Returns array(id, sha256 of the file, created). */
function fleet_self_backup(): array {
	if (!is_dir(FLEET_SELF_DIR) && !@mkdir(FLEET_SELF_DIR, 0700, true)) {
		throw new RuntimeException('The self-backup directory could not be created.');
	}
	$snap = FLEET_SELF_DIR . '/snapshot.db';
	@unlink($snap);
	/* A consistent copy while the poll keeps writing. */
	fleet_db()->exec('VACUUM INTO ' . fleet_db()->quote($snap));
	$bundle = array('format' => 'freesense-fleet-self-v1', 'created' => time(), 'schema' => FLEET_DB_SCHEMA,
	    'db' => base64_encode((string)file_get_contents($snap)),
	    'keys' => array('wg.key' => base64_encode(is_file(FLEET_DATA . '/wg.key') ? (string)file_get_contents(FLEET_DATA . '/wg.key') : ''), 'signing.pem' => fleet_signing_pem(),
	    'tls.pem' => fleet_tls_pem()),
	    'settings' => function_exists('config_get_path') ? (array)config_get_path('installedpackages/fleet/config/0', array()) : array());
	@unlink($snap);
	$sealed = fleet_seal(gzencode(json_encode($bundle), 6), fleet_master_key());
	$created = (int)$bundle['created'];
	$file = FLEET_SELF_DIR . "/self-{$created}.enc";
	if (@file_put_contents($file, $sealed) === false) {
		throw new RuntimeException('The self-backup could not be written. Check the free space on the controller.');
	}
	@chmod($file, 0600);
	/* Keep the newest three. */
	$all = glob(FLEET_SELF_DIR . '/self-*.enc') ?: array();
	rsort($all);
	foreach (array_slice($all, 3) as $old) {
		@unlink($old);
	}
	return array('ctl.self.' . $created, hash('sha256', $sealed), $created);
}

/* The newest self-backup: array(id, sha256, created, path) or null. */
function fleet_self_latest(): ?array {
	$all = glob(FLEET_SELF_DIR . '/self-*.enc') ?: array();
	if (empty($all)) {
		return null;
	}
	rsort($all);
	$created = (int)preg_replace('/\D/', '', basename($all[0]));
	return array('id' => 'ctl.self.' . $created, 'sha256' => hash_file('sha256', $all[0]), 'created' => $created, 'path' => $all[0]);
}

/* ------------------------------------------------------------------ */
/* Peers and sync                                                      */
/* ------------------------------------------------------------------ */

/* The copy targets (["all"], groups and firewalls); empty: copies are off. */
function fleet_replica_targets(): array {
	$t = json_decode((string)fleet_setting('replica_targets', '[]'), true);
	return is_array($t) ? $t : array();
}

function fleet_replica_targets_set(array $targets, string $who): void {
	$targets = empty($targets) ? array() : fleet_targets_from($targets);
	fleet_setting_set('replica_targets', json_encode($targets));
	fleet_audit($who, 'replicas', empty($targets) ? 'Copies on other firewalls turned off' :
	    'Copies on ' . fleet_targets_text($targets, fleet_target_names()));
}

/* The firewalls that hold copies: managed ones among the targets (monitor-only boxes refuse vault writes). */
function fleet_replica_peers(): array {
	$targets = fleet_replica_targets();
	if (empty($targets)) {
		return array();
	}
	list($boxes) = fleet_targets_now($targets);
	return array_values(array_filter($boxes, function ($b) { return $b['role'] === 'managed'; }));
}

/* Everything a peer should hold right now. */
function fleet_replica_wanted_now(): array {
	$rows = fleet_db()->query('SELECT id, node_id, time, file FROM backups ORDER BY id')->fetchAll();
	foreach ($rows as &$r) {
		$path = FLEET_BACKUP_DIR . '/' . $r['file'];
		$r['file_sha'] = is_file($path) ? hash_file('sha256', $path) : '';
	}
	unset($r);
	$self = fleet_self_latest();
	$env = fleet_recovery_ready() ? hash_file('sha256', FLEET_RECOVERY_ENVELOPE) : null;
	return fleet_replica_wanted($rows, $self, $env, time());
}

/* The bytes of one wanted copy. */
function fleet_replica_bytes(string $id, array $w): string {
	if ($id === 'ctl.recovery') {
		return (string)file_get_contents(FLEET_RECOVERY_ENVELOPE);
	}
	if (strncmp($id, 'ctl.self.', 9) === 0) {
		return (string)file_get_contents(FLEET_SELF_DIR . '/self-' . substr($id, 9) . '.enc');
	}
	return (string)file_get_contents(FLEET_BACKUP_DIR . '/' . $w['label']);
}

/* Bring one peer's copies up to date. Returns array(uploaded, removed, held after, used bytes, quota bytes). */
function fleet_replica_sync_peer(array $box, array $wanted): array {
	list($code, $json) = fleet_box_call($box, 'GET', '/api/v1/management/vault');
	if ($code !== 200) {
		throw new RuntimeException('The firewall did not list its copies: ' . fleet_box_error($code, $json));
	}
	$held = array_column((array)($json['data'] ?? array()), 'sha256', 'id');
	list($put, $del) = fleet_replica_plan($wanted, $held);
	foreach ($del as $id) {
		fleet_box_call($box, 'DELETE', '/api/v1/management/vault/' . rawurlencode($id));
	}
	foreach ($put as $id) {
		$bytes = fleet_replica_bytes($id, $wanted[$id]);
		list($code, $json) = fleet_box_call($box, 'PUT', '/api/v1/management/vault/' . rawurlencode($id), array('data' => base64_encode($bytes),
		    'sha256' => hash('sha256', $bytes), 'owner' => $wanted[$id]['owner'], 'kind' => $wanted[$id]['kind'], 'created' => $wanted[$id]['created'],
		    'label' => $wanted[$id]['label']));
		if ($code === 507) {
			throw new RuntimeException('FLEET-E803: The firewall\'s backup space is full (' . fleet_box_error($code, $json) . '). Raise its share or choose fewer copies.');
		}
		if (($code !== 200) && ($code !== 201)) {
			throw new RuntimeException('A copy was refused: ' . fleet_box_error($code, $json));
		}
	}
	list($code, $json) = fleet_box_call($box, 'GET', '/api/v1/management/vault');
	$meta = (array)($json['meta'] ?? array());
	/* Count only this fleet's copies that are still wanted (a box may hold other things). */
	$ours = count(array_intersect(array_column((array)($json['data'] ?? array()), 'id'), array_keys($wanted)));
	return array(count($put), count($del), $ours, (int)($meta['used_bytes'] ?? 0), (int)($meta['quota_bytes'] ?? 0));
}

/*
 * Sync every peer as a group operation (one task per peer). Takes a
 * self-backup first. Peers that are offline wait for the next sync.
 */
function fleet_replica_sync(string $who): ?int {
	$peers = fleet_replica_peers();
	if (empty($peers) && empty(fleet_offsite_ids())) {
		return null;
	}
	fleet_self_backup();
	$wanted = fleet_replica_wanted_now();
	fleet_offsite_sync($wanted, $who);
	if (empty($peers)) {
		return null;
	}
	$op = fleet_op_group_start('replica_sync', 'Sync backup copies', $who);
	$tasks = array();
	foreach ($peers as $p) {
		$tasks[$p['node_id']] = fleet_op_start($p['node_id'], 'replica', 'Waiting', $who, $op, 'queued');
	}
	foreach ($peers as $p) {
		$t = $tasks[$p['node_id']];
		if ($p['state'] === 'offline') {
			fleet_op_set($t, 'skipped', 'Skipped: offline. The next sync catches up.');
			fleet_replica_status_save($p['node_id'], null, 'Offline at the last sync');
			continue;
		}
		fleet_op_set($t, 'running', 'Copying', 30);
		try {
			$r = fleet_replica_sync_peer($p, $wanted);
			fleet_op_set($t, 'done', sprintf('%d copies, %d added, %d removed', $r[2], $r[0], $r[1]), 100);
			fleet_replica_status_save($p['node_id'], $r, null);
		} catch (RuntimeException $e) {
			fleet_op_set($t, 'failed', $e->getMessage(), 100);
			fleet_replica_status_save($p['node_id'], null, $e->getMessage());
		}
		fleet_op_group_update($op);
	}
	fleet_op_group_update($op);
	fleet_audit($who, 'replicas', sprintf('Copies synced to %d firewalls (%d items each)', count($peers), count($wanted)));
	return $op;
}

function fleet_replica_status_save(string $node, ?array $r, ?string $error): void {
	$all = json_decode((string)fleet_setting('replica_status', '{}'), true) ?: array();
	$prev = $all[$node] ?? array();
	$all[$node] = array('time' => time(), 'error' => $error,
	    'held' => ($r === null) ? ($prev['held'] ?? null) : $r[2], 'used' => ($r === null) ? ($prev['used'] ?? null) : $r[3],
	    'quota' => ($r === null) ? ($prev['quota'] ?? null) : $r[4], 'synced' => ($r === null) ? ($prev['synced'] ?? null) : time());
	fleet_setting_set('replica_status', json_encode($all));
}

function fleet_replica_status(): array {
	return json_decode((string)fleet_setting('replica_status', '{}'), true) ?: array();
}

/* ------------------------------------------------------------------ */
/* Archives (.fsfa) and Recover fleet                                  */
/* ------------------------------------------------------------------ */

/* Write everything a peer would hold as a .fsfa archive (the same layout as a firewall's vault download). Returns the file. */
function fleet_archive_export(): string {
	fleet_self_backup();
	$wanted = fleet_replica_wanted_now();
	$dir = FLEET_DATA . '/export-' . bin2hex(random_bytes(4));
	@mkdir($dir, 0700);
	foreach ($wanted as $id => $w) {
		$bytes = fleet_replica_bytes($id, $w);
		file_put_contents("{$dir}/{$id}.blob", $bytes);
		file_put_contents("{$dir}/{$id}.json", json_encode(array('sha256' => hash('sha256', $bytes), 'size' => strlen($bytes), 'owner' => $w['owner'],
		    'kind' => $w['kind'], 'created' => $w['created'], 'label' => $w['label'], 'stored' => time())));
	}
	$out = FLEET_DATA . '/fleet-export.fsfa';
	list($rc) = fleet_ctl_exec(array('/usr/bin/tar', '-czf', $out, '-C', $dir, '.'));
	array_map('unlink', glob("{$dir}/*") ?: array());
	@rmdir($dir);
	if ($rc !== 0) {
		throw new RuntimeException('The archive could not be written.');
	}
	return $out;
}

/*
 * Open an unpacked archive (a directory of <id>.blob and <id>.json) with a
 * recovery key. Returns what Recover fleet would restore:
 * array(master key, self bundle, backups: label => sealed bytes), or
 * throws with what is wrong. Nothing is written.
 */
function fleet_recover_open(string $dir, string $typed_key): array {
	$kb = fleet_recovery_key_bytes($typed_key);
	if ($kb === null) {
		throw new InvalidArgumentException('That is not a recovery key. It looks like FRK-XXXX-XXXX-... with 32 letters and digits.');
	}
	$read = function (string $id) use ($dir) {
		$blob = @file_get_contents("{$dir}/{$id}.blob");
		$meta = json_decode((string)@file_get_contents("{$dir}/{$id}.json"), true);
		if (($blob === false) || !is_array($meta) || !hash_equals((string)($meta['sha256'] ?? ''), hash('sha256', $blob))) {
			return null;
		}
		return array($blob, $meta);
	};
	$env = $read('ctl.recovery');
	if ($env === null) {
		throw new RuntimeException('FLEET-E805: The archive has no recovery envelope. Use a copy made after the recovery key was created.');
	}
	$master = fleet_unseal($env[0], fleet_recovery_kek($kb));
	if (($master === null) || (strlen($master) !== 32)) {
		throw new InvalidArgumentException('FLEET-E805: The recovery key does not open this archive. Check it, or use the key that was current when the copy was made.');
	}
	$selfs = array_map(function ($f) { return basename($f, '.blob'); }, glob("{$dir}/ctl.self.*.blob") ?: array());
	rsort($selfs, SORT_NATURAL);
	$bundle = null;
	foreach ($selfs as $id) {
		$s = $read($id);
		$plain = ($s === null) ? null : fleet_unseal($s[0], $master);
		$b = ($plain === null) ? null : json_decode((string)@gzdecode($plain), true);
		if (is_array($b) && (($b['format'] ?? '') === 'freesense-fleet-self-v1')) {
			$bundle = $b;
			break;
		}
	}
	if ($bundle === null) {
		throw new RuntimeException('FLEET-E805: The archive has no readable self-backup of the controller.');
	}
	$backups = array();
	foreach (glob("{$dir}/cfg.*.blob") ?: array() as $f) {
		$c = $read(basename($f, '.blob'));
		if (($c !== null) && preg_match('#^[A-Za-z0-9._/-]+$#', (string)$c[1]['label']) && (strpos((string)$c[1]['label'], '..') === false)) {
			$backups[(string)$c[1]['label']] = $c[0];
		}
	}
	return array($master, $bundle, $backups);
}

/* A short description of what an opened archive holds, for the preview. */
function fleet_recover_summary(array $opened): array {
	list(, $bundle, $backups) = $opened;
	$tmp = tempnam(sys_get_temp_dir(), 'fleet-db');
	file_put_contents($tmp, base64_decode($bundle['db']));
	$db = new PDO('sqlite:' . $tmp);
	$boxes = (int)$db->query('SELECT COUNT(*) FROM boxes')->fetchColumn();
	$rows = (int)$db->query('SELECT COUNT(*) FROM backups')->fetchColumn();
	$db = null;
	@unlink($tmp);
	return array('created' => (int)$bundle['created'], 'schema' => (int)$bundle['schema'], 'boxes' => $boxes, 'backup_rows' => $rows,
	    'backup_files' => count($backups));
}

/*
 * Restore the controller from an opened archive: master key, keys,
 * database and backup files. Refuses when this controller already has
 * firewalls, unless $replace. The Fleet settings are returned for the
 * caller to save (config.xml is the caller's business).
 */
function fleet_recover_apply(array $opened, bool $replace, string $who): array {
	list($master, $bundle, $backups) = $opened;
	if (!$replace && is_file(FLEET_DATA . '/fleet.db') && ((int)fleet_db()->query('SELECT COUNT(*) FROM boxes')->fetchColumn() > 0)) {
		throw new RuntimeException('This controller already has firewalls. Recovering replaces them; confirm that you want to replace this controller.');
	}
	if ((int)$bundle['schema'] > FLEET_DB_SCHEMA) {
		throw new RuntimeException('FLEET-E805: The copy comes from a newer Fleet. Update this controller first.');
	}
	$write = function (string $name, string $bytes) {
		$path = FLEET_DATA . '/' . $name;
		if (!is_dir(dirname($path))) {
			@mkdir(dirname($path), 0700, true);
		}
		if ((@file_put_contents("{$path}.tmp", $bytes) === false) || !@chmod("{$path}.tmp", 0600) || !@rename("{$path}.tmp", $path)) {
			throw new RuntimeException("{$path} could not be written.");
		}
	};
	$write('master.key', $master);
	if ((string)$bundle['keys']['wg.key'] !== '') {
		$write('wg.key', (string)base64_decode($bundle['keys']['wg.key']));
	}
	$write('signing.pem', (string)$bundle['keys']['signing.pem']);
	$write('tls.pem', (string)$bundle['keys']['tls.pem']);
	foreach (glob(FLEET_DATA . '/fleet.db*') ?: array() as $f) {
		@unlink($f);
	}
	$write('fleet.db', (string)base64_decode($bundle['db']));
	foreach ($backups as $label => $bytes) {
		$write('backups/' . $label, $bytes);
	}
	fleet_db(true);
	fleet_audit($who, 'recover', sprintf('Fleet recovered from copies of %s: %d backup files', date('Y-m-d H:i', (int)$bundle['created']), count($backups)));
	return (array)$bundle['settings'];
}

/* ------------------------------------------------------------------ */
/* Off-site copies                                                     */
/* ------------------------------------------------------------------ */

/* pure: off-site file names for one item. */
function fleet_offsite_names(string $id, string $sha256): array {
	$base = 'fleet-' . $id . '.' . substr($sha256, 0, 12);
	return array($base . '.blob', $base . '.json');
}

/* pure: id => sha12 for the items in a remote listing (only complete pairs Fleet wrote). */
function fleet_offsite_held(array $names): array {
	$set = array_flip($names);
	$held = array();
	foreach ($names as $n) {
		if (preg_match('/^fleet-((?:cfg|ctl)\.[A-Za-z0-9._-]+)\.([0-9a-f]{12})\.blob$/D', $n, $m) && isset($set['fleet-' . $m[1] . '.' . $m[2] . '.json'])) {
			$held[$m[1]] = $m[2];
		}
	}
	return $held;
}

function fleet_offsite_available(): bool {
	if (!is_file('/etc/inc/remote_backup.inc')) {
		return false;
	}
	require_once('remote_backup.inc');
	return function_exists('remote_backup_driver');
}

/* The storage targets chosen for off-site copies (ids of System's remote backup targets). */
function fleet_offsite_ids(): array {
	$ids = json_decode((string)fleet_setting('offsite_targets', '[]'), true);
	return is_array($ids) ? array_values(array_filter($ids, 'is_string')) : array();
}

function fleet_offsite_ids_set(array $ids, string $who): void {
	$known = fleet_offsite_available() ? array_column(remote_backup_targets(), 'id') : array();
	$ids = array_values(array_intersect(array_map('strval', $ids), $known));
	fleet_setting_set('offsite_targets', json_encode($ids));
	fleet_audit($who, 'replicas', empty($ids) ? 'Off-site copies turned off' : sprintf('Off-site copies to %d storage targets', count($ids)));
}

/* Bring one storage target up to date. Returns array(uploaded, removed, held after). */
function fleet_offsite_sync_target(array $t, array $wanted): array {
	$names = remote_backup_driver($t, 'list');
	if (!is_array($names)) {
		throw new RuntimeException('FLEET-E807: The storage could not be listed: ' . $names);
	}
	$held = fleet_offsite_held($names);
	$want12 = array_map(function ($w) { return array('sha256' => substr($w['sha256'], 0, 12)) + $w; }, $wanted);
	list($put, $del) = fleet_replica_plan($want12, $held);
	foreach ($put as $id) {
		$bytes = fleet_replica_bytes($id, $wanted[$id]);
		list($blob, $meta) = fleet_offsite_names($id, $wanted[$id]['sha256']);
		$json = json_encode(array('sha256' => hash('sha256', $bytes), 'size' => strlen($bytes), 'owner' => $wanted[$id]['owner'], 'kind' => $wanted[$id]['kind'],
		    'created' => $wanted[$id]['created'], 'label' => $wanted[$id]['label'], 'stored' => time()));
		foreach (array($blob => $bytes, $meta => $json) as $name => $data) {
			$r = remote_backup_driver($t, 'put', $name, $data);
			if ($r !== true) {
				throw new RuntimeException('FLEET-E807: An upload failed: ' . $r);
			}
		}
	}
	foreach ($del as $id) {
		foreach (fleet_offsite_names($id, str_pad($held[$id], 64, '0')) as $name) {
			remote_backup_driver($t, 'delete', $name);
		}
	}
	return array(count($put), count($del), count($held) - count($del) + count($put));
}

/* Sync every chosen storage target; results kept per target. */
function fleet_offsite_sync(array $wanted, string $who): void {
	$ids = fleet_offsite_ids();
	if (empty($ids) || !fleet_offsite_available()) {
		return;
	}
	$status = json_decode((string)fleet_setting('offsite_status', '{}'), true) ?: array();
	foreach ($ids as $id) {
		list(, $t) = remote_backup_find_target($id);
		if ($t === null) {
			$status[$id] = array('time' => time(), 'error' => 'The storage target was removed in System > Backup > Remote.') + ($status[$id] ?? array());
			continue;
		}
		try {
			$r = fleet_offsite_sync_target($t, $wanted);
			$status[$id] = array('time' => time(), 'synced' => time(), 'held' => $r[2], 'error' => null);
		} catch (RuntimeException $e) {
			$status[$id] = array('time' => time(), 'error' => $e->getMessage()) + ($status[$id] ?? array());
			fleet_audit($who, 'replicas', ($t['descr'] ?: $id) . ': ' . $e->getMessage());
		}
	}
	fleet_setting_set('offsite_status', json_encode($status));
}

function fleet_offsite_status(): array {
	return json_decode((string)fleet_setting('offsite_status', '{}'), true) ?: array();
}

/* Fetch Fleet's items from a storage target into a directory laid out like a vault (for Recover fleet). Returns how many items. */
function fleet_offsite_fetch(string $target_id, string $dir): int {
	if (!fleet_offsite_available()) {
		throw new RuntimeException('This firewall has no remote backup storage support.');
	}
	list(, $t) = remote_backup_find_target($target_id);
	if ($t === null) {
		throw new RuntimeException('Set up the storage in System > Backup > Remote first (the same bucket or server as before).');
	}
	$names = remote_backup_driver($t, 'list');
	if (!is_array($names)) {
		throw new RuntimeException('FLEET-E807: The storage could not be listed: ' . $names);
	}
	$n = 0;
	foreach (fleet_offsite_held($names) as $id => $sha12) {
		foreach (array('blob', 'json') as $ext) {
			$data = remote_backup_driver($t, 'get', 'fleet-' . $id . '.' . $sha12 . '.' . $ext);
			if (is_array($data)) {
				throw new RuntimeException('FLEET-E807: A download failed: ' . ($data['error'] ?? '?'));
			}
			file_put_contents("{$dir}/{$id}.{$ext}", $data);
		}
		$n++;
	}
	return $n;
}

