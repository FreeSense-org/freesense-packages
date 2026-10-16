<?php
/*
 * fleet_store.inc
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
 * FreeSense Fleet controller storage.
 *
 * Everything lives in the data directory /fleet, never in config.xml (which is
 * rewritten on every save, copied into every revision and pushed over HA
 * sync). On ZFS /fleet is its own dataset FreeSense/fleet, outside the boot
 * environment, so rolling back the controller's own update never rolls back
 * the fleet's state. On UFS it is a plain directory. /var is avoided: it can
 * be a RAM disk.
 *
 *   /fleet/fleet.db      SQLite (WAL): settings, invitations, enrollments, boxes, audit
 *   /fleet/master.key    32 random bytes; encrypts the secrets kept in the database
 *   /fleet/wg.key        the controller's WireGuard private key
 *   /fleet/signing.pem   the key that signs policy bundles (ECDSA P-256)
 *   /fleet/tls.pem       the enrollment endpoint's certificate and key (pinned by join links)
 *
 * Functions marked "pure" touch neither the system nor the database.
 */

define('FLEET_DATA', getenv('FLEET_DATA') ?: '/fleet');
define('FLEET_DB_SCHEMA', 27);

/* ------------------------------------------------------------------ */
/* Pure: secrets                                                       */
/* ------------------------------------------------------------------ */

/* pure: encrypt a secret for the database (AES-256-GCM, base64 "v1:nonce:tag:data"). */
function fleet_seal(string $plain, string $master): string {
	$nonce = random_bytes(12);
	$tag = '';
	$data = openssl_encrypt($plain, 'aes-256-gcm', $master, OPENSSL_RAW_DATA, $nonce, $tag, 'FreeSense-Fleet-Store-v1');
	return 'v1:' . base64_encode($nonce) . ':' . base64_encode($tag) . ':' . base64_encode((string)$data);
}

/* pure: decrypt fleet_seal() output, or null. */
function fleet_unseal(string $sealed, string $master): ?string {
	$p = explode(':', $sealed);
	if ((count($p) !== 4) || ($p[0] !== 'v1')) {
		return null;
	}
	$plain = openssl_decrypt((string)base64_decode($p[3]), 'aes-256-gcm', $master, OPENSSL_RAW_DATA, (string)base64_decode($p[1]),
	    (string)base64_decode($p[2]), 'FreeSense-Fleet-Store-v1');
	return ($plain === false) ? null : $plain;
}

/* pure: a random ULA /64 for the management overlay (RFC 4193: fd + 40 random bits + subnet f1). */
function fleet_random_overlay(): string {
	$g = bin2hex(random_bytes(5));
	return sprintf('fd%s:%s:%s:f1::/64', substr($g, 0, 2), substr($g, 2, 4), substr($g, 6, 4));
}

/* pure: the address of host number $n (1 = the controller) in a /64 overlay prefix. */
function fleet_overlay_host(string $prefix, int $n): string {
	$base = explode('/', $prefix)[0];
	return inet_ntop(substr(inet_pton($base), 0, 8) . pack('J', $n));
}

/* ------------------------------------------------------------------ */
/* Data directory and keys                                             */
/* ------------------------------------------------------------------ */

/*
 * Create the data directory: a ZFS dataset when the system runs on ZFS,
 * otherwise a directory. Returns an error text or null.
 */
function fleet_data_prepare(): ?string {
	if (!is_dir(FLEET_DATA)) {
		$pool = '';
		exec('/sbin/zfs list -H -o name / 2>/dev/null', $out, $rc);
		if (($rc === 0) && preg_match('#^([A-Za-z0-9_.:-]+)/#', (string)($out[0] ?? ''), $m)) {
			$pool = $m[1];
		}
		if ($pool !== '') {
			exec('/sbin/zfs create -o mountpoint=' . escapeshellarg(FLEET_DATA) . ' -o canmount=on ' .
			    escapeshellarg("{$pool}/fleet") . ' 2>&1', $zout, $zrc);
		}
		if (!is_dir(FLEET_DATA) && !@mkdir(FLEET_DATA, 0700, true)) {
			return 'The Fleet data directory ' . FLEET_DATA . ' could not be created.';
		}
	}
	@chmod(FLEET_DATA, 0700);
	return null;
}

/* True when the data directory is on ZFS (the controller then has rollback protection). */
function fleet_data_on_zfs(): bool {
	exec('/sbin/zfs list -H -o name ' . escapeshellarg(FLEET_DATA) . ' 2>/dev/null', $out, $rc);
	return $rc === 0;
}

/* Write a private file once; returns its content. */
function fleet_secret_file(string $name, callable $make): string {
	$path = FLEET_DATA . "/{$name}";
	if (!is_file($path)) {
		$tmp = "{$path}.tmp" . getmypid();
		if ((@file_put_contents($tmp, $make()) === false) || !@chmod($tmp, 0600) || !@rename($tmp, $path)) {
			@unlink($tmp);
			throw new RuntimeException("{$path} could not be written.");
		}
	}
	return (string)file_get_contents($path);
}

function fleet_master_key(): string {
	return fleet_secret_file('master.key', function () { return random_bytes(32); });
}

function fleet_signing_pem(): string {
	return fleet_secret_file('signing.pem', function () {
		$k = openssl_pkey_new(array('private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1'));
		openssl_pkey_export($k, $pem);
		return $pem;
	});
}

function fleet_signing_public(): string {
	return (string)openssl_pkey_get_details(openssl_pkey_get_private(fleet_signing_pem()))['key'];
}

/* The enrollment endpoint's certificate (self-signed ECDSA, 10 years): its fingerprint goes in every join link. */
function fleet_tls_pem(): string {
	return fleet_secret_file('tls.pem', function () {
		$k = openssl_pkey_new(array('private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1'));
		$csr = openssl_csr_new(array('commonName' => 'FreeSense Fleet controller', 'organizationName' => 'FreeSense Fleet'), $k,
		    array('digest_alg' => 'sha256'));
		openssl_x509_export(openssl_csr_sign($csr, null, $k, 3650, array('digest_alg' => 'sha256'), random_int(1, PHP_INT_MAX)), $crt);
		openssl_pkey_export($k, $kpem);
		return $crt . $kpem;
	});
}

/* ------------------------------------------------------------------ */
/* Database                                                            */
/* ------------------------------------------------------------------ */

/* The database; $reopen after the file was replaced (Recover fleet). */
function fleet_db(bool $reopen = false): PDO {
	static $db = null;
	if ($reopen) {
		$db = null;
	}
	if ($db === null) {
		$db = new PDO('sqlite:' . FLEET_DATA . '/fleet.db', null, null, array(PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
		    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC));
		$db->exec('PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;');
		@chmod(FLEET_DATA . '/fleet.db', 0600);
		fleet_db_migrate($db);
	}
	return $db;
}

/* Create or upgrade the schema; safe to run again. */
function fleet_db_migrate(PDO $db): void {
	$version = (int)$db->query('PRAGMA user_version')->fetchColumn();
	if ($version >= FLEET_DB_SCHEMA) {
		return;
	}
	$db->exec('BEGIN IMMEDIATE');
	if ($version < 1) {
		$db->exec(<<<'SQL'
CREATE TABLE IF NOT EXISTS settings (name TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS invitations (
	token_id TEXT PRIMARY KEY, secret_hash TEXT NOT NULL, okm TEXT NOT NULL, role TEXT NOT NULL, label TEXT NOT NULL,
	created INTEGER NOT NULL, expires INTEGER NOT NULL, state TEXT NOT NULL DEFAULT 'open', failures INTEGER NOT NULL DEFAULT 0,
	challenge TEXT, challenge_time INTEGER, created_by TEXT NOT NULL DEFAULT '');
CREATE TABLE IF NOT EXISTS enrollments (
	id TEXT PRIMARY KEY, token_id TEXT NOT NULL REFERENCES invitations(token_id), node_wg_pub TEXT NOT NULL, inventory TEXT NOT NULL,
	code TEXT NOT NULL, state TEXT NOT NULL DEFAULT 'pending', created INTEGER NOT NULL, decided_by TEXT, decided INTEGER, source_ip TEXT);
CREATE TABLE IF NOT EXISTS boxes (
	node_id TEXT PRIMARY KEY, name TEXT NOT NULL, label TEXT NOT NULL, host_no INTEGER NOT NULL UNIQUE, overlay TEXT NOT NULL,
	wg_pub TEXT NOT NULL UNIQUE, api_key TEXT NOT NULL, cert_sha256 TEXT NOT NULL, role TEXT NOT NULL, joined INTEGER NOT NULL,
	last_seen INTEGER, state TEXT NOT NULL DEFAULT 'new', misses INTEGER NOT NULL DEFAULT 0, status TEXT, error TEXT);
CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY AUTOINCREMENT, time INTEGER NOT NULL, who TEXT NOT NULL, action TEXT NOT NULL, detail TEXT NOT NULL);
PRAGMA user_version = 1;
SQL);
	}
	if ($version < 2) {
		/* Central configuration backups: the files are encrypted under backups/; this is the index. */
		$db->exec(<<<'SQL'
CREATE TABLE IF NOT EXISTS backups (
	id INTEGER PRIMARY KEY AUTOINCREMENT, node_id TEXT NOT NULL, time INTEGER NOT NULL, reason TEXT NOT NULL, who TEXT NOT NULL,
	sha256 TEXT NOT NULL, size INTEGER NOT NULL, file TEXT NOT NULL, config_time INTEGER, description TEXT, version TEXT);
CREATE INDEX IF NOT EXISTS backups_node_time ON backups (node_id, time);
PRAGMA user_version = 2;
SQL);
	}
	if ($version < 3) {
		/* Groups of firewalls (many-to-many). */
		$db->exec(<<<'SQL'
CREATE TABLE IF NOT EXISTS fleet_groups (
	id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE COLLATE NOCASE, description TEXT NOT NULL DEFAULT '',
	color TEXT NOT NULL DEFAULT '1', created INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS box_groups (node_id TEXT NOT NULL, group_id INTEGER NOT NULL REFERENCES fleet_groups(id), PRIMARY KEY (node_id, group_id));
PRAGMA user_version = 3;
SQL);
	}
	if ($version < 4) {
		/* Operations on firewalls (a reboot, a backup) and their current step. */
		$db->exec(<<<'SQL'
CREATE TABLE IF NOT EXISTS ops (
	id INTEGER PRIMARY KEY AUTOINCREMENT, node_id TEXT NOT NULL, kind TEXT NOT NULL, state TEXT NOT NULL, text TEXT NOT NULL,
	who TEXT NOT NULL, started INTEGER NOT NULL, updated INTEGER NOT NULL, finished INTEGER);
CREATE INDEX IF NOT EXISTS ops_node ON ops (node_id, state);
PRAGMA user_version = 4;
SQL);
	}
	if ($version < 5) {
		/* Group operations: one parent ("Back up 12 firewalls") with a task per firewall. */
		$db->exec(<<<'SQL'
ALTER TABLE ops ADD COLUMN parent INTEGER;
ALTER TABLE ops ADD COLUMN title TEXT NOT NULL DEFAULT '';
CREATE INDEX IF NOT EXISTS ops_parent ON ops (parent);
PRAGMA user_version = 5;
SQL);
	}
	if ($version < 6) {
		/* How far an operation is, 0-100, or NULL when it cannot know (the bar then slides). */
		$db->exec(<<<'SQL'
ALTER TABLE ops ADD COLUMN progress INTEGER;
PRAGMA user_version = 6;
SQL);
	}
	if ($version < 7) {
		/* Updates: an operation's own data (from, to, when the new version answered); each box's last update check. */
		$db->exec(<<<'SQL'
ALTER TABLE ops ADD COLUMN data TEXT;
ALTER TABLE boxes ADD COLUMN update_info TEXT;
PRAGMA user_version = 7;
SQL);
	}
	if ($version < 8) {
		/* Maintenance windows (a group may have one) and rollouts (rings of groups, one group operation each). */
		$db->exec(<<<'SQL'
CREATE TABLE IF NOT EXISTS windows (
	id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE COLLATE NOCASE, days TEXT NOT NULL, start INTEGER NOT NULL, length INTEGER NOT NULL);
ALTER TABLE fleet_groups ADD COLUMN window_id INTEGER;
CREATE TABLE IF NOT EXISTS rollouts (
	id INTEGER PRIMARY KEY AUTOINCREMENT, op_id INTEGER NOT NULL, target TEXT NOT NULL, rings TEXT NOT NULL, ring_done TEXT NOT NULL DEFAULT '{}',
	acked TEXT NOT NULL DEFAULT '[]', state TEXT NOT NULL, gap INTEGER NOT NULL, who TEXT NOT NULL, created INTEGER NOT NULL);
PRAGMA user_version = 8;
SQL);
	}
	if ($version < 9) {
		/* Schedules: recurring jobs on a group (group_id 0: every firewall). */
		$db->exec(<<<'SQL'
CREATE TABLE IF NOT EXISTS schedules (
	id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, kind TEXT NOT NULL, group_id INTEGER NOT NULL DEFAULT 0, days TEXT NOT NULL,
	time INTEGER NOT NULL, enabled INTEGER NOT NULL DEFAULT 1, last_run INTEGER NOT NULL DEFAULT 0, last_op INTEGER, last_result TEXT,
	who TEXT NOT NULL, created INTEGER NOT NULL);
PRAGMA user_version = 9;
SQL);
	}
	if ($version < 10) {
		/* A schedule can target one firewall instead of a group. */
		$db->exec(<<<'SQL'
ALTER TABLE schedules ADD COLUMN node_id TEXT;
PRAGMA user_version = 10;
SQL);
	}
	if ($version < 11) {
		/* Several targets per schedule: ["all"] or any of "g:<group>" and "n:<node>". */
		$db->exec(<<<'SQL'
ALTER TABLE schedules ADD COLUMN targets TEXT;
-- when the last result happened (last_run also moves when a schedule is changed)
ALTER TABLE schedules ADD COLUMN ran_at INTEGER;
UPDATE schedules SET ran_at = last_run WHERE last_result IS NOT NULL;
UPDATE schedules SET targets = CASE WHEN node_id IS NOT NULL THEN json_array('n:' || node_id)
    WHEN group_id > 0 THEN json_array('g:' || group_id) ELSE json_array('all') END;
PRAGMA user_version = 11;
SQL);
	}
	if ($version < 12) {
		/* Backup sets (which firewalls keep how many backups) and pinned backups. */
		$db->exec(<<<'SQL'
CREATE TABLE IF NOT EXISTS backup_sets (
	id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE COLLATE NOCASE, targets TEXT NOT NULL,
	keep_last INTEGER NOT NULL, keep_daily INTEGER NOT NULL, keep_weekly INTEGER NOT NULL, keep_monthly INTEGER NOT NULL, created INTEGER NOT NULL);
ALTER TABLE backups ADD COLUMN pinned INTEGER NOT NULL DEFAULT 0;
PRAGMA user_version = 12;
SQL);
	}
	if ($version < 13) {
		/* Policies, exceptions, and the last compliance check of every firewall and rule. */
		$db->exec(<<<'SQL'
CREATE TABLE IF NOT EXISTS policies (
	id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE COLLATE NOCASE, description TEXT NOT NULL DEFAULT '', targets TEXT NOT NULL,
	rules TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1, created INTEGER NOT NULL, updated INTEGER NOT NULL, who TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS policy_exceptions (
	id INTEGER PRIMARY KEY AUTOINCREMENT, node_id TEXT NOT NULL, rule_id TEXT NOT NULL, reason TEXT NOT NULL, who TEXT NOT NULL,
	created INTEGER NOT NULL, expires INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS compliance (
	node_id TEXT NOT NULL, rule_id TEXT NOT NULL, state TEXT NOT NULL, detail TEXT NOT NULL, policy_id INTEGER, conflict TEXT,
	checked INTEGER NOT NULL, PRIMARY KEY (node_id, rule_id));
PRAGMA user_version = 13;
SQL);
	}
	if ($version < 14) {
		/* Templates (configuration pushed to firewalls) and what each firewall last got. */
		$db->exec(<<<'SQL'
CREATE TABLE IF NOT EXISTS templates (
	id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE COLLATE NOCASE, description TEXT NOT NULL DEFAULT '', targets TEXT NOT NULL,
	items TEXT NOT NULL, created INTEGER NOT NULL, updated INTEGER NOT NULL, who TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS template_state (
	template_id INTEGER NOT NULL, node_id TEXT NOT NULL, hash TEXT NOT NULL, applied INTEGER NOT NULL, result TEXT NOT NULL, detail TEXT NOT NULL,
	PRIMARY KEY (template_id, node_id));
PRAGMA user_version = 14;
SQL);
	}
	if ($version < 15) {
		/* Central users and user groups (synced to firewalls). Passwords only as bcrypt hashes. */
		$db->exec(<<<'SQL'
CREATE TABLE IF NOT EXISTS fusers (
	id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE COLLATE NOCASE, fullname TEXT NOT NULL DEFAULT '', hash TEXT NOT NULL,
	ssh_keys TEXT NOT NULL DEFAULT '', expires TEXT NOT NULL DEFAULT '', disabled INTEGER NOT NULL DEFAULT 0, created INTEGER NOT NULL, updated INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS ugroups (
	id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE COLLATE NOCASE, description TEXT NOT NULL DEFAULT '', privs TEXT NOT NULL,
	targets TEXT NOT NULL, created INTEGER NOT NULL, updated INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS ugroup_members (user_id INTEGER NOT NULL, group_id INTEGER NOT NULL, PRIMARY KEY (user_id, group_id));
PRAGMA user_version = 15;
SQL);
	}
	if ($version < 16) {
		/* Naming per group: pattern and domain on the group, never-reused counters, the name an invitation holds. */
		$db->exec(<<<'SQL'
ALTER TABLE fleet_groups ADD COLUMN naming_pattern TEXT NOT NULL DEFAULT '';
ALTER TABLE fleet_groups ADD COLUMN naming_domain TEXT NOT NULL DEFAULT '';
ALTER TABLE invitations ADD COLUMN group_id INTEGER;
ALTER TABLE invitations ADD COLUMN hostname TEXT NOT NULL DEFAULT '';
ALTER TABLE invitations ADD COLUMN domain TEXT NOT NULL DEFAULT '';
CREATE TABLE IF NOT EXISTS name_counters (scope TEXT PRIMARY KEY, next INTEGER NOT NULL);
PRAGMA user_version = 16;
SQL);
	}
	if ($version < 17) {
		/* Deployment Factory: batches and their rows; invitations can be bound to a serial or cloud instance id. */
		$db->exec(<<<'SQL'
CREATE TABLE IF NOT EXISTS batches (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, settings TEXT NOT NULL, created INTEGER NOT NULL, who TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS batch_rows (
	batch_id INTEGER NOT NULL, n INTEGER NOT NULL, site TEXT NOT NULL, label TEXT NOT NULL, hostname TEXT NOT NULL, domain TEXT NOT NULL,
	serial TEXT NOT NULL, instance_id TEXT NOT NULL, token_id TEXT NOT NULL, PRIMARY KEY (batch_id, n));
ALTER TABLE invitations ADD COLUMN bind_serial TEXT NOT NULL DEFAULT '';
ALTER TABLE invitations ADD COLUMN bind_instance TEXT NOT NULL DEFAULT '';
ALTER TABLE invitations ADD COLUMN auto_approve INTEGER NOT NULL DEFAULT 0;
ALTER TABLE invitations ADD COLUMN batch_id INTEGER;
PRAGMA user_version = 17;
SQL);
	}
	if ($version < 18) {
		/* Which firewall used an invitation (Factory rows show it). */
		$db->exec(<<<'SQL'
ALTER TABLE invitations ADD COLUMN node_id TEXT;
PRAGMA user_version = 18;
SQL);
	}
	if ($version < 19) {
		/* Alerts: channels (secrets sealed) and every alert with where it was sent. */
		$db->exec(<<<'SQL'
CREATE TABLE IF NOT EXISTS alert_channels (
	id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, type TEXT NOT NULL, config TEXT NOT NULL, events TEXT NOT NULL,
	min_severity TEXT NOT NULL DEFAULT 'info', enabled INTEGER NOT NULL DEFAULT 1, report_hour INTEGER, report_sent INTEGER, created INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS alerts (
	id INTEGER PRIMARY KEY AUTOINCREMENT, time INTEGER NOT NULL, event TEXT NOT NULL, severity TEXT NOT NULL, node_id TEXT NOT NULL,
	text TEXT NOT NULL, sent TEXT NOT NULL, tries INTEGER NOT NULL DEFAULT 0, done INTEGER NOT NULL DEFAULT 0, repeats INTEGER NOT NULL DEFAULT 0, channel INTEGER);
CREATE INDEX IF NOT EXISTS alerts_open ON alerts (done, tries);
CREATE INDEX IF NOT EXISTS alerts_merge ON alerts (event, node_id, time);
PRAGMA user_version = 19;
SQL);
	}
	if ($version < 20) {
		/* NOC screens: kiosk keys (hash only), their networks, hiding names. */
		$db->exec(<<<'SQL'
CREATE TABLE IF NOT EXISTS kiosk_keys (
	id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, hash TEXT NOT NULL UNIQUE, networks TEXT NOT NULL, hide INTEGER NOT NULL DEFAULT 0,
	created INTEGER NOT NULL, who TEXT NOT NULL, last_used INTEGER, last_ip TEXT, revoked INTEGER);
PRAGMA user_version = 20;
SQL);
	}
	if ($version < 21) {
		/* Settings templates (time, DNS, SNMP, remote logging) beside alias templates. */
		$db->exec(<<<'SQL'
ALTER TABLE templates ADD COLUMN kind TEXT NOT NULL DEFAULT 'aliases';
ALTER TABLE templates ADD COLUMN settings TEXT;
PRAGMA user_version = 21;
SQL);
	}
	if ($version < 22) {
		/* Template drift: a firewall left alone by a template (Ignore), with who and why. */
		$db->exec(<<<'SQL'
CREATE TABLE IF NOT EXISTS template_ignores (
	template_id INTEGER NOT NULL, node_id TEXT NOT NULL, reason TEXT NOT NULL, who TEXT NOT NULL, time INTEGER NOT NULL, PRIMARY KEY (template_id, node_id));
PRAGMA user_version = 22;
SQL);
	}
	if ($version < 23) {
		/* Connection manager: the method per group and per firewall ('' = as above), and each firewall's path. */
		$db->exec(<<<'SQL'
ALTER TABLE fleet_groups ADD COLUMN conn_method TEXT NOT NULL DEFAULT '';
ALTER TABLE fleet_groups ADD COLUMN conn_iface TEXT NOT NULL DEFAULT '';
ALTER TABLE boxes ADD COLUMN conn_method TEXT NOT NULL DEFAULT '';
ALTER TABLE boxes ADD COLUMN conn_iface TEXT NOT NULL DEFAULT '';
ALTER TABLE boxes ADD COLUMN conn_state TEXT;
PRAGMA user_version = 23;
SQL);
	}
	if ($version < 24) {
		/* Joining over Tailscale: how an invitation reaches the controller; firewalls that switch their path by themselves once online. */
		$db->exec(<<<'SQL'
ALTER TABLE invitations ADD COLUMN via TEXT NOT NULL DEFAULT '';
ALTER TABLE invitations ADD COLUMN ts_key_id TEXT NOT NULL DEFAULT '';
ALTER TABLE boxes ADD COLUMN conn_auto INTEGER NOT NULL DEFAULT 0;
PRAGMA user_version = 24;
SQL);
	}
	if ($version < 25) {
		/* NOC screens: each screen's look. */
		$db->exec(<<<'SQL'
ALTER TABLE kiosk_keys ADD COLUMN style TEXT NOT NULL DEFAULT 'freesense';
ALTER TABLE kiosk_keys ADD COLUMN theme TEXT NOT NULL DEFAULT 'auto';
PRAGMA user_version = 25;
SQL);
	}
	if ($version < 26) {
		/* Availability: every state change of a firewall, filled from the audit log once. */
		$db->exec(<<<'SQL'
CREATE TABLE IF NOT EXISTS state_log (id INTEGER PRIMARY KEY AUTOINCREMENT, node_id TEXT NOT NULL, time INTEGER NOT NULL, state TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS state_log_node_time ON state_log (node_id, time);
SQL);
		require_once('fleet/fleet_stats.inc');
		fleet_stats_backfill($db);
		$db->exec('PRAGMA user_version = 26');
	}
	if ($version < 27) {
		/* Load samples for the fleet charts (fleet_samples.inc): five-minute rows for 48 hours, hourly for 30 days. */
		$db->exec(<<<'SQL'
CREATE TABLE IF NOT EXISTS samples (node_id TEXT NOT NULL, time INTEGER NOT NULL, cpu REAL, mem REAL, states INTEGER, states_max INTEGER, temp REAL,
	rx_bps REAL, tx_bps REAL);
CREATE INDEX IF NOT EXISTS samples_time ON samples (time, node_id);
CREATE TABLE IF NOT EXISTS samples_hourly (node_id TEXT NOT NULL, time INTEGER NOT NULL, n INTEGER NOT NULL, cpu REAL, cpu_max REAL, mem REAL, states INTEGER,
	states_max INTEGER, temp REAL, rx_bps REAL, tx_bps REAL);
CREATE INDEX IF NOT EXISTS samples_hourly_time ON samples_hourly (time, node_id);
PRAGMA user_version = 27;
SQL);
	}
	$db->exec('COMMIT');
}

function fleet_setting(string $name, ?string $default = null): ?string {
	$st = fleet_db()->prepare('SELECT value FROM settings WHERE name = ?');
	$st->execute(array($name));
	$v = $st->fetchColumn();
	return ($v === false) ? $default : (string)$v;
}

function fleet_setting_set(string $name, string $value): void {
	fleet_db()->prepare('INSERT INTO settings (name, value) VALUES (?, ?) ON CONFLICT(name) DO UPDATE SET value = excluded.value')
	    ->execute(array($name, $value));
}

function fleet_audit(string $who, string $action, string $detail): void {
	fleet_db()->prepare('INSERT INTO audit (time, who, action, detail) VALUES (?, ?, ?, ?)')->execute(array(time(), $who, $action, $detail));
	if (function_exists('fleet_alert_from_audit')) {
		fleet_alert_from_audit($action, $detail);
	}
}

/* First-time setup of the controller's identity: overlay prefix and keys. Idempotent. */
function fleet_controller_init(): void {
	if (fleet_setting('overlay_prefix') === null) {
		fleet_setting_set('overlay_prefix', fleet_random_overlay());
	}
	fleet_master_key();
	fleet_signing_pem();
	fleet_tls_pem();
}
