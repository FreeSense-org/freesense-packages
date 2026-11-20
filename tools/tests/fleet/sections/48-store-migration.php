<?php
/* Fleet controller tests: the store migration. Loaded by ../run.php (shares its variables). */

/* A failed migration is rolled back completely and leaves no open transaction behind. */
$mfile = "{$data}/migrate-fail.db";
$mdb = new PDO('sqlite:' . $mfile, null, null, array(PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION));
$mdb->exec('CREATE TABLE backups (x TEXT)');
$mfailed = false;
try {
	fleet_db_migrate($mdb);
} catch (Throwable $e) {
	$mfailed = true;
}
check($mfailed && !$mdb->inTransaction() && ((int)$mdb->query('PRAGMA user_version')->fetchColumn() === 0) &&
    ($mdb->query("SELECT COUNT(*) FROM sqlite_master WHERE name = 'settings'")->fetchColumn() == 0),
    'a failing migration rolls back everything and closes its transaction');
unset($mdb);

/* Several processes opening a fresh store at the same moment (an upgrade) all get a migrated store. */
$rdir = "{$data}/migrate-race";
mkdir($rdir, 0700);
$start = microtime(true) + 1.5;
$procs = array();
for ($i = 0; $i < 6; $i++) {
	$p = proc_open(array(PHP_BINARY, __DIR__ . '/../migrate-worker.php', $src, $rdir, (string)$start), array(1 => array('pipe', 'w'), 2 => array('pipe', 'w')), $pipes);
	$procs[] = array($p, $pipes);
}
$answers = array();
foreach ($procs as list($p, $pipes)) {
	$answers[] = trim((string)stream_get_contents($pipes[1])) . trim((string)stream_get_contents($pipes[2]));
	proc_close($p);
}
check($answers === array_fill(0, 6, 'ok'), 'six processes opening a fresh store at once all migrate it once (' . implode(' | ', array_unique($answers)) . ')');
foreach (glob("{$rdir}/*") ?: array() as $f) {
	@unlink($f);
}
@rmdir($rdir);
@unlink($mfile);
foreach (glob("{$mfile}-*") ?: array() as $f) {
	@unlink($f);
}

/* Schema 32: audit columns, the indexes the queries need, and the per-row state tables (no JSON blobs in settings any more). */
$s32 = fleet_db();
$idx = $s32->query("SELECT name FROM sqlite_master WHERE type = 'index'")->fetchAll(PDO::FETCH_COLUMN);
$tabs = $s32->query("SELECT name FROM sqlite_master WHERE type = 'table'")->fetchAll(PDO::FETCH_COLUMN);
check(((int)$s32->query('PRAGMA user_version')->fetchColumn() >= 32) && (array_diff(array('audit_time', 'audit_action', 'audit_node', 'ops_state', 'ops_started', 'samples_node', 'samples_hourly_node', 'access_fails_ip'), $idx) === array()) &&
    (array_diff(array('bundle_state', 'remediation_state', 'users_sync', 'access_fails', 'access_blocked'), $tabs) === array()) &&
    (strpos((string)$s32->query("SELECT sql FROM sqlite_master WHERE name = 'audit'")->fetchColumn(), 'node_id') !== false),
    'schema 32: audit columns, indexes and the per-row state tables exist');

/* Upgrading from schema 31: old audit rows get their node id and code, the old JSON state is dropped. */
$ufile = "{$data}/migrate-up.db";
$udb = new PDO('sqlite:' . $ufile, null, null, array(PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION));
fleet_db_migrate($udb);
foreach (array('audit_time', 'audit_action', 'audit_node', 'ops_state', 'ops_started', 'samples_node', 'samples_hourly_node', 'access_fails_ip') as $i) {
	$udb->exec("DROP INDEX {$i}");
}
foreach (array('bundle_state', 'remediation_state', 'users_sync', 'access_fails', 'access_blocked') as $t) {
	$udb->exec("DROP TABLE {$t}");
}
$udb->exec('ALTER TABLE audit DROP COLUMN node_id; ALTER TABLE audit DROP COLUMN code; PRAGMA user_version = 31;');
$udb->exec("INSERT INTO boxes (node_id, name, label, host_no, overlay, wg_pub, api_key, cert_sha256, role, joined) VALUES ('n-up-0001', 'up', 'Up', 1, 'x', 'wg1', 'k', 'c', 'managed', 1)");
$udb->exec("INSERT INTO audit (time, who, action, detail) VALUES (1, 'poll', 'state', 'n-up-0001 (Up): online -> offline (FLEET-E105)'), (2, 'poll', 'policy', 'FLEET-E321: Lock suspended on Up'),
    (3, 'x', 'state', 'n-gone-99 (Gone): online -> offline'), (4, 'x', 'users', 'Sync to Up: 1 added')");
$udb->exec("INSERT INTO settings (name, value) VALUES ('bundles', '{}'), ('access_blocked', '{}'), ('keep', 'me')");
fleet_db_migrate($udb);
$urows = $udb->query('SELECT node_id, code FROM audit ORDER BY id')->fetchAll(PDO::FETCH_NUM);
check(((int)$udb->query('PRAGMA user_version')->fetchColumn() === FLEET_DB_SCHEMA) && ($urows === array(array('n-up-0001', 'FLEET-E105'), array(null, 'FLEET-E321'), array(null, null), array(null, null))) &&
    ($udb->query("SELECT group_concat(name) FROM settings")->fetchColumn() === 'keep') && ($udb->query('SELECT COUNT(*) FROM bundle_state')->fetchColumn() == 0),
    'upgrading from schema 31 fills node id and code on old audit rows (only for firewalls that exist) and drops the old JSON state');
unset($udb);
foreach (glob("{$ufile}*") ?: array() as $f) {
	@unlink($f);
}
