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
