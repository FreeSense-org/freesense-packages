<?php
/*
 * One process that opens the Fleet store, for the migration race test
 * (sections/02-controller-init.php starts several at the same moment).
 * Args: the freesense checkout, the data directory, the start time (float).
 */
$repo = dirname(__DIR__, 3);
putenv('FLEET_DATA=' . $argv[2]);
set_include_path("{$argv[1]}/src/etc/inc" . PATH_SEPARATOR . "{$repo}/sysutils/FreeSense-pkg-Fleet/files/usr/local/pkg");
if (!function_exists('gettext')) {
	function gettext($t) { return $t; }
}
require_once('fleet.inc');
while (microtime(true) < (float)$argv[3]) {
	usleep(200);
}
try {
	$v = (int)fleet_db()->query('PRAGMA user_version')->fetchColumn();
	echo ($v === FLEET_DB_SCHEMA) ? "ok\n" : "version {$v}\n";
} catch (Throwable $e) {
	echo 'error: ' . $e->getMessage() . "\n";
}
