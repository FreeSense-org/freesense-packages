<?php
/*
 * One process that records a wrong key, for the concurrency test in sections/48-store-migration.php.
 * Args: the freesense checkout, the data directory, the start time (float).
 */
$repo = dirname(__DIR__, 3);
putenv('FLEET_DATA=' . $argv[2]);
set_include_path("{$argv[1]}/src/etc/inc" . PATH_SEPARATOR . "{$repo}/sysutils/FreeSense-pkg-Fleet/files/usr/local/pkg");
if (!function_exists('gettext')) {
	function gettext($t) { return $t; }
}
require_once('fleet.inc');
fleet_db();
while (microtime(true) < (float)$argv[3]) {
	usleep(200);
}
try {
	echo json_encode(fleet_access_fail_hit('203.0.113.5', 5000, 5, 10)), "\n";
} catch (Throwable $e) {
	echo 'error: ' . $e->getMessage() . "\n";
}
