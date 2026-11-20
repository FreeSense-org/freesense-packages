<?php
/*
 * FreeSense Fleet controller tests: shared setup. run.php loads this, then
 * one file per area from sections/ in order (they share one SQLite store and
 * the variables earlier sections leave behind, so the order matters).
 * Run: php tools/tests/fleet/run.php [path to the freesense checkout]
 */

$repo = dirname(__DIR__, 3);
$src = $argv[1] ?? (is_dir("{$repo}/freesense-src") ? "{$repo}/freesense-src" : dirname($repo) . '/freesense');
$data = sys_get_temp_dir() . '/fleet-test-' . getmypid();
mkdir($data, 0700);
putenv("FLEET_DATA={$data}");
set_include_path("{$src}/src/etc/inc" . PATH_SEPARATOR . "{$repo}/sysutils/FreeSense-pkg-Fleet/files/usr/local/pkg");
if (!function_exists('gettext')) {
	function gettext($t) { return $t; }
}
/* The webhook tests call a sink on 127.0.0.1, which production refuses. */
define('FLEET_ALERT_ALLOW_LOOPBACK', true);
require_once('fleet.inc');

/* Records a failure and goes on, so one run reports every failing check. */
$fleet_test_failures = array();
function check($condition, $message) {
	global $fleet_test_failures;
	if (!$condition) {
		fwrite(STDERR, "FAIL: {$message}\n");
		$fleet_test_failures[] = $message;
	}
}
register_shutdown_function(function () use ($data) {
	foreach (glob("{$data}/*") ?: array() as $f) {
		@unlink($f);
	}
	@rmdir($data);
});
