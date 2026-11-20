<?php
/*
 * FreeSense Fleet controller tests, including the integration of both sides:
 * the System's join client (freesense-src/src/etc/inc/fleet_join.inc) joins
 * through this package's enrollment server with a real SQLite store.
 * The areas live in sections/ (one file each, run in file-name order: they
 * share one store and the variables earlier ones leave behind). A failing
 * check is reported and the run goes on; the exit code is 1 if any failed.
 * Run: php tools/tests/fleet/run.php [path to the freesense checkout]
 */

require_once(__DIR__ . '/bootstrap.php');

$sections = glob(__DIR__ . '/sections/*.php') ?: array();
sort($sections);
foreach ($sections as $section) {
	require($section);
}

if (!empty($fleet_test_failures)) {
	fwrite(STDERR, sprintf("Fleet controller tests: %d failed\n", count($fleet_test_failures)));
	exit(1);
}
echo "Fleet controller tests: OK\n";
