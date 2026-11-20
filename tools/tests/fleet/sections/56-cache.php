<?php
/* Fleet controller tests: the shared cache. Loaded by ../run.php (shares its variables). */

$cn = 0;
$cv1 = fleet_cached('t1', 30, function () use (&$cn) { $cn++; return array('n' => $cn); });
$cv2 = fleet_cached('t1', 30, function () use (&$cn) { $cn++; return array('n' => $cn); });
check(($cv1 === array('n' => 1)) && ($cv2 === array('n' => 1)) && ($cn === 1), 'a cached value is made once while it is fresh');
$cf = FLEET_DATA . '/cache-t1.json';
touch($cf, time() - 100);
$cv3 = fleet_cached('t1', 30, function () use (&$cn) { $cn++; return array('n' => $cn); });
check(($cv3 === array('n' => 2)) && ($cn === 2) && ((time() - filemtime($cf)) < 5) && (decoct(fileperms($cf) & 0777) === '600'), 'a stale one is made again, written privately');
/* Someone else is making it: the old value is served meanwhile, nothing is made twice. */
touch($cf, time() - 100);
$hold = fopen($cf . '.lock', 'c');
flock($hold, LOCK_EX);
$cv4 = fleet_cached('t1', 30, function () use (&$cn) { $cn++; return array('n' => 99); });
flock($hold, LOCK_UN);
fclose($hold);
check(($cv4 === array('n' => 2)) && ($cn === 2), 'while another process makes it, the stale value is served and nothing is made twice');
fleet_cached('t2', 30, function () { return array('x' => "\xB1bad"); });
check(fleet_cached('t2', 30, function () { return array(); }) === array('x' => "\u{FFFD}bad"), 'a value with invalid UTF-8 is still kept (the bad byte replaced)');
foreach (glob(FLEET_DATA . '/cache-*') ?: array() as $f) {
	@unlink($f);
}
