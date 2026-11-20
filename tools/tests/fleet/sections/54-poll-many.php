<?php
/* Fleet controller tests: polling many firewalls at once. Loaded by ../run.php (shares its variables). */

$pbox = function (string $id, string $state = 'online') {
	return array('node_id' => $id, 'state' => $state, 'role' => 'managed');
};
$stub = array(PHP_BINARY, '-r', '
	$n = $argv[1];
	if ($n === "slow") { sleep(6); }
	if ($n === "junk") { echo "not json"; exit(0); }
	echo json_encode(array("state" => ($n === "off") ? "offline" : "online", "due" => ($n === "b-due" && $argv[3] === "1")));
', '--');
$t0 = microtime(true);
$pm = fleet_poll_many(array($pbox('a-one'), $pbox('off'), $pbox('b-due'), $pbox('junk', 'degraded'), $pbox('c-three')), 30, true, 2, time() + 20, $stub);
check(($pm['a-one'] === array('state' => 'online', 'due' => false)) && ($pm['off'] === array('state' => 'offline', 'due' => false)) && ($pm['b-due'] === array('state' => 'online', 'due' => true)) &&
    ($pm['junk'] === array('state' => 'degraded', 'due' => false)) && ($pm['c-three']['state'] === 'online') && (count($pm) === 5),
    'many firewalls are polled in child processes, a few at a time; a child that prints nothing usable leaves the box as it was');
/* Side by side, not one after the other: four sleeping children with four at once take about one sleep. */
$sleepy = array(PHP_BINARY, '-r', 'sleep(2); echo json_encode(array("state" => "online", "due" => false));', '--');
$t1 = microtime(true);
$ps = fleet_poll_many(array($pbox('s1'), $pbox('s2'), $pbox('s3'), $pbox('s4')), 30, false, 4, time() + 30, $sleepy);
$took = microtime(true) - $t1;
check((count($ps) === 4) && ($took < 5.5), sprintf('four 2-second polls at once took %.1f s, not 8', $took));
/* A child still running at the deadline is ended and the box keeps its state. */
$t2 = microtime(true);
$pd = fleet_poll_many(array($pbox('slow', 'degraded')), 30, false, 2, time() + 2, $stub);
check(($pd['slow'] === array('state' => 'degraded', 'due' => false)) && ((microtime(true) - $t2) < 5), 'a poll still running at the deadline is ended');
/* Backup retries after failures wait longer each time. */
check(fleet_backup_retry_ok(array('backup_fails' => 0, 'backup_try' => 0), 1000) && !fleet_backup_retry_ok(array('backup_fails' => 1, 'backup_try' => 1000), 1000 + 200) &&
    fleet_backup_retry_ok(array('backup_fails' => 1, 'backup_try' => 1000), 1000 + 241) && !fleet_backup_retry_ok(array('backup_fails' => 3, 'backup_try' => 1000), 1000 + 900) &&
    fleet_backup_retry_ok(array('backup_fails' => 20, 'backup_try' => 1000), 1000 + 6 * 3600 + 1) && !fleet_backup_retry_ok(array('backup_fails' => 20, 'backup_try' => 1000), 1000 + 6 * 3600 - 5),
    'a failing backup is tried again after 4, 8, 16 ... minutes, at most every six hours');
fleet_db()->exec("INSERT OR IGNORE INTO boxes (node_id, name, label, host_no, overlay, wg_pub, api_key, cert_sha256, role, joined) VALUES ('n-bk-0001', 'bk', 'Bk', 901, 'x', 'wgbk1', 'k', 'c', 'managed', 1)");
fleet_backup_attempt_record('n-bk-0001', false);
fleet_backup_attempt_record('n-bk-0001', false);
$bk = fleet_db()->query("SELECT backup_fails, backup_try FROM boxes WHERE node_id = 'n-bk-0001'")->fetch();
fleet_backup_attempt_record('n-bk-0001', true);
check(((int)$bk['backup_fails'] === 2) && ((int)$bk['backup_try'] > 0) && (fleet_db()->query("SELECT backup_fails FROM boxes WHERE node_id = 'n-bk-0001'")->fetchColumn() == 0), 'failures are counted per firewall and a success clears them');
fleet_db()->exec("DELETE FROM boxes WHERE node_id = 'n-bk-0001'");
