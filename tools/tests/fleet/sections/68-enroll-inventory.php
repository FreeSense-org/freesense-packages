<?php
/* Fleet controller tests: enrollment inventory bounds. Loaded by ../run.php (shares its variables). */

$big = array('serial' => 'S1', 'hostname' => "fw\n1", 'x-bad' => 'a', 'nested' => array(1), 'long' => str_repeat('a', 900));
for ($i = 0; $i < 40; $i++) {
	$big["k{$i}"] = 'v';
}
$clean = fleet_enroll_inventory_clean($big);
check(count($clean) === 24 && $clean['serial'] === 'S1' && $clean['hostname'] === 'fw1' && !isset($clean['x-bad']) && !isset($clean['nested']) && strlen($clean['long']) === 200,
    'enrollment inventory: bounded, scalar, no control characters');
check(fleet_enroll_inventory_clean('x') === array(), 'enrollment inventory: not a list gives nothing');

/* A block goes into the live pf table, not through a configuration write from the enrollment endpoint. */
$access_src = (string)file_get_contents($repo . '/sysutils/FreeSense-pkg-Fleet/files/usr/local/pkg/fleet/fleet_access.inc');
check(preg_match('/function fleet_access_failed.*?fleet_access_table\(\'add\'.*?\n}/s', $access_src) === 1 && preg_match('/function fleet_access_failed.*?\n}/s', $access_src, $mm) && strpos($mm[0], 'fleet_access_reload') === false,
    'a block is added to the pf table at once; the rules follow with the minute tick');

/* Review fixes: SEC-001 and SEC-003 read the configuration backup; a factory batch with no tasks is never "all done"; an older policy keeps its custom rule numbers. */
foreach (array('ssh_keyonly', 'login_protection') as $k) {
	check(in_array($k, array_column(fleet_policy_catalog(), 'kind'), true), "catalog has {$k}");
}
$src_pol = (string)file_get_contents($repo . '/sysutils/FreeSense-pkg-Fleet/files/usr/local/pkg/fleet/fleet_policy.inc');
check(strpos($src_pol, "array('config', 'ssh_keyonly', 'login_protection')") !== false, 'the compliance refresh loads the backup for the rules that read it (not only lockable ones)');
$gop = fleet_op_group_start('factory', 'empty group', 'test');
fleet_op_group_update($gop);
$gst = fleet_db()->query("SELECT state FROM ops WHERE id = {$gop}")->fetchColumn();
check($gst === 'running', 'a group without tasks is not counted as all done');
fleet_op_runner_crashed($gop, 'killed');
check(fleet_db()->query("SELECT state FROM ops WHERE id = {$gop}")->fetchColumn() === 'failed', 'a task-less group whose runner crashed fails');
