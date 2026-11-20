<?php
/* Fleet controller tests: updates. Loaded by ../run.php (shares its variables). */

check(fleet_version_number('1.1.5-RELEASE') === '1.1.5' && fleet_version_number('1.1.6_1') === '1.1.6' && fleet_version_number('x') === '' &&
    fleet_version_same('1.1.6-RELEASE', '1.1.6') && !fleet_version_same('1.1.6', '1.1.60') && !fleet_version_same('', ''), 'versions compared by their numbers');
$ui = fleet_update_info_from(200, array('data' => array('installed_version' => '1.1.5', 'latest_version' => '1.1.6', 'update_available' => true, 'channel' => 'stable')), 50);
check($ui['available'] && $ui['latest'] === '1.1.6' && $ui['error'] === null && fleet_update_verdict($ui) === array('info', 'Update: 1.1.6'), 'an available update');
$ue = fleet_update_info_from(502, array('error' => array('message' => 'Unable to check for updates.', 'details' => array('messages' => array('DNS servers not available')))), 50);
check($ue['error'] === 'The firewall could not check for updates: DNS servers not available' && fleet_update_verdict($ue)[1] === 'Update check failed' &&
    fleet_update_verdict(array('available' => false, 'error' => null)) === null && fleet_update_verdict(null) === null, 'a failed check says why; up to date says nothing');
$uop = array('started' => 1000, 'text' => 'Downloading and installing', 'data' => json_encode(array('from' => '1.1.5', 'to' => '1.1.6')));
$old = array('version' => '1.1.5-RELEASE', 'boot_time' => 900);
check(fleet_op_update_step($uop, $old, 1060, 360, 3600) === null || fleet_op_update_step($uop, $old, 1060, 360, 3600)[0] === 'running', 'installing: still running');
check(fleet_op_update_step($uop, null, 1300, 360, 3600)[1] === 'Restarting', 'no answer: restarting');
$s1 = fleet_op_update_step($uop, array('version' => '1.1.6-RELEASE', 'boot_time' => 1400), 1500, 360, 3600);
check($s1[0] === 'running' && $s1[1] === 'Checking that it stays healthy' && $s1[3]['reached'] === 1500, 'new version: waiting out the rollback window');
$uop2 = array('started' => 1000, 'text' => 'Checking that it stays healthy', 'data' => json_encode($s1[3]));
check(fleet_op_update_step($uop2, array('version' => '1.1.6-RELEASE', 'boot_time' => 1400), 1700, 360, 3600)[0] === 'running' &&
    fleet_op_update_step($uop2, array('version' => '1.1.6-RELEASE', 'boot_time' => 1400), 1860, 360, 3600)[1] === 'Updated to 1.1.6 in 14 min 20 s',
    'done only when the new version stayed up for the whole window');
check(strpos(fleet_op_update_step($uop2, array('version' => '1.1.5-RELEASE', 'boot_time' => 1700), 1750, 360, 3600)[1], 'Rolled back to 1.1.5') === 0,
    'back on the old version after a reboot: rolled back');
check(fleet_op_update_step($uop, $old, 1000 + 3601, 360, 3600)[0] === 'failed' && fleet_op_update_step($uop, null, 1000 + 3601, 360, 3600)[0] === 'failed', 'no result in time: failed');
/* Development builds: the same number, only the build stamp differs. */
$dfrom = '1.2.0.a.20261017.1403_1792249307';
$dto = '1.2.0.a.20261017.2210_1792276951';
check(fleet_build_same('1.2.0.a.20261017.2210_1792276951', '1.2.0.a.20261017.2210.1792276951') && !fleet_build_same($dfrom, $dto) && !fleet_build_same('', ''),
    'one build, whatever the separator');
check(fleet_version_show($dfrom, $dto) === '1.2.0 build 20261017.1403' && fleet_version_show($dto, $dfrom) === '1.2.0 build 20261017.2210' &&
    fleet_version_show('1.1.5', '1.1.6') === '1.1.5', 'a Development update names the builds; a release names the version');
$dop = array('started' => 1000, 'text' => 'Downloading and installing', 'data' => json_encode(array('from' => $dfrom, 'to' => $dto)));
$dold = array('version' => '1.2.0-DEVELOPMENT', 'boot_time' => 900);
$dnew = array('version' => '1.2.0-DEVELOPMENT', 'boot_time' => 1400);
$d0 = fleet_op_update_step($dop, $dold, 1020, 360, 3600);
check($d0 === null || ($d0[0] === 'running' && !isset($d0[3]['reached'])), 'dev update: same number before the reboot is not "reached"');
check(fleet_op_update_step($dop, $dnew, 1500, 360, 3600)[1] === 'Checking the new version', 'dev update: rebooted but the build is not known yet');
$d1 = fleet_op_update_step($dop, $dnew, 1500, 360, 3600, '1.2.0.a.20261017.2210.1792276951');
check($d1[0] === 'running' && $d1[1] === 'Checking that it stays healthy' && $d1[3]['reached'] === 1500, 'dev update: rebooted onto the new build: waiting out the window');
$dop2 = array('started' => 1000, 'text' => 'Checking that it stays healthy', 'data' => json_encode($d1[3]));
check(fleet_op_update_step($dop2, $dnew, 1860, 360, 3600, '1.2.0.a.20261017.2210.1792276951')[1] === 'Updated to 1.2.0 build 20261017.2210 in 14 min 20 s',
    'dev update: done, naming the build');
check(strpos(fleet_op_update_step($dop, $dnew, 1500, 360, 3600, '1.2.0.a.20261017.1403.1792249307')[1], 'Rolled back to 1.2.0 build 20261017.1403') === 0 &&
    fleet_op_update_step($dop, $dnew, 1500, 360, 3600, '1.2.0.a.20261017.1403.1792249307')[0] === 'failed', 'dev update: back on the old build after a reboot: rolled back');
$gp = fleet_group_update_plan(array(
    array('node_id' => 'u1', 'label' => 'A', 'role' => 'managed', 'state' => 'online', 'status' => json_encode(array('rollback_protection' => true))),
    array('node_id' => 'u2', 'label' => 'B', 'role' => 'managed', 'state' => 'online', 'status' => json_encode(array('rollback_protection' => false))),
    array('node_id' => 'u3', 'label' => 'C', 'role' => 'managed', 'state' => 'online', 'status' => '{}'),
    array('node_id' => 'u4', 'label' => 'D', 'role' => 'managed', 'state' => 'online', 'status' => '{}')), array(),
    array('u1' => $ui, 'u2' => $ui, 'u3' => array('available' => false, 'installed' => '1.1.6', 'error' => null), 'u4' => $ue), false);
check(array_column($gp['go'], 'node_id') === array('u1') && count($gp['skip']) === 3 &&
    in_array('No rollback (UFS): update it by itself', array_map(function ($s) { return $s[1]; }, $gp['skip']), true), 'a group update leaves out the up to date, the unchecked and (by default) UFS');
check(count(fleet_group_update_plan(array(array('node_id' => 'u2', 'label' => 'B', 'role' => 'managed', 'state' => 'online', 'status' => json_encode(array('rollback_protection' => false)))),
    array(), array('u2' => $ui), true)['go']) === 1, 'UFS joins when the setting allows it');
