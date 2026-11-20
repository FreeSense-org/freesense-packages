<?php
/* Fleet controller tests: policies. Loaded by ../run.php (shares its variables). */

$pcfg = simplexml_load_string('<freesense><system><hostname>dk-cph-edge01</hostname><domain>lab.arpa</domain><timezone>Europe/Copenhagen</timezone>' .
    '<timeservers>pool.ntp.org</timeservers><ssh><enable>enabled</enable><sshdkeyonly>enabled</sshdkeyonly><port>22</port></ssh>' .
    '<webgui><protocol>https</protocol></webgui></system></freesense>');
$pf = array('version' => '1.1.5-RELEASE', 'channel' => 'stable', 'rollback' => false, 'last_backup' => 1000, 'config' => $pcfg, 'now' => 1000 + 3 * 86400);
check(fleet_policy_check('VER-001', array('version' => '1.1.5'), $pf)[0] === 'pass' && fleet_policy_check('VER-001', array('version' => '1.1.6'), $pf)[0] === 'fail' &&
    fleet_policy_check('VER-002', array('version' => '1.1.5'), $pf)[0] === 'pass' && fleet_policy_check('VER-003', array('versions' => '1.1.6, 1.2.0'), $pf)[1] === 'Runs 1.1.5, allowed: 1.1.6, 1.2.0' &&
    fleet_policy_check('VER-004', array('channel' => 'testing'), $pf)[0] === 'fail', 'version rules: minimum, pinned, allowed, channel');
check(fleet_policy_check('VER-004', array('channel' => 'development'), array('channel' => 'devel') + $pf)[0] === 'pass' &&
    fleet_policy_check('VER-004', array('channel' => 'stable'), array('channel' => 'devel') + $pf)[0] === 'fail', 'a devel firewall follows the development channel');
$lp = function (string $sys) {
	return array('config' => simplexml_load_string('<freesense><system>' . $sys . '</system></freesense>'));
};
check(fleet_policy_check('SEC-003', array(), $lp(''))[0] === 'pass' && fleet_policy_check('SEC-003', array(), $lp('<webgui><noantilockout>true</noantilockout></webgui>'))[0] === 'pass' &&
    fleet_policy_check('SEC-003', array(), $lp('<sshguard_whitelist>10.0.0.0/8 0.0.0.0/0</sshguard_whitelist>'))[0] === 'fail' &&
    fleet_policy_check('SEC-003', array('threshold' => '30'), $lp('<sshguard_threshold>200</sshguard_threshold>'))[0] === 'fail' &&
    fleet_policy_check('SEC-003', array('threshold' => '30'), $lp('<sshguard_threshold>20</sshguard_threshold><sshguard_whitelist>10.0.0.0/8</sshguard_whitelist>'))[0] === 'pass',
    'login protection: an open pass list or a high threshold fails; the anti-lockout rule does not matter');
check(!in_array('SEC-003', FLEET_POLICY_REMEDIABLE, true) && !fleet_policy_lockable('SEC-003'), 'Fleet never fixes or locks login protection');
check(fleet_policy_check('OPS-010', array('days' => '2'), $pf)[0] === 'fail' && fleet_policy_check('OPS-020', array(), $pf)[0] === 'fail' &&
    fleet_policy_check('OPS-001', array(), $pf)[0] === 'pass' && fleet_policy_check('OPS-002', array(), $pf)[0] === 'fail' &&
    fleet_policy_check('OPS-003', array('value' => 'Europe/Copenhagen'), $pf)[0] === 'pass', 'operations rules');
check(fleet_policy_check('SEC-001', array(), $pf)[0] === 'pass' && fleet_policy_check('SEC-002', array(), $pf)[0] === 'pass' &&
    fleet_policy_check('NAME-001', array('regex' => '^[a-z]{2}-[a-z0-9]+-[a-z]+[0-9]{2}$'), $pf)[0] === 'pass' &&
    fleet_policy_check('NAME-002', array('value' => 'corp.net'), $pf)[1] === 'system/domain: "lab.arpa" (equals corp.net)', 'security and naming rules against the configuration backup');
check(fleet_policy_check('CUSTOM:1', array('path' => 'system/ssh/port', 'op' => 'max', 'value' => '1024', 'title' => 'x'), $pf)[0] === 'pass' &&
    fleet_policy_check('SEC-001', array(), array('config' => null) + $pf)[0] === 'unknown', 'custom path rules; no backup is unknown, not failed');
list($r1) = fleet_policy_rule_from('CUSTOM:3', array('path' => 'system/ssh/port', 'op' => 'equals', 'value' => '22', 'title' => 'Port'));
check($r1 === 'CUSTOM:3', 'a custom rule from the form');
foreach (array(array('VER-001', array('version' => 'abc')), array('CUSTOM:1', array('path' => '../etc', 'op' => 'equals', 'value' => '1', 'title' => 't')),
    array('NAME-001', array('regex' => '([')), array('CUSTOM', array())) as list($rid, $in)) {
	try {
		fleet_policy_rule_from($rid, $in);
		check(false, "rule {$rid} with bad settings is refused");
	} catch (InvalidArgumentException $e) {
	}
}
$pols = array(
	array('id' => 1, 'name' => 'Baseline', 'enabled' => 1, 'targets' => array('all'), 'rules' => array('VER-001' => array(array('version' => '1.1.5'), 'audit'), 'SEC-002' => array(array(), 'audit'))),
	array('id' => 2, 'name' => 'Retail', 'enabled' => 1, 'targets' => array('g:2'), 'rules' => array('VER-001' => array(array('version' => '1.1.6'), 'audit'))),
	array('id' => 3, 'name' => 'Denmark', 'enabled' => 1, 'targets' => array('g:1'), 'rules' => array('VER-001' => array(array('version' => '1.1.4'), 'audit'))),
	array('id' => 4, 'name' => 'Shop 7', 'enabled' => 1, 'targets' => array('n:shop7'), 'rules' => array('VER-002' => array(array('version' => '1.1.5'), 'audit'))),
	array('id' => 5, 'name' => 'Off', 'enabled' => 0, 'targets' => array('all'), 'rules' => array('OPS-020' => array(array(), 'audit'))));
$eff = fleet_policy_effective($pols, 'shop7', array(1, 2));
check($eff['VER-001'][2] === 3 && $eff['VER-001'][4] === 'Retail' && $eff['SEC-002'][3] === 'Baseline' && $eff['VER-002'][3] === 'Shop 7' && !isset($eff['OPS-020']),
    'effective rules: firewall over group over all; two groups that disagree are a conflict; disabled policies do nothing');
check(fleet_policy_effective($pols, 'x', array(2))['VER-001'][4] === null, 'one group: no conflict');
check(fleet_policy_update_block(fleet_policy_version_limits($eff), '1.1.6') === 'Pinned to 1.1.5 by policy' &&
    fleet_policy_update_block(array(null, array('1.1.6')), '1.1.6') === null && fleet_policy_update_block(array(null, array('1.1.5')), '1.1.6') === 'Policy allows only 1.1.5',
    'version rules stop updates they do not allow');
check(fleet_policy_update_block(array('1.1.5', null), '') === 'Pinned to 1.1.5 by policy' && fleet_policy_update_block(array(null, array('1.1.6')), '') !== null &&
    fleet_policy_update_block(array(null, null), '') === null, 'an unknown offered version: a pin or an allowed list still blocks');
check(fleet_policy_excepted(array(array('node_id' => 'a', 'rule_id' => 'SEC-002', 'expires' => 50)), 'a', 'SEC-002', 40) !== null &&
    fleet_policy_excepted(array(array('node_id' => 'a', 'rule_id' => 'SEC-002', 'expires' => 50)), 'a', 'SEC-002', 60) === null, 'exceptions expire');

$pid = fleet_policy_save(null, array('name' => 'Test baseline', 'targets' => array('all'), 'enabled' => '1',
    'use' => array('VER-001' => '1', 'OPS-010' => '1'), 'rule' => array('VER-001' => array('version' => '1.1.5'), 'OPS-010' => array('days' => '2'))), 'test');
$crows = fleet_db()->query('SELECT * FROM compliance')->fetchAll();
$nboxes = (int)fleet_db()->query('SELECT COUNT(*) FROM boxes')->fetchColumn();
check(($nboxes === 0) || (count($crows) === 2 * $nboxes), 'saving a policy checks every firewall against it');
try {
	fleet_policy_save(null, array('name' => 'Test baseline', 'targets' => array('all'), 'use' => array('VER-001' => '1'), 'rule' => array('VER-001' => array('version' => '1.1.5'))), 'test');
	check(false, 'policy names are unique');
} catch (InvalidArgumentException $e) {
}
try {
	fleet_policy_save(null, array('name' => 'Empty', 'targets' => array('all')), 'test');
	check(false, 'a policy needs a rule');
} catch (InvalidArgumentException $e) {
}
if ($nboxes > 0) {
	$anode = (string)fleet_db()->query('SELECT node_id FROM boxes LIMIT 1')->fetchColumn();
	fleet_policy_exception_add($anode, 'OPS-010', 'Lab box, backups by hand', date('Y-m-d', time() + 30 * 86400), 'test');
	$st = (string)fleet_db()->query("SELECT state FROM compliance WHERE node_id = " . fleet_db()->quote($anode) . " AND rule_id = 'OPS-010'")->fetchColumn();
	check(in_array($st, array('excepted', 'pass'), true), 'an exception turns a failure into excepted');
}
fleet_policy_delete($pid, 'test');
check((int)fleet_db()->query('SELECT COUNT(*) FROM compliance')->fetchColumn() === 0, 'deleting the last policy clears compliance');
