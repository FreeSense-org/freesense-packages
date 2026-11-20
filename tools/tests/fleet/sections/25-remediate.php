<?php
/* Fleet controller tests: remediate. Loaded by ../run.php (shares its variables). */

foreach (array(array('SEC-002', 'https'), array('VER-001', null), array('NAME-001', null)) as list($rid, $x)) {
	try {
		fleet_policy_rule_from($rid, ($rid === 'VER-001') ? array('version' => '1.1.5', 'mode' => 'remediate') : (($rid === 'NAME-001') ? array('regex' => '^a', 'mode' => 'remediate') : array('mode' => 'remediate')));
		check(false, "{$rid} cannot be set to fix itself");
	} catch (InvalidArgumentException $e) {
	}
}
list(, $rp, $rmode) = fleet_policy_rule_from('OPS-001', array('fix' => 'pool.ntp.org time.example', 'mode' => 'remediate'));
check($rmode === 'remediate' && $rp['fix'] === 'pool.ntp.org time.example', 'NTP can be fixed, with the servers to set');
$br = fleet_policy_lock_rules(array('OPS-001' => array($rp, 'remediate', 1, 'B', null), 'OPS-003' => array(array('value' => 'Europe/Copenhagen'), 'remediate', 1, 'B', null),
    'SEC-002' => array(array(), 'lock', 1, 'B', null), 'NAME-002' => array(array('value' => 'x.net'), 'audit', 1, 'B', null)));
check(count($br) === 3 && $br[0]['mode'] === 'remediate' && $br[0]['fix'] === 'pool.ntp.org time.example' && $br[2]['mode'] === 'lock', 'the bundle holds lock and remediate rules, not audit ones');
if (function_exists('fleet_remediate_plan')) {
	check(fleet_remediate_plan($br[0], null) === array('set', 'pool.ntp.org time.example') && fleet_remediate_plan($br[1], 'Etc/UTC') === array('set', 'Europe/Copenhagen') &&
	    fleet_remediate_plan($br[2], '') === null, 'the firewall plans the same fixes (and never fixes a lock rule)');
}
$h = hash('sha256', json_encode($rp));
check(fleet_remediate_due(array('OPS-001' => $rp), array(), 1000, false) === array('OPS-001' => $h), 'a new failure is fixed');
check(fleet_remediate_due(array('OPS-001' => $rp), array('OPS-001' => array('time' => 10, 'hash' => $h, 'result' => 'failed')), 99999, false) === array() &&
    fleet_remediate_due(array('OPS-001' => $rp), array('OPS-001' => array('time' => 10, 'hash' => $h, 'result' => 'failed')), 99999, true) === array('OPS-001' => $h),
    'a failed fix is not retried by itself; Fix now tries again');
check(fleet_remediate_due(array('OPS-001' => $rp), array('OPS-001' => array('time' => 10, 'hash' => 'old', 'result' => 'failed')), 99999, false) === array('OPS-001' => $h),
    'changed settings are tried again');
check(fleet_remediate_due(array('OPS-001' => $rp), array('OPS-001' => array('time' => 1000, 'hash' => $h, 'result' => 'fixed')), 2000, false) === array(),
    'a fix that worked waits for the next backup to show it');
