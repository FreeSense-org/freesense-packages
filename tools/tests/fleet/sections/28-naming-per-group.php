<?php
/* Fleet controller tests: naming per group. Loaded by ../run.php (shares its variables). */

check(fleet_naming_pattern_problem('{site}-fw{nn}') === null && fleet_naming_pattern_problem('') === null &&
    fleet_naming_pattern_problem('{city}-fw') !== null && fleet_naming_pattern_problem('{nn}-{nnn}') !== null && fleet_naming_pattern_problem('Shop_{nn}') !== null, 'hostname patterns');
check(fleet_naming_domain_ok('shops.example.local') && fleet_naming_domain_ok('hello.fish') && fleet_naming_domain_ok('') && !fleet_naming_domain_ok('local') && !fleet_naming_domain_ok('-x.fish'), 'group domains');
check(fleet_naming_render('{site}-fw{nn}', array('site' => 'Copenhagen HQ'), 3) === 'copenhagen-hq-fw03' && fleet_naming_render('{group}{nnn}', array('group' => 'Retail'), 7) === 'retail007' &&
    fleet_naming_render('{site}-fw', array('site' => ''), 1) === null, 'names from patterns (an empty token cannot make a valid name)');
check(fleet_naming_scope(4, '{site}-fw{nn}', array('site' => 'CPH')) === '4:cph-fw#' && fleet_naming_scope(4, '{site}-fw{nn}', array('site' => 'aar')) !== '4:cph-fw#', 'counters per group and site');
check(fleet_naming_next('{site}-fw{nn}', array('site' => 'cph'), 1, array('cph-fw01', 'CPH-FW02')) === array('cph-fw03', 3) &&
    fleet_naming_next('{site}-fw{nn}', array('site' => 'cph'), 5, array()) === array('cph-fw05', 5), 'the next free name; numbers only go up');
check(fleet_naming_next('edge', array(), 1, array('edge')) === null, 'a pattern without a counter cannot be used twice');
$nre = '/' . fleet_naming_regex('{site}-fw{nn}') . '/';
check(preg_match($nre, 'cph-fw01') === 1 && preg_match($nre, 'copenhagen-hq-fw12') === 1 && preg_match($nre, 'FreeSense') === 0 && preg_match($nre, 'cph-fwx') === 0, 'a hostname follows a pattern');
check(fleet_policy_group_params('domain', array('name' => 'Retail', 'naming_domain' => 'shops.example.local', 'naming_pattern' => '')) === array('value' => 'shops.example.local', '_group' => 'Retail') &&
    fleet_policy_group_params('pattern', array('name' => 'Retail', 'naming_domain' => 'x.y', 'naming_pattern' => '')) === array('_none' => 1) &&
    fleet_policy_group_params('domain', null) === array('_none' => 1), 'rules take the value from the firewall\'s naming group');
check(fleet_policy_check('NAME-003', array('value' => 'shops.example.local'), $pf)[1] === 'system/domain: "lab.arpa" (equals shops.example.local)' &&
    fleet_policy_check('NAME-004', array('regex' => fleet_naming_regex('{site}-{role}{nn}')), $pf)[0] === 'pass' &&
    fleet_policy_check('NAME-003', array('_none' => 1), $pf)[0] === 'unknown', 'group domain and pattern checked against the configuration');
check(fleet_policy_lock_rules(array('NAME-003' => array(array('_none' => 1), 'remediate', 1, 'B', null))) === array() &&
    fleet_policy_lock_rules(array('NAME-003' => array(array('value' => 'a.b'), 'remediate', 1, 'B', null)))[0]['value'] === 'a.b', 'the firewall gets its own group\'s domain to fix');
