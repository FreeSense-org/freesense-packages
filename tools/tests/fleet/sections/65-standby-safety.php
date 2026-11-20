<?php
/* Fleet controller tests: standby takeover and step-down safety. Loaded by ../run.php (shares its variables). */

check(fleet_standby_primary_answered(200) && fleet_standby_primary_answered(401) && fleet_standby_primary_answered(404) && !fleet_standby_primary_answered(0) && !fleet_standby_primary_answered(502) && !fleet_standby_primary_answered(503),
    'the primary has answered with any HTTP answer below 500; silence and server errors are not an answer');
$sp = array('role' => 'standby');
/* A standby that only gets refusals or bad copies (the primary is up) never takes over, one that hears nothing does. */
$st = array('takeover' => 'auto', 'auto_minutes' => 10, 'snapshot' => array('created' => 1), 'last_ok' => 1, 'last_alive' => 5000);
check(!fleet_standby_takeover_due($sp, $st, 5000 + 599) && fleet_standby_takeover_due($sp, $st, 5000 + 600) && !fleet_standby_takeover_due($sp, array('last_alive' => 0) + $st, 99999) && !fleet_standby_takeover_due($sp, array('last_alive' => 99999) + $st, 100000),
    'automatic takeover counts the time since the primary last answered, not since the last good copy');
/* The partner decides whether this controller was replaced. */
fleet_standby_pairing_save(array('role' => 'primary', 'peer_addr' => '203.0.113.9', 'token' => random_bytes(32), 'key' => random_bytes(32), 'created' => 1));
fleet_setting_set('ctl_epoch', '3');
check((fleet_standby_partner_newer(function () { return array(200, array('role' => 'primary', 'epoch' => 4)); }) === true) && (fleet_standby_partner_newer(function () { return array(200, array('role' => 'primary', 'epoch' => 3)); }) === false) &&
    (fleet_standby_partner_newer(function () { return array(200, array('role' => 'standby', 'epoch' => 9)); }) === false) && (fleet_standby_partner_newer(function () { return array(0, array()); }) === null) &&
    (fleet_standby_partner_newer(function () { return array(404, array()); }) === null), 'only the partner saying it is the primary with a newer epoch means this controller was replaced');
@unlink(FLEET_STANDBY_PAIRING);
check(fleet_standby_partner_newer(function () { return array(200, array('role' => 'primary', 'epoch' => 99)); }) === null, 'with no partner paired, nothing can say this controller was replaced');
