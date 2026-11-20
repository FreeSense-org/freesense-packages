<?php
/* Fleet controller tests: per-firewall state is one row each, not a JSON blob. Loaded by ../run.php (shares its variables). */

fleet_bundle_state_set('n-st-one1', array('hash' => 'h1', 'version' => 7, 'sent' => 100, 'error' => null, 'rules' => 3, 'lock_accounts' => true));
fleet_bundle_state_set('n-st-two2', array('hash' => 'h2', 'error' => 'Waiting for the firewall to come online'));
fleet_bundle_state_set('n-st-one1', array('hash' => 'h1b', 'version' => 8, 'sent' => 200, 'error' => null, 'rules' => 4));
$bs = fleet_bundle_state();
check(($bs['n-st-one1'] === array('hash' => 'h1b', 'version' => 8, 'sent' => 200, 'error' => null, 'rules' => 4, 'lock_accounts' => false)) &&
    ($bs['n-st-two2']['error'] === 'Waiting for the firewall to come online') && ($bs['n-st-two2']['version'] === 0) && ($bs['n-st-two2']['sent'] === null) &&
    (fleet_bundle_state_get('n-st-two2') === $bs['n-st-two2']) && (fleet_bundle_state_get('n-st-none') === null),
    'bundle state: one row per firewall, updated in place, a firewall never touches another\'s');
fleet_remediation_record('n-st-one1', 'SEC-002', 'hh', 'failed', 'cannot');
fleet_remediation_record('n-st-one1', 'SEC-002', 'hh2', 'fixed', 'done');
fleet_remediation_record('n-st-one1', 'NAME-001', 'hn', 'cannot', 'x');
$rm = fleet_remediations_for('n-st-one1');
check((count($rm) === 2) && ($rm['SEC-002']['result'] === 'fixed') && ($rm['SEC-002']['hash'] === 'hh2') && (fleet_remediations_for('n-st-two2') === array()),
    'remediation state: the last fix per firewall and rule');
fleet_users_state_set('n-st-one1', 'failed', 'refused');
fleet_users_state_set('n-st-one1', 'failed', 'refused again');
$us = fleet_users_states();
check(($us['n-st-one1']['result'] === 'failed') && ($us['n-st-one1']['detail'] === 'refused again') && ($us['n-st-one1']['synced'] === null),
    'users sync state: one row per firewall, a failure keeps what was last synced');
foreach (array('bundle_state', 'remediation_state', 'users_sync') as $t) {
	fleet_db()->exec("DELETE FROM {$t}");
}
