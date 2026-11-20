<?php
/* Fleet controller tests: users. Loaded by ../run.php (shares its variables). */

check(fleet_users_valid_name('anna.b') && !fleet_users_valid_name('admin') && !fleet_users_valid_name('Admins') && !fleet_users_valid_name('9x y'), 'account names; the firewall\'s own names are refused');
$ug = array(1 => array('name' => 'shop-support', 'description' => 'Status', 'privs' => array('page-dashboard-all')),
    2 => array('name' => 'netteam', 'description' => '', 'privs' => array('page-all')));
$fu = array(array('name' => 'anna', 'fullname' => 'Anna', 'hash' => 'h1', 'ssh_keys' => '', 'expires' => '', 'disabled' => 0, 'groups' => array(1, 2)),
    array('name' => 'bob', 'fullname' => '', 'hash' => 'h2', 'ssh_keys' => '', 'expires' => '', 'disabled' => 1, 'groups' => array(2)),
    array('name' => 'cid', 'fullname' => '', 'hash' => 'h3', 'ssh_keys' => '', 'expires' => '', 'disabled' => 0, 'groups' => array()));
$ud = fleet_users_desired($fu, $ug, array(1));
check($ud['format'] === 'fleet-users-v1' && array_column($ud['groups'], 'name') === array('shop-support') && count($ud['users']) === 1 &&
    $ud['users'][0]['groups'] === array('shop-support') && $ud['users'][0]['bcrypt_hash'] === 'h1', 'a firewall gets only the groups for it and their members');
$ud2 = fleet_users_desired($fu, $ug, array(1, 2));
check(count($ud2['users']) === 2 && $ud2['users'][1]['disabled'] === true, 'disabled users are sent disabled; users without a group go nowhere');
check(fleet_users_plan_counts(array('users' => array('a' => 'create', 'b' => 'same'), 'groups' => array('g' => 'delete'), 'clashes' => array('user admin'), 'skipped_privs' => array('g' => array('x', 'y')))) ===
    array('create' => 1, 'update' => 0, 'delete' => 1, 'same' => 1, 'clashes' => 1, 'skipped' => 2), 'plan counts');
if (is_file($src . '/src/etc/inc/fleet_accounts.inc')) {
	require_once($src . '/src/etc/inc/fleet_accounts.inc');
	/* What the controller sends is what the firewall accepts. */
	$fu[0]['hash'] = password_hash('x', PASSWORD_BCRYPT);
	check(count(fleet_accounts_desired(fleet_users_desired(array($fu[0]), $ug, array(1, 2)))['users']) === 1, 'the firewall accepts the controller\'s set');
}

$ue = fleet_users_from_entry(array('descr' => 'Anna B', 'bcrypt-hash' => '$2y$10$x', 'authorizedkeys' => base64_encode("ssh-ed25519 AAAA k\n"), 'expires' => '01/31/2027', 'disabled' => ''));
check($ue === array('fullname' => 'Anna B', 'hash' => '$2y$10$x', 'ssh_keys' => 'ssh-ed25519 AAAA k', 'expires' => '2027-01-31', 'disabled' => 1), 'adopt reads a firewall user back');
list($btext) = fleet_bundle_make('n1', array(), 5, true);
check(json_decode($btext, true)['lock_accounts'] === true && !isset(json_decode(fleet_bundle_make('n1', array(), 5)[0], true)['lock_accounts']), 'the bundle carries the account lock only when it is on');
