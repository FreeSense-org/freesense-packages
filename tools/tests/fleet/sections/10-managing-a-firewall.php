<?php
/* Fleet controller tests: managing a firewall. Loaded by ../run.php (shares its variables). */

check(fleet_manage_allowed(array('role' => 'managed')) && !fleet_manage_allowed(array('role' => 'monitor')) && !fleet_manage_allowed(array()),
    'only a Managed firewall can be changed');
$svcs = fleet_services_from(array('data' => array(
    array('name' => 'unbound', 'description' => 'DNS Resolver', 'running' => true),
    array('name' => 'openvpn', 'description' => 'OpenVPN server: Office', 'running' => false, 'mode' => 'server', 'vpnid' => 2),
    array('name' => 'bad name; rm', 'description' => 'x'), 'junk',
    array('name' => 'dpinger', 'description' => 'Gateway Monitoring &amp; alerts', 'running' => true))));
check(array_column($svcs, 'name') === array('unbound', 'dpinger', 'openvpn') && $svcs[1]['description'] === 'Gateway Monitoring & alerts' &&
    $svcs[2]['vpnid'] === 2 && $svcs[2]['running'] === false, 'services from the box, sorted, junk names dropped');
check(fleet_service_body($svcs[2]) === array('confirm' => true, 'mode' => 'server', 'vpnid' => 2) &&
    fleet_service_body($svcs[1]) === array('confirm' => true), 'an OpenVPN instance is addressed by mode and vpnid');
try {
	fleet_box_reboot(array('role' => 'monitor', 'node_id' => 'n', 'label' => 'L'), 'tester');
	check(false, 'no reboot of a monitor-only firewall');
} catch (RuntimeException $e) {
	check(strpos($e->getMessage(), 'Monitor only') !== false, 'a monitor-only firewall is refused before anything is sent');
}
check(fleet_event_text('n', 'reboot', 'n (L): reboot started') === array('Rebooted', 'by the controller') &&
    fleet_event_text('n', 'service', 'n (L): restart DNS Resolver') === array('Service', 'restart DNS Resolver') &&
    fleet_event_text('n', 'groups', 'n (L): in Denmark, Retail') === array('Groups changed', 'in Denmark, Retail'), 'manage events in words');
