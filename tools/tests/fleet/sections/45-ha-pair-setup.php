<?php
/* Fleet controller tests: HA pair setup. Loaded by ../run.php (shares its variables). */

check((fleet_ha_bits('255.255.255.0') === 24) && (fleet_ha_bits('24') === 24) && (fleet_ha_bits('255.0.255.0') === null) && fleet_ha_in_net('10.1.0.9', '10.1.0.1', 24) && !fleet_ha_in_net('10.2.0.9', '10.1.0.1', 24),
    'HA setup: masks and networks');
$hfa = array('label' => 'A', 'role' => 'managed', 'state' => 'online', 'api_level' => 12, 'in_pair' => false, 'hasync_peer' => '', 'vhids' => array(1),
    'ifaces' => fleet_ha_ifaces(array(array('name' => 'lan', 'description' => 'LAN', 'ipaddr' => '10.1.0.2', 'subnet' => '255.255.255.0', 'status' => 'up'),
    array('name' => 'opt1', 'description' => 'SYNC', 'ipaddr' => '10.9.0.1', 'subnet' => '255.255.255.252', 'status' => 'up'))));
$hcl = fleet_ha_ifaces(array(array('name' => 'lan', 'description' => 'LAN', 'hwif' => 'vtnet1', 'ipaddr' => '10.2.0.2', 'subnet' => '24'),
    array('name' => 'opt1', 'description' => 'SYNC', 'hwif' => 'vtnet1', 'ipaddr' => '10.2.0.2', 'subnet' => '24'), array('name' => 'wan', 'description' => 'WAN', 'hwif' => 'vtnet0', 'ipaddr' => '192.0.2.5', 'subnet' => '24')));
check(($hcl['lan']['clash'] === array('SYNC')) && ($hcl['opt1']['clash'] === array('LAN')) && ($hcl['wan']['clash'] === array()), 'HA setup: two assignments on one network card are found');
$hfb = array('label' => 'B', 'gui_cert' => str_repeat('ab', 32), 'vhids' => array(2), 'ifaces' => fleet_ha_ifaces(array(array('name' => 'lan', 'description' => 'LAN', 'ipaddr' => '10.1.0.3', 'subnet' => '255.255.255.0', 'status' => 'up'),
    array('name' => 'opt1', 'description' => 'SYNC', 'ipaddr' => '10.9.0.2', 'subnet' => '255.255.255.252', 'status' => 'up')))) + $hfa;
$hin = array('primary' => 'a', 'secondary' => 'b', 'vips' => array(array('iface' => 'lan', 'address' => '10.1.0.1')), 'sync_iface' => 'opt1', 'sections' => array('rules', 'users'));
list($herr, $hplan) = fleet_ha_setup_plan($hin, $hfa, $hfb);
check(empty($herr) && ($hplan['vips'][0]['vhid'] === 3) && ($hplan['vips'][0]['bits'] === 24) && ($hplan['secondary_sync_ip'] === '10.9.0.2') && ($hplan['sections'] === array('rules')),
    'HA setup plan: a free VHID on both, the subnet from the interface, the peer from the sync interface; users are never synced');
list($herr) = fleet_ha_setup_plan(array('vips' => array(array('iface' => 'lan', 'address' => '10.1.0.2'))) + $hin, $hfa, array('role' => 'monitor', 'hasync_peer' => '10.0.0.9') + $hfb);
check((count($herr) === 4) && (strpos(implode(' ', $herr), 'monitor only') !== false) && (strpos(implode(' ', $herr), 'own address') !== false),
    'HA setup refuses a monitored firewall, one that already syncs, and a firewall\'s own address as the shared one');
list($herr) = fleet_ha_setup_plan(array('vips' => array(array('iface' => 'lan', 'address' => '10.7.0.1', 'vhid' => 2))) + $hin, $hfa, $hfb);
check((count($herr) === 2) && (strpos($herr[0], '10.1.0.2/24') !== false), 'an address outside the network is refused');
$hvb = fleet_ha_vip_body($hplan['vips'][0], 100, 'pw');
$hsb = fleet_ha_sync_body($hplan, true, 'pw');
check(($hvb['mode'] === 'carp') && ($hvb['advskew'] === '100') && (strpos($hvb['descr'], FLEET_HA_MARK) === 0) &&
    ($hsb['synchronizetoip'] === '10.9.0.2') && ($hsb['synchronizerules'] === true) && ($hsb['synchronizenat'] === false) && !isset($hsb['synchronizeusers']) &&
    !isset(fleet_ha_sync_body($hplan, false)['synchronizetoip']) && ($hsb['syncpeerpin'] === str_repeat('ab', 32)), 'the CARP address and HA sync bodies (the secondary WebGUI certificate pinned); the secondary pushes nothing');
list($herr) = fleet_ha_setup_plan($hin, $hfa, array('gui_cert' => '') + $hfb);
check((count($herr) === 1) && (strpos($herr[0], 'WebGUI certificate') !== false) && empty(fleet_ha_setup_plan(array('sections' => array()) + $hin, $hfa, array('gui_cert' => '') + $hfb)[0]),
    'configuration sync needs the secondary certificate to pin; without sync sections it is not needed');

check((fleet_ha_sync_risk($hplan) === null) && (fleet_ha_sync_risk(array('sync_iface' => 'wan') + $hplan) === 'wan') && (fleet_ha_sync_risk(array('sync_iface' => 'lan') + $hplan) === 'shared'),
    'the sync risk: a network of its own is quiet, the WAN and a network that carries a shared address are warned about');

list($hb_err) = fleet_ha_setup_plan($hin, array('busy' => 'reboots') + $hfa, $hfb);
check((count($hb_err) === 1) && (strpos($hb_err[0], 'busy with another operation (reboots)') !== false) && empty(fleet_ha_setup_plan($hin, array('busy' => '') + $hfa, $hfb)[0]),
    'HA setup waits for a firewall that is busy with another operation (a reboot in the middle of a setup undoes it)');
