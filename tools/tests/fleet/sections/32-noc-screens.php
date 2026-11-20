<?php
/* Fleet controller tests: NOC screens. Loaded by ../run.php (shares its variables). */

list($kn, $kp) = fleet_kiosk_networks("10.20.0.15\n10.20.5.0/24, fd00::/64");
check($kp === null && $kn === array('10.20.0.15/32', '10.20.5.0/24', 'fd00::/64'), 'screen networks: addresses become /32 or /128, lists split on lines and commas');
check(fleet_kiosk_networks('0.0.0.0/0')[1] !== null && fleet_kiosk_networks('')[1] !== null && fleet_kiosk_networks('10.0.0.0/33')[1] !== null && fleet_kiosk_networks('kiosk')[1] !== null,
    'screen networks: everywhere, nothing, a bad prefix and text are refused');
check(fleet_kiosk_ip_allowed('10.20.5.77', $kn) && fleet_kiosk_ip_allowed('10.20.0.15', $kn) && !fleet_kiosk_ip_allowed('10.20.0.16', $kn) && !fleet_kiosk_ip_allowed('10.20.6.1', $kn) &&
    fleet_kiosk_ip_allowed('fd00::1234', $kn) && !fleet_kiosk_ip_allowed('fd01::1', $kn) && !fleet_kiosk_ip_allowed('junk', $kn) &&
    fleet_kiosk_ip_allowed('192.168.1.130', array('192.168.1.128/25')) && !fleet_kiosk_ip_allowed('192.168.1.127', array('192.168.1.128/25')), 'a screen works only from its networks');
$kdata = array('headline' => 'x', 'total' => 2, 'counts' => array('online' => 1, 'offline' => 1), 'checked' => 1, 'now' => 2, 'boxes' => array(
    array('label' => 'Copenhagen HQ', 'host' => 'cph-fw01', 'state' => 'offline', 'groups' => array(array('id' => 1, 'name' => 'Retail', 'color' => '')), 'version' => '1.1.5', 'seen' => 1,
        'policy' => 0, 'breakglass' => false, 'update' => null, 'op' => null, 'problem' => 'FLEET-E105: no answer from 100.64.0.3'),
    array('label' => 'Oslo', 'host' => 'osl-fw01', 'state' => 'online', 'groups' => array(), 'version' => '1.1.5', 'seen' => 1, 'policy' => 1, 'breakglass' => false,
        'update' => array('info', 'Update'), 'op' => array('text' => 'Updating cph', 'progress' => 40), 'problem' => '')));
$khid = fleet_kiosk_view($kdata, array(array('title' => 'Update Retail', 'done' => 1, 'total' => 3, 'percent' => 33)), true, 'NOC');
$kjson = json_encode($khid);
check(strpos($kjson, 'Copenhagen') === false && strpos($kjson, 'cph-fw01') === false && strpos($kjson, '100.64') === false && strpos($kjson, 'Retail') === false,
    'hidden names: no labels, hostnames, group names, addresses, error texts or operation titles');
check($khid['boxes'][0]['name'] === 'Firewall 1' && $khid['boxes'][0]['problem'] === '' && $khid['boxes'][1]['update'] === true && $khid['ops'][0]['title'] === 'Fleet operation',
    'hidden names: firewalls are numbered and error texts are left out');
check(fleet_kiosk_view($kdata, array(), false, 'NOC')['boxes'][0]['name'] === 'Copenhagen HQ', 'shown names: the labels are there');
list($kid, $kkey) = fleet_kiosk_create(array('name' => 'Wall', 'networks' => '10.20.5.0/24'), 'test');
check(strpos($kkey, 'fkk_') === 0 && strpos(json_encode(fleet_db()->query("SELECT * FROM kiosk_keys WHERE id = {$kid}")->fetch()), $kkey) === false, 'a kiosk key is kept only as a hash');
check(fleet_kiosk_check($kkey, '10.20.5.9', time())[0]['name'] === 'Wall' && fleet_kiosk_check($kkey, '10.30.0.1', time())[0] === null &&
    fleet_kiosk_check($kkey . 'x', '10.20.5.9', time())[0] === null && fleet_kiosk_check('nope', '10.20.5.9', time())[0] === null, 'a key works from its networks only, and only that key');
fleet_kiosk_revoke($kid, 'test');
check(fleet_kiosk_check($kkey, '10.20.5.9', time())[0] === null, 'a revoked key stops at once');
