<?php
/* Fleet controller tests: groups. Loaded by ../run.php (shares its variables). */

check(fleet_group_name_problem('Retail', array()) === null && fleet_group_name_problem('', array()) !== null &&
    fleet_group_name_problem(str_repeat('x', 41), array()) !== null && fleet_group_name_problem('a<b', array()) !== null &&
    fleet_group_name_problem('all firewalls', array()) !== null && fleet_group_name_problem('RETAIL', array('Retail')) !== null,
    'group names: 1-40 characters, no markup, unique ignoring case, "All firewalls" is built in');
check(fleet_group_color('3') === '3' && fleet_group_color('red; x') === '1', 'only the eight series colours');
$g1 = fleet_group_save(null, 'Denmark', 'Danish sites', '2', 'tester');
$g2 = fleet_group_save(null, 'Retail', '', '9', 'tester');
try {
	fleet_group_save(null, 'denmark', '', '1', 'tester');
	check(false, 'a second Denmark is refused');
} catch (InvalidArgumentException $e) {
}
check(fleet_group_get($g2)['color'] === '1' && fleet_group_save($g1, 'Denmark', 'Danish sites and shops', '2', 'tester') === $g1 &&
    fleet_group_get($g1)['description'] === 'Danish sites and shops', 'create and change');
$gbox = array('node_id' => 'node-g', 'label' => 'Group test');
fleet_box_set_groups($gbox, array($g1, (string)$g2, 999, $g1), 'tester');
check(array_column(fleet_box_groups('node-g'), 'name') === array('Denmark', 'Retail'), 'a firewall in several groups; unknown ids and repeats are ignored');
check(array_column(fleet_groups_all(), 'members', 'name') === array('Denmark' => 1, 'Retail' => 1), 'member counts');
$byb = fleet_groups_by_box();
check($byb['node-g'] === array(array('id' => $g1, 'name' => 'Denmark', 'color' => '2'), array('id' => $g2, 'name' => 'Retail', 'color' => '1')),
    'groups per firewall for the dashboard');
$gdash = fleet_dashboard_data(array($row('node-g', 'G', 'online')), 0, 1, $byb);
check($gdash['boxes'][0]['groups'][0]['name'] === 'Denmark' && fleet_dashboard_data(array($row('x', 'X', 'online')), 0, 1, $byb)['boxes'][0]['groups'] === array(),
    'dashboard tiles carry their groups');
fleet_group_delete($g2, 'tester');
check(array_column(fleet_box_groups('node-g'), 'name') === array('Denmark') && fleet_group_get($g2) === null, 'deleting a group leaves its firewalls in the others');
fleet_box_set_groups($gbox, array(), 'tester');
check(fleet_box_groups('node-g') === array(), 'a firewall in no group');

foreach (glob($repo . '/sysutils/FreeSense-pkg-Fleet/files/usr/local/www/fleet/*.php') as $page) {
	check(preg_match('/\$g\b/', (string)file_get_contents($page)) === 0, basename($page) . ' does not use $g (the WebUI\'s global settings; the footer reads it)');
}
