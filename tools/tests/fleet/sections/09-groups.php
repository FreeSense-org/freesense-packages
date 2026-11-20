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
/* A group something uses cannot be deleted: its policy, schedule, backup set, template, user group, ring or NOC screen would silently lose its firewalls. */
$gdb = fleet_db();
$gt = json_encode(array('g:' . $g2));
$now = time();
$gdb->prepare('INSERT INTO policies (name, targets, rules, created, updated, who) VALUES (?, ?, ?, ?, ?, ?)')->execute(array('Baseline', $gt, '{}', $now, $now, 't'));
$gdb->prepare('INSERT INTO schedules (name, kind, days, time, who, created, targets) VALUES (?, ?, ?, ?, ?, ?, ?)')->execute(array('Nightly', 'backup', '[1]', 60, 't', $now, $gt));
$gdb->prepare('INSERT INTO backup_sets (name, targets, keep_last, keep_daily, keep_weekly, keep_monthly, created) VALUES (?, ?, 1, 1, 1, 1, ?)')->execute(array('Set', $gt, $now));
$gdb->prepare('INSERT INTO templates (name, targets, items, created, updated, who) VALUES (?, ?, ?, ?, ?, ?)')->execute(array('Tpl', $gt, '[]', $now, $now, 't'));
$gdb->prepare('INSERT INTO ugroups (name, privs, targets, created, updated) VALUES (?, ?, ?, ?, ?)')->execute(array('Admins', '[]', $gt, $now, $now));
$gdb->prepare('INSERT INTO kiosk_keys (name, hash, networks, created, who, config) VALUES (?, ?, ?, ?, ?, ?)')->execute(array('Lobby', 'h1', '[]', $now, 't', json_encode(array('groups' => array($g2)))));
$gdb->prepare('INSERT INTO kiosk_keys (name, hash, networks, created, who, config, revoked) VALUES (?, ?, ?, ?, ?, ?, ?)')->execute(array('Old', 'h2', '[]', $now, 't', json_encode(array('groups' => array($g2))), $now));
$gdb->prepare("INSERT INTO rollouts (op_id, target, rings, state, gap, who, created) VALUES (1, 'Update', ?, 'running', 0, 't', ?)")->execute(array(json_encode(array(array('group' => $g2, 'name' => 'Retail', 'window' => null))), $now));
$gdb->prepare("INSERT INTO invitations (token_id, secret_hash, okm, role, label, created, expires, state, group_id) VALUES ('t-open', 'x', 'x', 'managed', 'Shop 9', ?, ?, 'open', ?)")->execute(array($now, $now + 3600, $g2));
$users = fleet_group_users($g2);
check(count($users) === 8 && ($users[0] === 'policy "Baseline"') && in_array('NOC screen "Lobby"', $users, true) && in_array('rollout "Update"', $users, true) &&
    in_array('open invitation "Shop 9"', $users, true) && !in_array('NOC screen "Old"', $users, true) && (fleet_group_users($g1) === array()),
    'a group is in use by policies, schedules, backup sets, templates, user groups, running rollouts, NOC screens and open invitations (not revoked screens)');
$refused = null;
try {
	fleet_group_delete($g2, 'tester');
} catch (RuntimeException $e) {
	$refused = $e->getMessage();
}
check(($refused !== null) && (strpos($refused, 'still used by policy "Baseline"') !== false) && (fleet_group_get($g2) !== null) &&
    (count(array_column(fleet_box_groups('node-g'), 'name')) === 2), 'deleting a group in use is refused and changes nothing');
check(fleet_group_users_words(array('schedule' => array('A', 'B', 'C', 'D'), 'policy' => array('P'), 'template' => array())) === array('4 schedules (A, B, C, ...)', 'policy "P"'),
    'users of a group as words');
foreach (array('policies', 'schedules', 'backup_sets', 'templates', 'ugroups', 'kiosk_keys', 'rollouts') as $t) {
	$gdb->exec("DELETE FROM {$t}");
}
$gdb->exec("DELETE FROM invitations WHERE token_id = 't-open'");
fleet_group_delete($g2, 'tester');
check(array_column(fleet_box_groups('node-g'), 'name') === array('Denmark') && fleet_group_get($g2) === null, 'deleting a group leaves its firewalls in the others');
fleet_box_set_groups($gbox, array(), 'tester');
check(fleet_box_groups('node-g') === array(), 'a firewall in no group');

foreach (glob($repo . '/sysutils/FreeSense-pkg-Fleet/files/usr/local/www/fleet/*.php') as $page) {
	check(preg_match('/\$g\b/', (string)file_get_contents($page)) === 0, basename($page) . ' does not use $g (the WebUI\'s global settings; the footer reads it)');
}
