<?php
/* Fleet controller tests: templates. Loaded by ../run.php (shares its variables). */

$ta = fleet_template_alias_from(array('name' => 'office_nets', 'type' => 'network', 'description' => 'Offices', 'entries' => "10.0.0.0/24  # HQ\n\n192.168.10.0/24\n2001:db8::/48 # v6"));
check($ta['entries'] === array(array('address' => '10.0.0.0/24', 'detail' => 'HQ'), array('address' => '192.168.10.0/24', 'detail' => ''), array('address' => '2001:db8::/48', 'detail' => 'v6')),
    'alias entries from lines with notes');
check(fleet_template_entries_text($ta['entries']) === "10.0.0.0/24  # HQ\n192.168.10.0/24\n2001:db8::/48  # v6", 'and back to text');
foreach (array(array('name' => 'bad name', 'type' => 'host', 'entries' => '1.2.3.4'), array('name' => '_x', 'type' => 'host', 'entries' => '1.2.3.4'),
    array('name' => 'n', 'type' => 'network', 'entries' => '10.0.0.0/33'), array('name' => 'p', 'type' => 'port', 'entries' => '70000'),
    array('name' => 'p', 'type' => 'port', 'entries' => '90:80'), array('name' => 'u', 'type' => 'url', 'entries' => 'http://x'), array('name' => 'e', 'type' => 'host', 'entries' => '')) as $bad) {
	try {
		fleet_template_alias_from($bad);
		check(false, 'a bad alias is refused: ' . json_encode($bad));
	} catch (InvalidArgumentException $e) {
	}
}
check(fleet_template_alias_from(array('name' => 'web', 'type' => 'port', 'entries' => "443\n8000:8080\nhttps_ports"))['entries'][1]['address'] === '8000:8080', 'ports and port ranges');
check(fleet_template_owner('[Fleet:T7] Offices') === 7 && fleet_template_owner('Offices [Fleet:T7]') === null && fleet_template_owner('') === null, 'the ownership marker');
$tb = fleet_template_alias_body(7, $ta);
$remote = array(
	array('name' => 'OFFICE_NETS', 'type' => 'network', 'description' => '[Fleet:T7] Offices', 'entries' => array_slice($ta['entries'], 0, 2)),
	array('name' => 'old_one', 'type' => 'host', 'description' => '[Fleet:T7] gone', 'entries' => array()),
	array('name' => 'local_srv', 'type' => 'host', 'description' => 'made on the box', 'entries' => array()),
	array('name' => 'other_t', 'type' => 'host', 'description' => '[Fleet:T9] x', 'entries' => array()),
);
$items = array($ta, array('name' => 'local_srv', 'type' => 'host', 'description' => '', 'entries' => array(array('address' => '1.1.1.1', 'detail' => ''))),
    array('name' => 'other_t', 'type' => 'host', 'description' => '', 'entries' => array(array('address' => '1.1.1.1', 'detail' => ''))),
    array('name' => 'new_one', 'type' => 'port', 'description' => '', 'entries' => array(array('address' => '22', 'detail' => ''))));
$tp = fleet_template_plan(7, $items, $remote);
$by = array_column($tp, null, 'name');
check($by['office_nets']['action'] === 'update' && $by['office_nets']['detail'] === '+1 -0 entries' && $by['local_srv']['action'] === 'conflict' &&
    $by['other_t']['action'] === 'conflict' && strpos($by['other_t']['detail'], 'Template 9') === 0 && $by['new_one']['action'] === 'create' && $by['old_one']['action'] === 'delete',
    'plan: change, conflicts (local and another template), create, and remove what the template no longer holds');
check(fleet_template_plan_counts($tp) === array('create' => 1, 'update' => 1, 'delete' => 1, 'same' => 0, 'conflict' => 2), 'plan counts');
check(fleet_template_plan(7, array($ta), array($tb))[0]['action'] === 'same', 'a pushed alias is in sync');
check(fleet_template_plan(8, array(), $remote) === array(), 'an empty template never touches other templates\' or local aliases');
$cx = '<freesense><aliases><alias><name>office_nets</name><type>network</type><address>10.0.0.0/24 192.168.10.0/24 2001:db8::/48</address>' .
    '<descr>[Fleet:T7] Offices</descr><detail>HQ||||v6</detail></alias></aliases></freesense>';
check(fleet_template_plan(7, array($ta), fleet_template_aliases_in_config($cx))[0]['action'] === 'same', 'drift from a configuration backup: in sync');
$tid = fleet_template_save(null, array('name' => 'Test nets', 'targets' => array('all'), 'alias' => array(array('name' => 'office_nets', 'type' => 'network', 'entries' => '10.0.0.0/24'))), 'test');
try {
	fleet_template_save(null, array('name' => 'Other', 'targets' => array('all'), 'alias' => array(array('name' => 'OFFICE_NETS', 'type' => 'host', 'entries' => '1.2.3.4'))), 'test');
	check((int)fleet_db()->query('SELECT COUNT(*) FROM boxes')->fetchColumn() === 0, 'two templates cannot push the same alias to the same firewalls');
} catch (InvalidArgumentException $e) {
}
check(fleet_template_get($tid)['items'][0]['name'] === 'office_nets', 'a template is stored');
fleet_template_delete($tid, 'test');
check(fleet_template_get($tid) === null, 'and deleted');

foreach (fleet_template_starters() as $sk => $st) {
	foreach ($st['aliases'] as $sa) {
		fleet_template_alias_from($sa);
	}
	check(count($st['aliases']) > 0, "starter {$sk} is valid");
}
