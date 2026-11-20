<?php
/* Fleet controller tests: rule and port forward templates. Loaded by ../run.php (shares its variables). */

$tlbad = function (string $kind, array $in) {
	try {
		fleet_tlist_item_from($kind, $in);
	} catch (InvalidArgumentException $e) {
		return true;
	}
	return false;
};
$tlr = fleet_tlist_item_from('rules', array('key' => 'Allow-DNS', 'action' => 'pass', 'iface' => 'lan', 'proto' => 'tcp/udp', 'src' => 'lan', 'dst' => 'lanip', 'port' => '53', 'log' => '1', 'descr' => 'DNS'));
check(($tlr['key'] === 'allow-dns') && $tlr['log'] && $tlbad('rules', array('key' => 'x', 'iface' => 'eth0')) && $tlbad('rules', array('key' => 'x', 'iface' => 'lan', 'proto' => 'icmp', 'port' => '80')) &&
    $tlbad('rules', array('key' => 'x', 'iface' => 'lan', 'src' => '10.0.0.0/33')) && !$tlbad('rules', array('key' => 'x', 'iface' => 'opt2', 'src' => 'office_nets', 'dst' => '2001:db8::/64')) &&
    $tlbad('nat', array('key' => 'w', 'iface' => 'wan', 'proto' => 'tcp', 'port' => '443', 'target' => '10.0.0.0/24')) && $tlbad('nat', array('key' => 'w', 'iface' => 'wan', 'proto' => 'any', 'port' => '443', 'target' => '10.0.0.5')),
    'rule and port forward entries are checked: interfaces, addresses, networks, aliases, ports only with TCP or UDP, one forward target');
check(fleet_tlist_items_from('rules', array(array('key' => '', 'action' => 'pass', 'proto' => 'any', 'iface' => 'lan'), array('key' => 'a', 'iface' => 'lan'))) !== array() &&
    $tlbad('rules', array('key' => 'a b', 'iface' => 'lan')), 'empty rows are skipped; names are short and plain');
$tlb = fleet_tlist_body('rules', 7, $tlr);
check(($tlb['descr'] === '[Fleet:T7:allow-dns] DNS') && ($tlb['srctype'] === 'lan') && ($tlb['dsttype'] === 'lanip') && ($tlb['dstbeginport'] === '53') &&
    (fleet_tlist_body('rules', 7, array('src' => '10.1.0.0/16', 'dst' => 'web_servers', 'port' => '8000-8080') + $tlr)['srcmask'] === '16') &&
    (fleet_tlist_body('rules', 7, array('src' => '10.1.0.0/16', 'dst' => 'web_servers', 'port' => '8000-8080') + $tlr)['dstendport'] === '8080') &&
    (fleet_tlist_owner($tlb['descr']) === array(7, 'allow-dns')) && (fleet_tlist_owner('NAT ' . $tlb['descr']) === null),
    'the REST body carries the marker; addresses, masks and port ranges map to the edit form');
$tlraw = array('id' => 4, 'type' => 'pass', 'interface' => 'lan', 'protocol' => 'tcp/udp', 'source' => array('network' => 'lan'), 'destination' => array('network' => 'lanip', 'port' => '53'),
    'log' => '', 'descr' => '[Fleet:T7:allow-dns] DNS');
$tlother = array('id' => 5, 'type' => 'pass', 'interface' => 'lan', 'source' => array('any' => ''), 'destination' => array('any' => ''), 'descr' => 'Default allow LAN');
$tlold = array('id' => 6, 'type' => 'block', 'interface' => 'lan', 'source' => array('any' => ''), 'destination' => array('any' => ''), 'descr' => '[Fleet:T7:gone] old');
$tlp = fleet_tlist_plan('rules', 7, array($tlr), array($tlother, $tlraw, $tlold));
check((array_column($tlp, 'action', 'name') === array('allow-dns' => 'same', 'gone' => 'delete')) && ($tlp[1]['id'] === 6),
    'a matching rule is left alone, a rule the template dropped is removed, the firewall\'s own rule is never touched');
$tlp2 = fleet_tlist_plan('rules', 7, array(array('port' => '853') + $tlr), array($tlraw));
check(($tlp2[0]['action'] === 'update') && ($tlp2[0]['id'] === 4) && (fleet_tlist_plan('rules', 8, array($tlr), array($tlraw))[0]['action'] === 'create'),
    'a changed rule is updated in place; another template\'s marker is not this one\'s');
check((fleet_tlist_rule_order(7, array($tlr), array($tlother, $tlraw)) === array('lan' => array(4, 5))) && (fleet_tlist_rule_order(7, array($tlr), array($tlraw, $tlother)) === array()),
    'the template\'s rules come first on their interface; nothing to reorder when they already are');
check(fleet_tlist_item_from_raw('rules', 'allow-dns', $tlraw) === $tlr, 'adopting reads a firewall\'s rule back into the template\'s words');
$tln = fleet_tlist_item_from('nat', array('key' => 'web', 'iface' => 'wan', 'proto' => 'tcp', 'port' => '443', 'target' => '10.0.0.10', 'local' => '', 'descr' => 'Web'));
$tlnraw = array('id' => 0, 'interface' => 'wan', 'protocol' => 'tcp', 'destination' => array('network' => 'wanip', 'port' => '443'), 'target' => '10.0.0.10', 'local-port' => '443',
    'descr' => '[Fleet:T9:web] Web');
check(($tln['local'] === '443') && (fleet_tlist_plan('nat', 9, array($tln), array($tlnraw))[0]['action'] === 'same') &&
    (fleet_tlist_body('nat', 9, $tln)['filter-rule-association'] === 'add-associated') && (fleet_tlist_body('nat', 9, $tln)['dsttype'] === 'wanip'),
    'a port forward keeps its port when no local port is given, comes with its firewall rule, and matches the stored form');
$tlxml = '<?xml version="1.0"?><freesense><filter><rule><type>pass</type><interface>lan</interface><protocol>tcp/udp</protocol><source><network>lan</network></source>' .
    '<destination><network>lanip</network><port>53</port></destination><log/><descr>[Fleet:T7:allow-dns] DNS</descr></rule></filter><nat></nat></freesense>';
$tlcfg = fleet_tlist_from_config('rules', $tlxml);
check((count($tlcfg) === 1) && (fleet_tlist_plan('rules', 7, array($tlr), $tlcfg)[0]['action'] === 'same') && (fleet_tlist_from_config('nat', $tlxml) === array()),
    'drift is read from a configuration backup in the same form');
