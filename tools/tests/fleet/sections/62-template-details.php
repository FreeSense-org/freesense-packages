<?php
/* Fleet controller tests: rule template details. Loaded by ../run.php (shares its variables). */

check((fleet_tlist_addr_family('10.0.0.0/8') === 'inet') && (fleet_tlist_addr_family('2001:db8::/32') === 'inet6') && (fleet_tlist_addr_family('2001:db8::1') === 'inet6') && (fleet_tlist_addr_family('any') === null) &&
    (fleet_tlist_addr_family('lan') === null) && (fleet_tlist_addr_family('web_servers') === null), 'the address family of a rule address');
$r4 = fleet_tlist_item_from('rules', array('key' => 'a', 'iface' => 'wan', 'action' => 'block', 'proto' => 'tcp', 'src' => '10.0.0.0/8', 'dst' => 'any', 'port' => '23'));
$r6 = fleet_tlist_item_from('rules', array('key' => 'b', 'iface' => 'wan', 'action' => 'block', 'proto' => 'tcp', 'src' => 'any', 'dst' => '2001:db8::/32', 'port' => '23'));
$ra = fleet_tlist_item_from('rules', array('key' => 'c', 'iface' => 'wan', 'action' => 'pass', 'proto' => 'tcp', 'src' => 'any', 'dst' => 'any'));
check((fleet_tlist_body('rules', 1, $r4)['ipprotocol'] === 'inet') && (fleet_tlist_body('rules', 1, $r6)['ipprotocol'] === 'inet6') && (fleet_tlist_body('rules', 1, $ra)['ipprotocol'] === 'inet'),
    'a rule template is IPv6 when its addresses are (it used to send every rule as IPv4)');
$mixed = null;
try {
	fleet_tlist_item_from('rules', array('key' => 'd', 'iface' => 'wan', 'action' => 'pass', 'proto' => 'tcp', 'src' => '10.0.0.1', 'dst' => '2001:db8::1'));
} catch (InvalidArgumentException $e) {
	$mixed = $e->getMessage();
}
$nat6 = null;
try {
	fleet_tlist_item_from('nat', array('key' => 'e', 'iface' => 'wan', 'proto' => 'tcp', 'port' => '443', 'target' => '2001:db8::5'));
} catch (InvalidArgumentException $e) {
	$nat6 = $e->getMessage();
}
check((strpos((string)$mixed, 'not both IPv4 or both IPv6') !== false) && (strpos((string)$nat6, 'port forwards are IPv4') !== false), 'mixed IPv4 and IPv6 in one rule, and an IPv6 port forward target, are refused when typed');

/* The stored hash of a settings template does not give its SNMP community away. */
$tpl = array('id' => 1, 'kind' => 'snmp', 'settings' => array('enable' => true, 'rocommunity' => fleet_seal('communitystring', fleet_master_key()), 'syslocation' => 'x'));
$tpl2 = array('settings' => array('rocommunity' => fleet_seal('other', fleet_master_key())) + $tpl['settings']) + $tpl;
$h1 = fleet_template_hash($tpl);
check(($h1 === fleet_template_hash($tpl)) && ($h1 !== fleet_template_hash($tpl2)) && ($h1 !== hash('sha256', json_encode(fleet_template_settings_open($tpl)))) && (strlen($h1) === 64),
    'the hash of a settings template is keyed (a plain hash of it could be used to guess the community), stable, and changes with the community');
