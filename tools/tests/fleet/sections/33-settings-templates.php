<?php
/* Fleet controller tests: settings templates. Loaded by ../run.php (shares its variables). */

$tsbad = function (string $kind, array $in) {
	try {
		fleet_tset_from($kind, $in);
	} catch (InvalidArgumentException $e) {
		return true;
	}
	return false;
};
check(fleet_tset_from('time', array('set_timezone' => 'Europe/Copenhagen', 'set_timeservers' => "0.pool.ntp.org, 1.pool.ntp.org\n10.0.0.1")) ===
    array('timezone' => 'Europe/Copenhagen', 'timeservers' => array('0.pool.ntp.org', '1.pool.ntp.org', '10.0.0.1')) &&
    $tsbad('time', array('set_timezone' => 'Mars/Base', 'set_timeservers' => 'a.b')) && $tsbad('time', array('set_timezone' => 'UTC', 'set_timeservers' => 'bad host!')),
    'time templates: a real time zone and up to 5 NTP servers');
check(fleet_tset_from('dns', array('set_dnsservers' => "9.9.9.9\n2620:fe::fe", 'set_dnsallowoverride' => '1')) === array('dnsservers' => array('9.9.9.9', '2620:fe::fe'), 'dnsallowoverride' => true) &&
    $tsbad('dns', array('set_dnsservers' => 'dns.example.com')) && $tsbad('dns', array('set_dnsservers' => '')), 'DNS templates: addresses only, at least one');
check($tsbad('snmp', array('set_enable' => '1', 'set_rocommunity' => 'public')) && $tsbad('snmp', array('set_enable' => '1', 'set_rocommunity' => 'abc')) &&
    fleet_tset_from('snmp', array('set_enable' => '1', 'set_rocommunity' => ''), array('rocommunity' => 'kept-secret'))['rocommunity'] === 'kept-secret' &&
    !$tsbad('snmp', array()), 'SNMP templates: never "public", a short community is refused, an empty one on a change keeps the old');
check($tsbad('syslog', array('set_enable' => '1', 'set_servers' => '')) && $tsbad('syslog', array('set_enable' => '1', 'set_servers' => '12345')) &&
    $tsbad('syslog', array('set_enable' => '1', 'set_servers' => 'a.example b.example c.example d.example')) &&
    fleet_tset_from('syslog', array('set_enable' => '1', 'set_servers' => 'logs.example.net:5514', 'set_contents' => 'some', 'set_contents_list' => array('filter', 'bogus')))['contents'] === array('filter'),
    'syslog templates: 1 to 3 servers (a bare number is refused), only known log kinds');
$tsxml = '<?xml version="1.0"?><freesense><system><timezone>Etc/UTC</timezone><timeservers>pool.ntp.org</timeservers><dnsserver>1.1.1.1</dnsserver><dnsserver>8.8.8.8</dnsserver>' .
    '</system><snmpd><syslocation>HQ</syslocation><syscontact></syscontact><rocommunity>s3cret</rocommunity></snmpd><syslog><enable></enable><remoteserver>10.0.9.5</remoteserver>' .
    '<filter></filter><system></system></syslog></freesense>';
check(fleet_tset_from_config('time', $tsxml) === array('timezone' => 'Etc/UTC', 'timeservers' => array('pool.ntp.org')) &&
    fleet_tset_from_config('dns', $tsxml) === array('dnsservers' => array('1.1.1.1', '8.8.8.8'), 'dnsallowoverride' => false) &&
    fleet_tset_from_config('snmp', $tsxml) === array('enable' => false, 'syslocation' => 'HQ', 'syscontact' => '') &&
    fleet_tset_from_config('syslog', $tsxml) === array('enable' => true, 'servers' => array('10.0.9.5'), 'ipproto' => 'ipv4', 'contents' => array('system', 'filter')) &&
    fleet_tset_from_config('time', 'not xml') === null, 'settings read from a config backup');
check(fleet_tset_current('dns', array('dnsservers' => array(array('address' => '1.1.1.1', 'hostname' => ''), array('address' => '8.8.8.8')), 'dnsallowoverride' => false)) ===
    fleet_tset_from_config('dns', $tsxml) && fleet_tset_current('time', array('timezone' => 'Etc/UTC', 'timeservers' => 'pool.ntp.org')) === fleet_tset_from_config('time', $tsxml),
    'the route and the backup give the same comparable settings');
$tsd = fleet_tset_diff('time', array('timezone' => 'Europe/Copenhagen', 'timeservers' => array('pool.ntp.org')), fleet_tset_from_config('time', $tsxml));
check(count($tsd) === 1 && $tsd[0][0] === 'timezone' && $tsd[0][2] === 'Etc/UTC' && $tsd[0][3] === 'Europe/Copenhagen' &&
    fleet_tset_diff('dns', array('dnsservers' => array('8.8.8.8', '1.1.1.1'), 'dnsallowoverride' => false), fleet_tset_from_config('dns', $tsxml))[0][0] === 'dnsservers' &&
    fleet_tset_diff('syslog', array('enable' => false, 'servers' => array(), 'ipproto' => 'ipv4', 'contents' => 'all'), array('enable' => false, 'servers' => array('x'), 'ipproto' => 'ipv6', 'contents' => 'all')) === array() &&
    fleet_tset_diff('snmp', array('enable' => true, 'syslocation' => 'HQ', 'syscontact' => '', 'rocommunity' => 'x'), fleet_tset_from_config('snmp', $tsxml))[0][0] === 'enable',
    'the difference: changed fields only, DNS order matters, nothing else counts while a service stays off, the community is never compared');
check(fleet_tset_body('time', array('timezone' => 'UTC', 'timeservers' => array('a', 'b'))) === array('timezone' => 'UTC', 'timeservers' => 'a b') &&
    fleet_tset_body('dns', array('dnsservers' => array('9.9.9.9'), 'dnsallowoverride' => false))['dnsservers'] === array(array('address' => '9.9.9.9')) &&
    fleet_tset_body('syslog', array('enable' => false, 'servers' => array('x'), 'ipproto' => 'ipv4', 'contents' => 'all')) === array('enable' => false, 'servers' => array()),
    'the request bodies');
$tsid = fleet_template_save(null, array('name' => 'Lab SNMP', 'kind' => 'snmp', 'targets' => array('all'), 'set_enable' => '1', 'set_syslocation' => 'Lab', 'set_rocommunity' => 'lab-community-1'), 'test');
$tst = fleet_template_get($tsid);
check($tst['kind'] === 'snmp' && strpos(json_encode($tst['settings']), 'lab-community-1') === false && fleet_template_settings_open($tst)['rocommunity'] === 'lab-community-1',
    'the SNMP community is stored sealed');
$tsthrown = false;
try {
	fleet_template_save(null, array('name' => 'Second SNMP', 'kind' => 'snmp', 'targets' => array('all'), 'set_enable' => '1', 'set_rocommunity' => 'other-community'), 'test');
} catch (InvalidArgumentException $e) {
	$tsthrown = strpos($e->getMessage(), 'one of each') !== false;
}
check($tsthrown, 'two templates of the same kind cannot meet on a firewall');
fleet_template_save($tsid, array('name' => 'Lab SNMP', 'targets' => array('all'), 'set_enable' => '1', 'set_syslocation' => 'Lab 2', 'set_rocommunity' => ''), 'test');
check(fleet_template_settings_open(fleet_template_get($tsid))['rocommunity'] === 'lab-community-1' && fleet_template_get($tsid)['settings']['syslocation'] === 'Lab 2',
    'changing a settings template keeps its kind and its community');
check(fleet_template_settings_plan('time', array())[0]['action'] === 'same' && fleet_template_settings_plan('time', $tsd)[0]['action'] === 'update' &&
    fleet_template_plan_counts(fleet_template_settings_plan('time', $tsd))['update'] === 1, 'settings differences count like alias changes');
fleet_template_delete($tsid, 'test');
