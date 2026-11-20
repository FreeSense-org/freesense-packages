<?php
/* Fleet controller tests: connection manager. Loaded by ../run.php (shares its variables). */

$cfleet = array('method' => 'wireguard', 'iface' => 'lan');
check(fleet_conn_effective(array('method' => ''), array(), $cfleet) === array('wireguard', 'lan', 'fleet', null) &&
    fleet_conn_effective(array('method' => ''), array('Retail' => array('method' => 'direct', 'iface' => 'opt2'), 'All' => array('method' => '')), $cfleet) === array('direct', 'opt2', 'group:Retail', null) &&
    fleet_conn_effective(array('method' => 'tailscale', 'iface' => 'tailscale'), array('Retail' => array('method' => 'direct', 'iface' => 'opt2')), $cfleet)[2] === 'firewall',
    'the most specific choice wins: firewall, then group, then the fleet');
$cconf = fleet_conn_effective(array('method' => ''), array('Retail' => array('method' => 'direct', 'iface' => 'lan'), 'Denmark' => array('method' => 'tailscale', 'iface' => 'tailscale')), $cfleet);
check($cconf[3] === array('Denmark', 'Retail') && $cconf[2] === 'group:Denmark', 'two groups that disagree are a conflict, shown, never silent');
check(fleet_conn_effective(array('method' => ''), array('A' => array('method' => 'direct', 'iface' => 'lan'), 'B' => array('method' => 'direct', 'iface' => 'lan')), $cfleet)[3] === null,
    'groups that agree are no conflict');
check(fleet_conn_advise(array('public' => 'yes', 'private' => 'no', 'thirdparty' => 'no', 'udp' => 'yes'))[0] === 'wireguard' &&
    fleet_conn_advise(array('public' => 'no', 'private' => 'yes', 'thirdparty' => 'no', 'udp' => 'no'))[0] === 'direct' &&
    fleet_conn_advise(array('public' => 'no', 'private' => 'no', 'thirdparty' => 'yes', 'udp' => 'unsure'))[0] === 'tailscale' &&
    fleet_conn_advise(array('public' => 'yes', 'private' => 'no', 'thirdparty' => 'unsure', 'udp' => 'no'))[0] === 'tailscale' &&
    fleet_conn_advise(array('public' => 'no', 'private' => 'no', 'thirdparty' => 'no', 'udp' => 'no'))[0] === 'wireguard',
    'the advisor: public + UDP -> tunnel, shared network -> direct, no public address or no UDP -> Tailscale when allowed');
check(count(fleet_conn_advise(array('public' => 'no', 'private' => 'no', 'thirdparty' => 'yes', 'udp' => 'yes'))[2]) >= 2 && !empty(fleet_conn_requirements('direct')),
    'every recommendation says what it needs');
$cst = array('method' => 'direct', 'address' => '10.0.0.1', 'ok' => true, 'since' => 1, 'checked' => 1);
list($cdown, $calert) = fleet_conn_after($cst, false, 'timed out', 100);
list($cup, $calert2) = fleet_conn_after($cdown, true, '', 200);
list(, $calert3) = fleet_conn_after($cup, true, '', 300);
check(($calert === 'down') && ($cdown['error'] === 'timed out') && ($calert2 === 'up') && ($calert3 === null) && ($cup['since'] === 200), 'a path that stops or starts answering is noted once each way');
check(!fleet_conn_use_path(null, 100) && fleet_conn_use_path($cst, 100) && !fleet_conn_use_path($cdown, 100 + 60) && fleet_conn_use_path($cdown, 100 + FLEET_CONN_RETRY) &&
    !fleet_conn_use_path(array('method' => 'wireguard', 'address' => 'x', 'ok' => true), 1), 'a path is used while it answers, and tried again after a pause');
check(fleet_conn_pending(array('want' => array('direct', 'lan', 'fleet', null), 'state' => null)) && !fleet_conn_pending(array('want' => array('wireguard', '', 'fleet', null), 'state' => null)) &&
    fleet_conn_pending(array('want' => array('direct', 'opt2', 'fleet', null), 'state' => array('method' => 'direct', 'iface' => 'lan'))) &&
    fleet_conn_pending(array('want' => array('wireguard', '', 'fleet', null), 'state' => array('method' => 'tailscale', 'iface' => 'tailscale'))),
    'a change is pending when the method or the direct interface differs');
$cbad = function (array $in, bool $fleet) {
	try {
		fleet_conn_cfg_from($in, $fleet);
	} catch (InvalidArgumentException $e) {
		return true;
	}
	return false;
};
check($cbad(array('conn_method' => 'direct', 'conn_iface' => 'wan'), false) && $cbad(array('conn_method' => 'direct', 'conn_iface' => ''), false) && $cbad(array('conn_method' => ''), true) &&
    $cbad(array('conn_method' => 'ssh'), false) && fleet_conn_cfg_from(array('conn_method' => ''), false) === array('method' => '', 'iface' => '') &&
    fleet_conn_cfg_from(array('conn_method' => 'tailscale', 'conn_iface' => 'lan'), false)['iface'] === 'tailscale', 'connection choices: never WAN, the fleet needs a method, Tailscale always on tailscale0');
fleet_db()->exec("INSERT INTO fleet_groups (name, description, color, created) VALUES ('ConnTest', '', '', 1)");
$cgid = (int)fleet_db()->lastInsertId();
fleet_conn_set_group($cgid, array('conn_method' => 'direct', 'conn_iface' => 'opt2'), 'test');
check(fleet_group_get($cgid)['conn_method'] === 'direct' && is_array(fleet_conn_overview()), 'group choices are stored and the overview reads');
fleet_db()->exec("DELETE FROM fleet_groups WHERE id = {$cgid}");
