<?php
/* Fleet controller tests: Tailscale API checks. Loaded by ../run.php (shares its variables). */

check(fleet_ts_token_valid('tskey-api-kAbC123CNTRL-xyzXYZ0123456789') && !fleet_ts_token_valid('tskey-auth-kAbC123CNTRL-xyz0123456789') && !fleet_ts_token_valid('tskey-api-x y'),
    'only an API access token is taken');
$tsdev = array(array('id' => '1', 'addresses' => array('100.64.0.5', 'fd7a::5')), array('id' => '2', 'addresses' => array('100.64.0.9')));
check((fleet_ts_device_for($tsdev, '100.64.0.9')['id'] === '2') && (fleet_ts_device_for($tsdev, '100.64.0.1') === null), 'a firewall\'s device is found by its tailnet address');
$tsnow = 1800000000;
$tsp = function (array $d) use ($tsnow) {
	return array_map(function ($p) { return $p[0] . '/' . $p[1]; }, fleet_ts_device_problems($d, $tsnow));
};
check($tsp(array('authorized' => true, 'keyExpiryDisabled' => true, 'connectedToControl' => true)) === array() &&
    $tsp(array('keyExpiryDisabled' => false, 'expires' => gmdate('c', $tsnow + 90 * 86400))) === array('FLEET-E136/warn') &&
    $tsp(array('keyExpiryDisabled' => false, 'expires' => gmdate('c', $tsnow + 3 * 86400))) === array('FLEET-E136/error') &&
    $tsp(array('keyExpiryDisabled' => false, 'expires' => gmdate('c', $tsnow - 60))) === array('FLEET-E136/error') &&
    $tsp(array('authorized' => false, 'keyExpiryDisabled' => true, 'connectedToControl' => false)) === array('/error', '/warn'),
    'key expiry on is FLEET-E136 (an error when close or past), unapproved and offline devices are named');
check(fleet_ts_check(array()) === null, 'without a token Tailscale paths are only probed');
