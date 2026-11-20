<?php
/* Fleet controller tests: Deployment Factory over Tailscale. Loaded by ../run.php (shares its variables). */

require_once('fleet_seed.inc');
list($fshown) = fleet_join_key_generate();
$flink = 'https://100.64.0.1:8443/fleet/join#abcdef012345.' . str_repeat('A', 43) . '.' . str_repeat('a', 64) . '.s';
$ftsk = 'tskey-auth-kTEST123CNTRL-abcdefghijkl';
$fa = fleet_seed_parse(json_encode(fleet_factory_seed($flink, 'attended', $fshown, null, $ftsk)));
$fp = fleet_seed_parse(json_encode(fleet_factory_seed($flink, 'pin', $fshown, '482913', $ftsk)));
$fu = fleet_seed_parse(json_encode(fleet_factory_seed($flink, 'unattended', $fshown, null, $ftsk)));
check((fleet_seed_tailscale_key($fa, (string)fleet_join_key_normalize($fshown)) === $ftsk) && !isset($fa['tailscale']['key']) &&
    (fleet_seed_tailscale_key($fp, '482913') === $ftsk) && !isset($fp['tailscale']['key']) && (fleet_seed_tailscale_key($fu, '') === $ftsk) &&
    !isset(fleet_factory_seed($flink, 'attended', $fshown, null)['tailscale']),
    'Factory seeds carry the Tailscale key the way System opens it: sealed to the join key or PIN, plain only unattended');
check(fleet_factory_settings(array('name' => 'B', 'mode' => 'pin', 'via' => 'tailscale'))['via'] === 'tailscale' && fleet_factory_settings(array('name' => 'B', 'via' => 'x'))['via'] === 'tunnel',
    'a batch is over the internet or over Tailscale');
