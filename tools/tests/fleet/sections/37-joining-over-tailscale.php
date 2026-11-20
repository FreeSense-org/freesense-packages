<?php
/* Fleet controller tests: joining over Tailscale. Loaded by ../run.php (shares its variables). */

$tsb = fleet_ts_authkey_body('Aarhus <office> & co', 30 * 86400);
check(($tsb['capabilities']['devices']['create'] === array('reusable' => false, 'ephemeral' => false, 'preauthorized' => true)) &&
    ($tsb['description'] === 'FreeSense Fleet Aarhus office  co') && ($tsb['expirySeconds'] === 30 * 86400) &&
    (fleet_ts_authkey_body('x', 400 * 86400)['expirySeconds'] === 90 * 86400) && (strlen(fleet_ts_authkey_body(str_repeat('a', 80), 3600)['description']) <= 50),
    'a Tailscale key per firewall: single use, pre-approved, not ephemeral, at most 90 days, a description Tailscale accepts');
check((count(fleet_ts_join_problems(null, null)) === 2) && (fleet_ts_join_problems('', '100.64.0.1') === array()) &&
    (fleet_ts_join_problems('The token expired.', '100.64.0.1') === array('The token expired.')),
    'joining over Tailscale needs a working API token and a controller in the tailnet');
