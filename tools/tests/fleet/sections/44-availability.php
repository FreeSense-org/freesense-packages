<?php
/* Fleet controller tests: Availability. Loaded by ../run.php (shares its variables). */

$sb = fleet_stats_box('online', array(array(1100, 'offline'), array(1400, 'online'), array(1800, 'degraded')), 1000, 2000);
check(($sb['up'] === 700) && ($sb['known'] === 1000) && ($sb['outages'] === array(array(1100, 1400))) && (fleet_stats_percent(700, 1000) === 70.0),
    'availability: online and degraded are up; an offline period is one outage');
$sb = fleet_stats_box(null, array(array(1500, 'online'), array(1900, 'offline')), 1000, 2000);
check(($sb['known'] === 500) && ($sb['up'] === 400) && ($sb['outages'] === array(array(1900, 2000))),
    'a firewall that joined during the range counts only from then; one still down has an open outage to the end');
check((fleet_stats_box('offline', array(), 0, 100)['outages'] === array(array(0, 100))) && (fleet_stats_percent(0, 0) === null), 'down the whole range; nothing known is no percentage');
$stl = fleet_stats_timeline(array('a' => array('online', array(array(50, 'offline'))), 'b' => array('online', array())), 0, 100, 4);
check(($stl['up'] === array(2, 2, 1, 1)) && ($stl['in'] === array(2, 2, 2, 2)), 'the timeline counts the firewalls up, and in the fleet, in each part of the range');
check((fleet_stats_audit_line('demo-909 (Demo: Pop-up store): online -> degraded (FLEET-E105: x)') === array('demo-909', 'online', 'degraded')) &&
    (fleet_stats_audit_line('something else') === null), 'state changes are read back from the audit log');
check(strpos(fleet_stats_svg($stl, 2, 0, 400, 100, function ($t) { return (string)$t; }, 'Up'), '<polyline') !== false, 'the timeline draws as SVG');
