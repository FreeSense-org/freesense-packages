<?php
/* Fleet controller tests: top-bar item. Loaded by ../run.php (shares its variables). */

check((fleet_nav_item(0, 0, 0, 0, 3)['kind'] === 'warn') && (fleet_nav_item(0, 0, 0, 0, 3)['label'] === 'FreeSense Fleet: 3 firewalls fail a policy rule') &&
    (fleet_nav_item(0, 0, 1, 0, 3)['kind'] === 'block'), 'the top bar shows policy failures after offline and degraded firewalls');
check(fleet_policy_fail_alerts('SEC-001', 'fail', array()) && !fleet_policy_fail_alerts('SEC-001', 'fail', array('SEC-001')) &&
    !fleet_policy_fail_alerts('OPS-003', 'fail', array()) && !fleet_policy_fail_alerts('SEC-001', 'pass', array()),
    'a new failure of a High rule raises an alert once; Medium and Low rules do not');
check((fleet_nav_item(0, 0)['hidden'] === false) && (fleet_nav_item(0, 0)['kind'] === 'pass') && (fleet_nav_item(0, 0)['badge'] === 0) &&
    (fleet_nav_item(2, 0)['busy'] === true) && (fleet_nav_item(2, 0)['badge'] === 2) && (fleet_nav_item(2, 0)['kind'] === 'info') &&
    (fleet_nav_item(2, 1)['kind'] === 'block') && (fleet_nav_item(0, 1)['label'] === 'FreeSense Fleet: 1 action failed') &&
    (fleet_nav_item(0, 0, 3, 1)['kind'] === 'block') && (fleet_nav_item(0, 0, 3, 1)['badge'] === 3) && (fleet_nav_item(1, 0, 0, 2)['kind'] === 'warn') &&
    (fleet_nav_item(0, 0)['panel'] === '/fleet/fleet_nav.php?panel=1'),
    'top bar: always there, green when fine; failures, then offline, then degraded, then running decide the count; it opens a panel');
check(strpos(fleet_nav_panel_html(time()), 'fs-navpanel-counts') !== false, 'the top-bar panel from the store');
check(is_array(fleet_nav_now(time())), 'the top-bar item from the store');
$nav = fleet_nav_item(3, 0);
require_once($argv[1] . '/src/usr/local/www/includes/fs_menu.inc');
check(fs_nav_plugin_item('fleet', $nav) !== null, 'System accepts the Fleet item as it is');
