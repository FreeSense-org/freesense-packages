<?php
/* Fleet controller tests: live state and operations. Loaded by ../run.php (shares its variables). */

check(fleet_box_state_for(20, 10) === 'online' && fleet_box_state_for(60, 10) === 'degraded' && fleet_box_state_for(300, 10) === 'offline' &&
    fleet_box_state_for(120, 60) === 'online' && fleet_box_state_for(180, 60) === 'degraded' && fleet_box_state_for(600, 60) === 'offline',
    'degraded after 1 min of silence and offline after 5 min, whatever the interval (longer when checks are rarer)');
$rop = array('started' => 1000, 'text' => 'Rebooting');
check(fleet_op_reboot_step($rop, array('boot_time' => 900), 1010) === array('running', 'Waiting for it to go down', 25) &&
    fleet_op_reboot_step($rop, null, 1030) === array('running', 'Restarting', 50) &&
    fleet_op_reboot_step(array('started' => 1000, 'text' => 'Restarting'), null, 1040) === null &&
    fleet_op_reboot_step($rop, array('boot_time' => 1050), 1070) === array('done', 'Back online after 1 min 10 s', 100) &&
    fleet_op_reboot_step($rop, null, 1000 + 60 * fleet_opt('reboot_timeout') + 1)[0] === 'failed', 'a reboot is done only when the box answers with a new boot time');
check((fleet_op_reboot_step($rop, array('boot_time' => 900), 1000 + 60 * fleet_opt('reboot_timeout'))[0] ?? '') === 'running' &&
    (fleet_op_reboot_step($rop, array('boot_time' => 900), 1000 + 60 * fleet_opt('reboot_timeout') + 1)[0] ?? '') === 'failed' &&
    (fleet_op_reboot_step($rop, array('boot_time' => 1050), 1000 + 60 * fleet_opt('reboot_timeout') + 1)[0] ?? '') === 'done',
    'a firewall that answers but never restarts fails the reboot after the timeout instead of waiting for ever (the group runner then stops)');
check(fleet_op_duration(45) === '45 s' && fleet_op_duration(120) === '2 min' && fleet_op_duration(-3) === '0 s', 'durations in words');
check(fleet_op_view(array('id' => 1, 'kind' => 'reboot', 'state' => 'done', 'text' => 'x', 'started' => 1, 'who' => 'a', 'finished' => 100), 100 + fleet_opt('show_done') + 1) === null &&
    fleet_op_view(array('id' => 1, 'kind' => 'reboot', 'state' => 'running', 'text' => 'x', 'started' => 1, 'who' => 'a', 'finished' => null), 99999)['state'] === 'running',
    'a finished operation leaves the tile after a moment; a running one stays');
$oid = fleet_op_start('node-op', 'reboot', 'Rebooting', 'tester');
check(fleet_op_running('node-op')['id'] == $oid && isset(fleet_ops_for_tiles(time())['node-op']), 'a running operation shows on its tile');
fleet_ops_follow(array('node_id' => 'node-op', 'label' => 'Op'), array('boot_time' => time() + 5), time() + 60);
check(fleet_op_running('node-op') === null && fleet_ops_for_tiles(time() + 60)['node-op']['state'] === 'done', 'the poll finishes the reboot when the box is back');
check(fleet_dashboard_data(array($row('node-op', 'Op', 'online')), 0, time(), array(), fleet_ops_for_tiles(time()))['boxes'][0]['op']['kind'] === 'reboot',
    'the tile data carries the operation');
