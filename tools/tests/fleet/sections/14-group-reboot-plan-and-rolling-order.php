<?php
/* Fleet controller tests: group reboot: plan and rolling order. Loaded by ../run.php (shares its variables). */

check(fleet_rolling_next(array('queued', 'queued')) === array('do' => 'start', 'index' => 0) &&
    fleet_rolling_next(array('done', 'running', 'queued')) === array('do' => 'wait') &&
    fleet_rolling_next(array('done', 'done', 'queued')) === array('do' => 'start', 'index' => 2) &&
    fleet_rolling_next(array('done', 'failed', 'queued')) === array('do' => 'stop') &&
    fleet_rolling_next(array('done', 'skipped', 'done')) === array('do' => 'done') && fleet_rolling_next(array()) === array('do' => 'done'),
    'one at a time; the first failure stops the rest');
$plan = fleet_group_reboot_plan(array(
    array('node_id' => 'b', 'label' => 'Bravo', 'role' => 'managed', 'state' => 'online'),
    array('node_id' => 'a', 'label' => 'alpha', 'role' => 'managed', 'state' => 'degraded'),
    array('node_id' => 'm', 'label' => 'Mon', 'role' => 'monitor', 'state' => 'online'),
    array('node_id' => 'o', 'label' => 'Off', 'role' => 'managed', 'state' => 'offline'),
    array('node_id' => 'x', 'label' => 'Busy', 'role' => 'managed', 'state' => 'online')), array('x' => 'Backing up'));
check(array_column($plan['go'], 'node_id') === array('a', 'b') &&
    array_map(function ($s) { return $s[1]; }, $plan['skip']) === array('Busy: backing up', 'Monitor only: the controller may not change it', 'Offline'),
    'the review lists who reboots in order and who is left alone and why');
$rop = fleet_op_group_start('reboot_group', 'Reboot Canary', 'tester');
$ra = fleet_op_start('node-ra', 'reboot', 'Waiting', 'tester', $rop, 'queued');
check(fleet_rolling_next(array_column(fleet_op_tasks($rop), 'state'))['index'] === 0, 'tasks run in the order they were planned');
fleet_db()->prepare("UPDATE ops SET state = 'running', text = 'Rebooting', started = ? WHERE id = ?")->execute(array(time() - 30, $ra));
fleet_ops_follow(array('node_id' => 'node-ra', 'label' => 'RA'), array('boot_time' => time()), time());
check(fleet_op_group_update($rop)['finished'] === 1 && fleet_ops_history(1)[0]['text'] === 'Done', 'the poll finishes a group task the same way as a single reboot');

check(strpos(fleet_progress_bar('running', null, 'x'), 'data-indeterminate') !== false && strpos(fleet_progress_bar('running', 40, 'x'), 'aria-valuenow="40"') !== false &&
    strpos(fleet_progress_bar('done', null, 'x'), 'width: 100%') !== false, 'one bar: sliding when unknown, filling when known, full when over');
$pop = fleet_op_start('node-pg', 'reboot', 'Rebooting', 'tester');
fleet_op_set($pop, 'running', 'Restarting', 50);
fleet_op_set($pop, 'running', 'Still restarting');
check(fleet_ops_for_tiles(time())['node-pg']['progress'] === 50, 'progress is kept when a step does not say');
fleet_op_set($pop, 'done', 'Back');
check(fleet_ops_for_tiles(time())['node-pg']['progress'] === 100, 'a finished operation is at 100');
