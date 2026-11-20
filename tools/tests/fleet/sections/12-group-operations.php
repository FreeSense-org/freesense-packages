<?php
/* Fleet controller tests: group operations. Loaded by ../run.php (shares its variables). */

check(fleet_op_progress(array('done', 'failed', 'running', 'queued')) === array('total' => 4, 'finished' => 2, 'failed' => 1, 'skipped' => 0, 'percent' => 50) &&
    fleet_op_progress(array())['percent'] === 100, 'group progress counts finished tasks');
check(fleet_op_summary(array('total' => 8, 'finished' => 5, 'failed' => 0), false) === '5 of 8 done' && fleet_op_summary(array('total' => 8, 'finished' => 8, 'failed' => 0), true) === 'All 8 done' &&
    fleet_op_summary(array('total' => 8, 'finished' => 8, 'failed' => 2), true) === '2 of 8 failed', 'group progress in words');
check(fleet_op_summary(array('total' => 3, 'finished' => 3, 'failed' => 1, 'skipped' => 2), true) === '1 of 3 failed, 2 left alone', 'a stopped rolling operation says what was left alone');
$gop = fleet_op_group_start('backup_all', 'Back up Denmark', 'tester');
$t1 = fleet_op_start('node-ga', 'backup', 'Waiting', 'tester', $gop, 'queued');
$t2 = fleet_op_start('node-gb', 'backup', 'Waiting', 'tester', $gop, 'queued');
check(fleet_op_running('node-ga') === null && fleet_ops_for_tiles(time())['node-ga']['state'] === 'queued' && fleet_ops_groups_running()[0]['title'] === 'Back up Denmark' &&
    !isset(fleet_ops_for_tiles(time())['']), 'a waiting task shows on its tile but does not make the firewall busy; the group shows in the strip, not as a tile');
fleet_op_set($t1, 'done', 'Backed up and checked');
check(fleet_op_group_update($gop)['finished'] === 1 && fleet_ops_groups_running()[0]['text'] === '1 of 2 done', 'progress after one task');
fleet_op_set($t2, 'failed', 'Backup failed: x');
fleet_op_group_update($gop);
check(fleet_ops_groups_running() === array() && fleet_ops_history(5)[0]['state'] === 'failed' && fleet_ops_history(5)[0]['text'] === '1 of 2 failed' &&
    count(fleet_op_tasks($gop)) === 2 && fleet_op_tasks($gop)[0]['state'] === 'failed', 'a group with a failed task ends failed; failures listed first; tasks are not in the history');

check(fleet_event_text('n', 'reboot_done', 'n (L): Back online after 1 min 22 s') === array('Back online', 'after 1 min 22 s'), 'a finished reboot in words');
check(fleet_op_progress(array('done', 'running', 'queued', 'queued'), array(50))['percent'] === 37, 'a firewall half way moves the group bar');
