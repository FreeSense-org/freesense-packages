<?php
/* Fleet controller tests: an update is never queued twice for one firewall. Loaded by ../run.php (shares its variables). */

if (!function_exists('mwexec_bg')) {
	function mwexec_bg($cmd) { $GLOBALS['uq_bg'][] = $cmd; }
}
$uq_bg = array();
$uq_box = function (string $id) { return array('node_id' => $id, 'label' => $id, 'role' => 'managed', 'state' => 'online', 'status' => '{}'); };

check(fleet_op_update_busy('uq-a') === null, 'update busy: nothing on the firewall, nothing in the way');
$uq_g1 = fleet_op_group_start('update_group', 'Update Denmark', 'tester');
$uq_t1 = fleet_op_queue_update('uq-a', 'Waiting', 'tester', $uq_g1, $why);
check($uq_t1 !== null && $why === null && fleet_op_running('uq-a') === null, 'a free firewall gets its waiting update task, and is still not "running"');
check(fleet_op_update_busy('uq-a') === 'An update is already waiting (Update Denmark)', 'a waiting update stands in the way of a second update plan, naming the group');

/* a second group update for the same firewall: the plan leaves it out, and so does the launch if the plan was made before */
$uq_plan = fleet_boxes_plan(array($uq_box('uq-a')), 'update');
check(count($uq_plan['go']) === 0 && count($uq_plan['skip']) === 1 && strpos($uq_plan['skip'][0][1], 'Busy: an update is already waiting') === 0, 'a group update plan skips a firewall whose update is already waiting');
$uq_rb = fleet_boxes_plan(array($uq_box('uq-a')), 'reboot');
check(count($uq_rb['go']) === 1, 'a waiting update does not stop a reboot plan (a waiting task is not busy)');

$uq_g2 = fleet_op_group_start('update_group', 'Update everything', 'tester');
$uq_t2 = fleet_op_queue_update('uq-a', 'Waiting', 'tester', $uq_g2, $why);
check($uq_t2 === null && strpos((string)$why, 'An update is already waiting') === 0, 'queueing a second update task for the same firewall is refused');
$uq_before = (int)fleet_db()->query("SELECT COUNT(*) FROM ops WHERE node_id = 'uq-a' AND kind = 'update'")->fetchColumn();
$uq_stale = array('go' => array($uq_box('uq-a'), $uq_box('uq-b')), 'skip' => array());
$uq_op = fleet_group_op_launch('Everything', 'update', $uq_stale, 'tester');
$uq_rows = fleet_db()->query('SELECT node_id, state FROM ops WHERE parent = ' . $uq_op . ' ORDER BY node_id')->fetchAll(PDO::FETCH_KEY_PAIR);
check($uq_rows === array('uq-a' => 'skipped', 'uq-b' => 'queued') &&
    (int)fleet_db()->query("SELECT COUNT(*) FROM ops WHERE node_id = 'uq-a' AND kind = 'update' AND state = 'queued'")->fetchColumn() === 1 &&
    ((int)fleet_db()->query("SELECT COUNT(*) FROM ops WHERE node_id = 'uq-a' AND kind = 'update'")->fetchColumn() === $uq_before + 1),
    'a launch from an older plan skips the firewall that was queued meanwhile (the skip is recorded, no second queued task) and queues the free one');

/* a rollout: same rule */
$uq_ro = fleet_rollout_start(array('rings' => array(array(0, 'Everyone else', null, array($uq_box('uq-a'), $uq_box('uq-c')))), 'skip' => array()), '1.2.0', 0, 'tester');
$uq_rr = fleet_db()->query('SELECT node_id, state FROM ops WHERE parent = ' . $uq_ro . ' ORDER BY node_id')->fetchAll(PDO::FETCH_KEY_PAIR);
check($uq_rr === array('uq-a' => 'skipped', 'uq-c' => 'queued'), 'a rollout queues only the firewalls with no update waiting or running');

/* once the waiting task is over, the firewall can be planned again */
fleet_op_set($uq_t1, 'done', 'Updated');
check(fleet_op_update_busy('uq-a') === null, 'when the waiting update is over the firewall can be planned again');
