<?php
/* Fleet controller tests: operations that die, cancelling and claiming. Loaded by ../run.php (shares its variables). */

$od = fleet_db();
$od->exec('DELETE FROM ops; DELETE FROM rollouts');
$onow = time();
$long = 100000;
/* Stale limits follow the settings. */
check((fleet_op_stale_limit('backup') === 1800) && (fleet_op_stale_limit('update') === 60 * (fleet_opt('update_timeout') + fleet_opt('update_healthy')) + 1800) &&
    (fleet_op_stale_limit('reboot') >= 1800) && (fleet_op_stale_limit('restore') === 60 * fleet_opt('restore_confirm') + 1800), 'how long an operation may go without progress, by kind');

/* Claim: only one caller gets a queued task, and a cancelled one stays skipped. */
$t1 = fleet_op_start('n-od-0001', 'update', 'Waiting', 'w', null, 'queued');
check(fleet_op_claim($t1) && !fleet_op_claim($t1), 'a queued task can be claimed once');
$t2 = fleet_op_start('n-od-0002', 'update', 'Waiting', 'w', null, 'queued');
fleet_op_set($t2, 'skipped', 'Skipped: cancelled');
check(!fleet_op_claim($t2), 'a cancelled task cannot be claimed');
fleet_op_fail_open($t2, 'Update refused: x');
fleet_op_fail_open($t1, 'Update refused: y');
$st = $od->query('SELECT id, state FROM ops ORDER BY id')->fetchAll(PDO::FETCH_KEY_PAIR);
check(($st[$t2] === 'skipped') && ($st[$t1] === 'failed'), 'a task that was cancelled meanwhile stays skipped when the caller reports a failure');

/* A firewall with something running refuses a second start; another firewall does not. */
$g1 = fleet_op_start_guarded('n-od-0003', 'backup', 'Backing up', 'w');
$refused = null;
try {
	fleet_op_start_guarded('n-od-0003', 'restore', 'Starting', 'w');
} catch (RuntimeException $e) {
	$refused = $e->getMessage();
}
check(($refused !== null) && (fleet_op_start_guarded('n-od-0004', 'backup', 'Backing up', 'w') > $g1) && (fleet_op_running('n-od-0003', $g1) === null) && (fleet_op_running('n-od-0003')['id'] === $g1),
    'a firewall with an operation running refuses another; the running one is not "other" to itself');

/* The reaper: a stuck operation fails, a fresh one and a rollout's do not. */
$od->exec('DELETE FROM ops');
$stuck = fleet_op_start('n-od-0005', 'backup', 'Backing up', 'w');
$fresh = fleet_op_start('n-od-0006', 'backup', 'Backing up', 'w');
$od->prepare('UPDATE ops SET updated = ? WHERE id = ?')->execute(array($onow - 3600, $stuck));
$grp = fleet_op_group_start('template', 'Apply template X', 'w');
$run = fleet_op_start('n-od-0007', 'template', 'Applying', 'w', $grp, 'running');
$wait1 = fleet_op_start('n-od-0008', 'template', 'Waiting', 'w', $grp, 'queued');
$wait2 = fleet_op_start('n-od-0009', 'template', 'Waiting', 'w', $grp, 'queued');
$od->prepare('UPDATE ops SET updated = ? WHERE id IN (?, ?, ?, ?)')->execute(array($onow - 3600, $grp, $run, $wait1, $wait2));
$rgrp = fleet_op_group_start('rollout', 'Roll out 1.2', 'w');
$rrun = fleet_op_start('n-od-0010', 'update', 'Updating', 'w', $rgrp, 'running');
$od->prepare('UPDATE ops SET updated = ? WHERE id IN (?, ?)')->execute(array($onow - 999999, $rgrp, $rrun));
$od->prepare("INSERT INTO rollouts (op_id, target, rings, state, gap, who, created) VALUES (?, 'x', '[]', 'running', 0, 'w', ?)")->execute(array($rgrp, $onow));
$failed = fleet_ops_reap($onow);
$s = $od->query('SELECT id, state FROM ops')->fetchAll(PDO::FETCH_KEY_PAIR);
check(($failed === 2) && ($s[$stuck] === 'failed') && ($s[$fresh] === 'running') && ($s[$run] === 'failed') && ($s[$wait1] === 'skipped') && ($s[$wait2] === 'skipped') && ($s[$grp] === 'failed') &&
    ($s[$rgrp] === 'running') && ($s[$rrun] === 'running'),
    'the reaper fails stuck operations and skips what a dead runner left waiting; fresh ones and rollouts are left alone');
check(strpos((string)$od->query("SELECT text FROM ops WHERE id = {$stuck}")->fetchColumn(), 'Stopped: no progress') === 0, 'and says why');

/* A live runner (its lock is held) is never reaped. */
$grp2 = fleet_op_group_start('users', 'Sync users', 'w');
$run2 = fleet_op_start('n-od-0011', 'users', 'Syncing', 'w', $grp2, 'running');
$od->prepare('UPDATE ops SET updated = ? WHERE id IN (?, ?)')->execute(array($onow - 3600, $grp2, $run2));
$lockfile = "/var/run/fleet-op-{$grp2}.lock";
$holder = fopen($lockfile, 'c');
flock($holder, LOCK_EX);
check(fleet_op_runner_alive($grp2) && (fleet_ops_reap($onow) === 0) && ($od->query("SELECT state FROM ops WHERE id = {$run2}")->fetchColumn() === 'running'), 'an operation whose runner holds its lock is not reaped');
flock($holder, LOCK_UN);
fclose($holder);
check(!fleet_op_runner_alive($grp2) && (fleet_ops_reap($onow) === 1), 'once the runner is gone it is');
@unlink($lockfile);

/* Cancelling. */
$od->exec('DELETE FROM ops');
$cg = fleet_op_group_start('update_group', 'Update Canary', 'w');
$crun = fleet_op_start('n-od-0012', 'update', 'Updating', 'w', $cg, 'running');
$cq1 = fleet_op_start('n-od-0013', 'update', 'Waiting', 'w', $cg, 'queued');
$cq2 = fleet_op_start('n-od-0014', 'update', 'Waiting', 'w', $cg, 'queued');
$cl = "/var/run/fleet-op-{$cg}.lock";
$ch = fopen($cl, 'c');
flock($ch, LOCK_EX);
$msg = fleet_op_cancel($cg, 'tester');
$s = $od->query('SELECT id, state FROM ops')->fetchAll(PDO::FETCH_KEY_PAIR);
check(($s[$cq1] === 'skipped') && ($s[$cq2] === 'skipped') && ($s[$crun] === 'running') && ($s[$cg] === 'running') && (strpos($msg, '2 waiting skipped') !== false),
    'cancelling a group with a live runner skips what waits; the firewall busy with its part finishes it');
flock($ch, LOCK_UN);
fclose($ch);
$msg = fleet_op_cancel($cg, 'tester');
$s = $od->query('SELECT id, state FROM ops')->fetchAll(PDO::FETCH_KEY_PAIR);
check(($s[$crun] === 'failed') && ($s[$cg] === 'failed'), 'cancelling it again when nothing runs it any more fails the stuck part so the firewall is free');
@unlink($cl);
$none = null;
try {
	fleet_op_cancel($cg, 'tester');
} catch (RuntimeException $e) {
	$none = $e->getMessage();
}
check($none === 'That action is not running any more.', 'a finished action cannot be cancelled');
$single = fleet_op_start('n-od-0015', 'backup', 'Backing up', 'w');
$young = null;
try {
	fleet_op_cancel($single, 'tester');
} catch (RuntimeException $e) {
	$young = $e->getMessage();
}
$od->prepare('UPDATE ops SET updated = ? WHERE id = ?')->execute(array($onow - 120, $single));
fleet_op_cancel($single, 'tester');
check(($young !== null) && ($od->query("SELECT state FROM ops WHERE id = {$single}")->fetchColumn() === 'failed') && (fleet_op_running('n-od-0015') === null),
    'a single action that just ran cannot be cancelled; one with no progress for a minute and no runner can');
/* A runner that died with an error: the group is settled. */
$od->exec('DELETE FROM ops');
$xg = fleet_op_group_start('template', 'Apply template Y', 'w');
$xr = fleet_op_start('n-od-0016', 'template', 'Applying', 'w', $xg, 'running');
$xq = fleet_op_start('n-od-0017', 'template', 'Waiting', 'w', $xg, 'queued');
fleet_op_runner_crashed($xg, 'Call to undefined function');
$s = $od->query('SELECT id, state FROM ops')->fetchAll(PDO::FETCH_KEY_PAIR);
check(($s[$xr] === 'failed') && ($s[$xq] === 'skipped') && ($s[$xg] === 'failed'), 'a runner that died with an uncaught error fails what it was doing and skips the rest');
$od->exec('DELETE FROM ops; DELETE FROM rollouts');

/* A runner taking its next task: not while the firewall is busy with something else, and not when the task was cancelled. */
$od->exec('DELETE FROM ops');
$bg = fleet_op_group_start('template', 'Apply template Z', 'w');
$busy_other = fleet_op_start('n-od-0020', 'update', 'Updating', 'w');
$ta = fleet_op_start('n-od-0020', 'template', 'Waiting', 'w', $bg, 'queued');
$tfree = fleet_op_start('n-od-0021', 'template', 'Waiting', 'w', $bg, 'queued');
$tcan = fleet_op_start('n-od-0022', 'template', 'Waiting', 'w', $bg, 'queued');
fleet_op_set($tcan, 'skipped', 'Skipped: cancelled');
$rows = $od->query("SELECT * FROM ops WHERE parent = {$bg}")->fetchAll();
$by = array_column($rows, null, 'id');
check(!fleet_op_begin_task($by[$ta]) && fleet_op_begin_task($by[$tfree]) && !fleet_op_begin_task($by[$tcan]), 'a task does not start on a busy firewall or after it was cancelled, otherwise it is claimed');
$s = $od->query('SELECT id, state, text FROM ops')->fetchAll(PDO::FETCH_UNIQUE | PDO::FETCH_ASSOC);
check(($s[$ta]['state'] === 'failed') && (strpos($s[$ta]['text'], 'Busy: updating') === 0) && ($s[$tfree]['state'] === 'running') && ($s[$tcan]['state'] === 'skipped'), 'and the reason is recorded');
$od->exec('DELETE FROM ops');

/* After a failure that makes going on unsafe the rest of a group is skipped. */
$od->exec('DELETE FROM ops');
$sg = fleet_op_group_start('template', 'Apply template W', 'w');
$sf = fleet_op_start('n-od-0030', 'template', 'Failed', 'w', $sg, 'running');
fleet_op_set($sf, 'failed', 'No answer');
$sq1 = fleet_op_start('n-od-0031', 'template', 'Waiting', 'w', $sg, 'queued');
$sq2 = fleet_op_start('n-od-0032', 'template', 'Waiting', 'w', $sg, 'queued');
$sd0 = fleet_op_start('n-od-0033', 'template', 'Done', 'w', $sg, 'running');
fleet_op_set($sd0, 'done', 'ok');
check((fleet_op_skip_rest($sg, 'Skipped: stopped after a failure on Shop. Apply again to the rest.') === 2) &&
    ($od->query("SELECT group_concat(state) FROM (SELECT state FROM ops WHERE parent = {$sg} ORDER BY id)")->fetchColumn() === 'failed,skipped,skipped,done') && ($od->query("SELECT state FROM ops WHERE id = {$sg}")->fetchColumn() === 'failed'),
    'after a failure the tasks still waiting are skipped with the reason and the group is settled');
$od->exec('DELETE FROM ops');
