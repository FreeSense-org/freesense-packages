<?php
/* Fleet controller tests: a schedule that cannot start is recorded and tried again. Loaded by ../run.php (shares its variables). */

$sx = fleet_db();
$sx->exec('DELETE FROM schedules; DELETE FROM alerts');
$sx->exec("INSERT OR IGNORE INTO boxes (node_id, name, label, host_no, overlay, wg_pub, api_key, cert_sha256, role, joined, state) VALUES ('n-sf-0001', 'sf', 'Sf', 902, 'x', 'wgsf1', 'k', 'c', 'managed', 1, 'online')");
$sid = fleet_schedule_save(null, array('name' => 'Every minute test', 'kind' => 'backup', 'targets' => array('all'), 'days' => array(1, 2, 3, 4, 5, 6, 7), 'time' => '00:00', 'enabled' => '1'), 'tester');
$at = (new DateTimeImmutable('today', new DateTimeZone(fleet_tz())))->getTimestamp();
$sx->prepare('UPDATE schedules SET last_run = 0 WHERE id = ?')->execute(array($sid));
/* It is due (just after midnight), and starting it fails here (no way to start the backup process in the test): */
fleet_schedules_tick($at + 60);
$row = $sx->query("SELECT last_run, last_result FROM schedules WHERE id = {$sid}")->fetch();
check((int)$row['last_run'] === 0 && (strpos((string)$row['last_result'], 'Failed:') === 0), 'a schedule that could not start keeps its last run, so the next minute tries again');
check(((int)$sx->query("SELECT COUNT(*) FROM audit WHERE action = 'schedule_failed'")->fetchColumn() === 1) && ((int)$sx->query("SELECT COUNT(*) FROM alerts WHERE event = 'op_failed'")->fetchColumn() === 1),
    'and the failure is in the audit log and raises an alert');
fleet_schedules_tick($at + 120);
check((int)$sx->query("SELECT COUNT(*) FROM audit WHERE action = 'schedule_failed'")->fetchColumn() === 2, 'it is tried again a minute later');
fleet_schedules_tick($at + 60 * fleet_opt('schedule_grace') + 600);
check((string)$sx->query("SELECT last_result FROM schedules WHERE id = {$sid}")->fetchColumn() !== '' && ((int)$sx->query("SELECT last_run FROM schedules WHERE id = {$sid}")->fetchColumn() > 0) &&
    (strpos((string)$sx->query("SELECT last_result FROM schedules WHERE id = {$sid}")->fetchColumn(), 'Missed') === 0), 'after the grace time it is recorded as missed, not tried for ever');
$sx->exec("DELETE FROM schedules; DELETE FROM alerts; DELETE FROM boxes WHERE node_id = 'n-sf-0001'");
