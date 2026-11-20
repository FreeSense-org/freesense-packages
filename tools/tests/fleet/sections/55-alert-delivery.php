<?php
/* Fleet controller tests: alert delivery (the worker's part). Loaded by ../run.php (shares its variables). */

if (!function_exists('config_get_path')) {
	/* The System's configuration is not here: the controller's settings are the defaults. */
	function config_get_path($path, $default = null) {
		return $default;
	}
}
$ad = fleet_db();
$ad->exec('DELETE FROM alerts; DELETE FROM alert_channels');
$anow = time();
/* pure parts */
check((fleet_alert_next_try(0, 1000) === 1060) && (fleet_alert_next_try(1, 1000) === 1120) && (fleet_alert_next_try(3, 1000) === 1480) && (fleet_alert_next_try(30, 1000) === 4600),
    'a failed alert is tried again after 1, 2, 4, 8 ... minutes, at most an hour apart');
$dm = fleet_alerts_digest_message(array(array('severity' => 'warning', 'text' => 'one'), array('severity' => 'critical', 'text' => 'two')) + array_fill(2, 20, array('severity' => 'info', 'text' => 'x')), 1000);
check(($dm['severity'] === 'critical') && ($dm['title'] === '22 alerts from FreeSense Fleet') && (substr_count($dm['text'], "\n") === 15) && (strpos($dm['text'], 'and 7 more') !== false), 'a burst becomes one message: the worst severity, the first lines, how many more');
$chs = array(array('id' => 1, 'enabled' => 1, 'events' => array('offline'), 'min_severity' => 'info'), array('id' => 2, 'enabled' => 1, 'events' => array('op_failed'), 'min_severity' => 'info'));
$rows = array(array('id' => 10, 'event' => 'offline', 'severity' => 'critical', 'sent' => '{}', 'channel' => null), array('id' => 11, 'event' => 'offline', 'severity' => 'critical', 'sent' => '{"1":"ok"}', 'channel' => null),
    array('id' => 12, 'event' => 'op_failed', 'severity' => 'warning', 'sent' => '{}', 'channel' => null));
$pl = fleet_alerts_plan($rows, $chs, 1);
check((array_keys($pl) === array(1, 2)) && ($pl[1][0] === false) && (array_column($pl[1][1], 'id') === array(10)) && (array_column($pl[2][1], 'id') === array(12)) &&
    (fleet_alerts_plan(array($rows[0], array('id' => 13) + $rows[0]), $chs, 1)[1][0] === true), 'what each channel is to get: not what it did not choose, not what it already has; more than the limit is a digest');

/* a webhook receiver on this machine */
$sink = "{$data}/sink.txt";
$port = 18000 + (getmypid() % 1000);
putenv("SINK_FILE={$sink}");
$srv = proc_open(array(PHP_BINARY, '-S', "127.0.0.1:{$port}", __DIR__ . '/../webhook-sink.php'), array(0 => array('file', '/dev/null', 'r'), 1 => array('file', '/dev/null', 'w'), 2 => array('file', '/dev/null', 'w')), $spipes);
for ($i = 0; $i < 50; $i++) {
	if (($c = @fsockopen('127.0.0.1', $port, $en, $es, 0.2)) !== false) {
		fclose($c);
		break;
	}
	usleep(100000);
}
$cid1 = fleet_alert_channel_save(null, array('name' => 'Sink', 'type' => 'webhook', 'cfg_url' => "http://127.0.0.1:{$port}/hook", 'events' => array('offline'), 'enabled' => '1'), 'test');
$sent = function () use ($sink): array {
	return is_file($sink) ? array_values(array_filter(explode("\n", (string)file_get_contents($sink)))) : array();
};
fleet_alert('offline', 'n-ad-0001', 'Shop 1 is offline');
fleet_alert('offline', 'n-ad-0002', 'Shop 2 is offline');
fleet_alerts_deliver($anow);
$s1 = $sent();
check((count($s1) === 2) && ((int)$ad->query('SELECT COUNT(*) FROM alerts WHERE done = 1')->fetchColumn() === 2), 'the worker sends each alert to the channel and marks it done');
fleet_alerts_deliver($anow);
check(count($sent()) === 2, 'and does not send them again');

/* A burst goes out as one summary. */
@unlink($sink);
for ($i = 1; $i <= 10; $i++) {
	fleet_alert('offline', sprintf('n-ad-b%03d', $i), "Burst {$i} is offline");
}
fleet_alerts_deliver($anow);
$s2 = $sent();
check((count($s2) === 1) && (strpos($s2[0], '10 alerts from FreeSense Fleet') !== false) && ((int)$ad->query('SELECT COUNT(*) FROM alerts WHERE done = 0')->fetchColumn() === 0),
    'ten alerts for one channel go out as one summary and are all marked done');

/* Old alerts nobody tried to send are dropped, not sent to a channel that came later. */
@unlink($sink);
$old = fleet_alert('offline', 'n-ad-old1', 'Old news');
$ad->prepare('UPDATE alerts SET time = ? WHERE id = ?')->execute(array($anow - FLEET_ALERT_MAX_AGE - 10, $old));
fleet_alerts_deliver($anow);
check((count($sent()) === 0) && ($ad->query("SELECT done FROM alerts WHERE id = {$old}")->fetchColumn() == 1) && (strpos((string)$ad->query("SELECT sent FROM alerts WHERE id = {$old}")->fetchColumn(), 'expired') !== false),
    'an alert nobody ever tried to send that is over an hour old is dropped, not sent late');

/* A channel that does not answer: tried again later and later, not every minute. */
$ad->exec('DELETE FROM alerts; DELETE FROM alert_channels');
$cid2 = fleet_alert_channel_save(null, array('name' => 'Dead', 'type' => 'webhook', 'cfg_url' => 'http://127.0.0.1:1/hook', 'events' => array('offline'), 'enabled' => '1'), 'test');
$dead = fleet_alert('offline', 'n-ad-dead', 'Nobody listens');
fleet_alerts_deliver($anow);
$r1 = $ad->query("SELECT tries, done, next_try FROM alerts WHERE id = {$dead}")->fetch();
fleet_alerts_deliver($anow + 30);
$r2 = $ad->query("SELECT tries FROM alerts WHERE id = {$dead}")->fetchColumn();
fleet_alerts_deliver($anow + 61);
$r3 = $ad->query("SELECT tries, next_try FROM alerts WHERE id = {$dead}")->fetch();
check(((int)$r1['tries'] === 1) && ((int)$r1['done'] === 0) && ((int)$r1['next_try'] === $anow + 60) && ((int)$r2 === 1) && ((int)$r3['tries'] === 2) && ((int)$r3['next_try'] === $anow + 61 + 120),
    'a failed send waits 1, then 2 minutes before it is tried again');
for ($i = 0; $i < 12; $i++) {
	fleet_alerts_deliver($anow + 100000 + 4000 * $i);
}
check((int)$ad->query("SELECT tries FROM alerts WHERE id = {$dead}")->fetchColumn() === FLEET_ALERT_TRIES, 'and it is given up after the set number of tries');

/* The time budget stops a run. */
$ad->exec('DELETE FROM alerts');
fleet_alert('offline', 'n-ad-bud1', 'Budget 1');
fleet_alerts_deliver($anow, -1.0);
check((int)$ad->query('SELECT tries FROM alerts')->fetchColumn() === 0, 'a run whose time is used up sends nothing and counts no try');
proc_terminate($srv);
proc_close($srv);
$ad->exec('DELETE FROM alerts; DELETE FROM alert_channels');
@unlink($sink);
