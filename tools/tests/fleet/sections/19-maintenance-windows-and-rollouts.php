<?php
/* Fleet controller tests: maintenance windows and rollouts. Loaded by ../run.php (shares its variables). */

$w = fleet_window_from(array('name' => 'Nights', 'days' => array('1', '2', '3', '4', '5', '9'), 'start' => '23:00', 'length' => '180'));
check($w === array('name' => 'Nights', 'days' => array(1, 2, 3, 4, 5), 'start' => 1380, 'length' => 180) && fleet_window_text($w) === 'Mon-Fri 23:00, 3 h', 'a window from the form');
foreach (array(array('name' => ''), array('name' => 'x', 'days' => array()), array('name' => 'x', 'days' => array(1), 'start' => '25:00'),
    array('name' => 'x', 'days' => array(1), 'start' => '01:00', 'length' => '10')) as $bad) {
	try {
		fleet_window_from($bad + array('days' => array(1), 'start' => '01:00', 'length' => '60'));
		check(false, 'a bad window is refused');
	} catch (InvalidArgumentException $e) {
	}
}
/* 2026-10-16 is a Friday. */
$fri2330 = (new DateTimeImmutable('2026-10-16 23:30:00', new DateTimeZone('Europe/Copenhagen')))->getTimestamp();
$sat0130 = $fri2330 + 2 * 3600;
$sat0300 = $fri2330 + 3.5 * 3600;
check(fleet_window_state($w, $fri2330, 'Europe/Copenhagen') === array(true, 9000) && fleet_window_state($w, $sat0130, 'Europe/Copenhagen') === array(true, 1800) &&
    fleet_window_state($w, (int)$sat0300, 'Europe/Copenhagen') === array(false, 0), 'a window running past midnight is open the next morning, then closes');
check(fleet_window_next($w, (int)$sat0300, 'Europe/Copenhagen') === (new DateTimeImmutable('2026-10-19 23:00:00', new DateTimeZone('Europe/Copenhagen')))->getTimestamp(),
    'after Friday night the next window is Monday night');
check(fleet_rollout_rings(array(3, 1, 0), array(3 => array('a', 'b'), 1 => array('b', 'c', 'x')), array('a', 'b', 'c', 'd')) === array(array('a', 'b'), array('c'), array('d')),
    'rings: a firewall goes in the first ring that has it; the last ring is everyone else');
$open = array('name' => 'Always', 'days' => array(1, 2, 3, 4, 5, 6, 7), 'start' => 0, 'length' => 1440);
check(fleet_rollout_next(array(array(null, array('done', 'queued'))), array(), 1000, 86400, 3600) === array('do' => 'start', 'ring' => 0, 'task' => 1), 'next firewall in the ring');
check(fleet_rollout_next(array(array(null, array('done', 'running'))), array(), 1000, 86400, 3600)['do'] === 'wait', 'one at a time');
check(fleet_rollout_next(array(array(null, array('failed', 'queued'))), array(), 1000, 86400, 3600) === array('do' => 'pause', 'ring' => 0), 'a failure pauses the rollout');
check(fleet_rollout_next(array(array(null, array('done')), array(null, array('queued'))), array(0 => 1000), 2000, 86400, 3600) === array('do' => 'wait', 'why' => 'Waiting before the next ring', 'until' => 87400) &&
    fleet_rollout_next(array(array(null, array('done')), array(null, array('queued'))), array(0 => 1000), 87400, 86400, 3600)['do'] === 'start', 'the next ring waits for the gap');
$late = fleet_rollout_next(array(array($w, array('queued'))), array(), (int)($sat0130), 0, 3600, 'Europe/Copenhagen');
check($late['do'] === 'wait' && $late['why'] === 'Waiting for the maintenance window' && $late['until'] === (new DateTimeImmutable('2026-10-19 23:00:00', new DateTimeZone('Europe/Copenhagen')))->getTimestamp(),
    'an update is not started when the window has too little time left');
check(fleet_rollout_next(array(array($open, array('done', 'skipped')), array(null, array())), array(), 1000, 0, 3600) === array('do' => 'done'), 'all rings done');
