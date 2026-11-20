<?php
/* Fleet controller tests: schedules. Loaded by ../run.php (shares its variables). */

$sc = fleet_schedule_from(array('name' => 'Nightly Retail', 'kind' => 'backup', 'group_id' => '2', 'days' => array('1', '2', '3', '4', '5', '6', '7'), 'time' => '02:30', 'enabled' => '1'));
check($sc['time'] === 150 && $sc['days'] === array(1, 2, 3, 4, 5, 6, 7) && $sc['enabled'] && fleet_schedule_text($sc) === 'Every day 02:30', 'a schedule from the form');
try {
	fleet_schedule_from(array('name' => 'x', 'kind' => 'format', 'days' => array(1), 'time' => '02:00'));
	check(false, 'an unknown job is refused');
} catch (InvalidArgumentException $e) {
}
$utc = function ($s) { return (new DateTimeImmutable($s, new DateTimeZone('UTC')))->getTimestamp(); };
$sun = array('days' => array(7), 'time' => 240);
check(fleet_schedule_due($sun, $utc('2026-10-11 00:00'), $utc('2026-10-18 04:03'), 900) === array('run', $utc('2026-10-18 04:00')), 'due a few minutes after its time');
check(fleet_schedule_due($sun, $utc('2026-10-18 04:00'), $utc('2026-10-18 04:05'), 900) === null, 'runs once');
check(fleet_schedule_due($sun, $utc('2026-10-11 00:00'), $utc('2026-10-18 09:00'), 900) === array('missed', $utc('2026-10-18 04:00')), 'too late: missed, not run late');
check(fleet_schedule_due($sun, $utc('2026-10-18 03:00'), $utc('2026-10-18 03:59'), 900) === null, 'not before its time');
check(fleet_schedule_next($sun, $utc('2026-10-18 04:00')) === $utc('2026-10-25 04:00') && fleet_schedule_next($sc, $utc('2026-10-16 03:00')) === $utc('2026-10-17 02:30'), 'next run');

$s1 = fleet_schedule_from(array('name' => 'Edge', 'kind' => 'reboot', 'targets' => array('n:node-abc', 'g:2', 'g:2'), 'days' => array(7), 'time' => '04:00'));
check($s1['targets'] === array('g:2', 'n:node-abc') && fleet_targets_from(array('g:1', 'all')) === array('all') && fleet_targets_from('n:x') === array('n:x'),
    'targets: any mix of groups and firewalls, no repeats; All wins');
foreach (array(array(), array('x:1'), array('n:a b')) as $bad) {
	try {
		fleet_targets_from($bad);
		check(false, 'bad targets are refused');
	} catch (InvalidArgumentException $e) {
	}
}
$tb = array(array('node_id' => 'a', 'label' => 'A'), array('node_id' => 'b', 'label' => 'B'), array('node_id' => 'c', 'label' => 'C'));
list($tl, $tg) = fleet_targets_resolve(array('g:1', 'g:9', 'n:c', 'n:gone'), $tb, array(1 => array('a', 'c')));
check(array_column($tl, 'node_id') === array('a', 'c') && $tg === array('g:9', 'n:gone') && count(fleet_targets_resolve(array('all'), $tb, array())[0]) === 3,
    'targets resolve to each firewall once and name what no longer exists');
check(fleet_targets_text(array('g:1', 'n:c', 'n:gone'), array('g:1' => 'Canary', 'n:c' => 'C')) === 'Canary, C, removed firewall', 'targets as text');
