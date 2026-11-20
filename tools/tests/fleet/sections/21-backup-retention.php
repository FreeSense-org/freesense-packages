<?php
/* Fleet controller tests: backup retention. Loaded by ../run.php (shares its variables). */

$day = 86400;
$now0 = (new DateTimeImmutable('2026-10-16 12:00:00', new DateTimeZone('UTC')))->getTimestamp();
$rows = array();
for ($i = 0; $i < 60; $i++) {
	/* two backups a day for 30 days, newest first */
	$rows[] = array('id' => 100 + $i, 'time' => $now0 - (int)($i * $day / 2), 'reason' => 'change', 'pinned' => 0);
}
$rows[] = array('id' => 900, 'time' => $now0 - 200 * $day, 'reason' => 'manual', 'pinned' => 1);
$rows[] = array('id' => 901, 'time' => $now0 - 3 * $day - 3600, 'reason' => 'safety', 'pinned' => 0);
$rows[] = array('id' => 902, 'time' => $now0 - 90 * $day, 'reason' => 'safety', 'pinned' => 0);
$k = fleet_backup_keep($rows, array(array('last' => 3, 'daily' => 7, 'weekly' => 0, 'monthly' => 0)), $now0, 30);
check(isset($k[100], $k[101], $k[102]) && $k[100] === 'Newest' && $k[900] === 'Pinned' && $k[901] === 'Safety backup' && !isset($k[902]), 'newest, pinned and recent safety backups are kept; old safety ones are not');
$daily = array_keys(array_filter($k, function ($w) { return $w === 'Daily'; }));
check(count($daily) === 5 && !isset($k[116]), 'one a day for 7 days (days already kept by "last" count), nothing older');
$k2 = fleet_backup_keep($rows, array(array('last' => 1, 'daily' => 0, 'weekly' => 0, 'monthly' => 0), array('last' => 1, 'daily' => 0, 'weekly' => 3, 'monthly' => 0)), $now0, 30);
check(count(array_filter($k2, function ($w) { return $w === 'Weekly'; })) === 2 && count($k2) === 5, 'several sets: the union of their rules (weekly picks the newest of each week)');
check(fleet_backup_keep(array(), array(fleet_keep_rule_from(array('keep_last' => '1', 'keep_daily' => '0', 'keep_weekly' => '0', 'keep_monthly' => '0'))), $now0, 30) === array(), 'nothing to keep in an empty list');
try {
	fleet_keep_rule_from(array('keep_last' => '0', 'keep_daily' => '1', 'keep_weekly' => '1', 'keep_monthly' => '1'));
	check(false, 'keep at least one');
} catch (InvalidArgumentException $e) {
}
check(fleet_keep_rule_text(array('last' => 10, 'daily' => 14, 'weekly' => 0, 'monthly' => 12)) === 'last 10, 14 daily, 12 monthly', 'rule as text');
