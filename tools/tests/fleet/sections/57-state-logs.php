<?php
/* Fleet controller tests: the state history read for many firewalls at once. Loaded by ../run.php (shares its variables). */

$sl = fleet_db();
$sl->exec('DELETE FROM state_log');
$sl->exec("INSERT INTO state_log (node_id, time, state) VALUES ('sl-a', 10, 'online'), ('sl-a', 100, 'offline'), ('sl-a', 200, 'online'), ('sl-a', 300, 'degraded'), ('sl-b', 50, 'online')");
$lg = fleet_stats_logs(array(array('node_id' => 'sl-a'), array('node_id' => 'sl-b'), array('node_id' => 'sl-c')), 150, 250);
check(($lg['sl-a'] === array('offline', array(array(200, 'online')))) && ($lg['sl-b'] === array('online', array())) && ($lg['sl-c'] === array(null, array())) &&
    (fleet_stats_logs(array(), 0, 100) === array()), 'the state before the range and the changes inside it, for many firewalls in two queries');
$many = array();
for ($i = 0; $i < 1200; $i++) {
	$many[] = array('node_id' => "sl-m{$i}");
}
check(count(fleet_stats_logs($many, 0, 100)) === 1200, 'a thousand firewalls are read in chunks');
$sl->exec('DELETE FROM state_log');
