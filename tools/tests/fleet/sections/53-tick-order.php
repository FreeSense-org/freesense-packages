<?php
/* Fleet controller tests: ticks visit the firewall checked longest ago first. Loaded by ../run.php (shares its variables). */

$tb = array(array('node_id' => 'a'), array('node_id' => 'b'), array('node_id' => 'c'), array('node_id' => 'd'));
check(array_column(fleet_oldest_first($tb, array('a' => 500, 'b' => 100, 'c' => 300)), 'node_id') === array('d', 'b', 'c', 'a') &&
    array_column(fleet_oldest_first($tb, array()), 'node_id') === array('a', 'b', 'c', 'd'),
    'the firewall checked longest ago (or never) is visited first, the host order breaks ties, so a tick that runs out of time rotates through the fleet');
