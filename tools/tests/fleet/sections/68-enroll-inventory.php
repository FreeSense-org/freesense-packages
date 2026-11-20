<?php
/* Fleet controller tests: enrollment inventory bounds. Loaded by ../run.php (shares its variables). */

$big = array('serial' => 'S1', 'hostname' => "fw\n1", 'x-bad' => 'a', 'nested' => array(1), 'long' => str_repeat('a', 900));
for ($i = 0; $i < 40; $i++) {
	$big["k{$i}"] = 'v';
}
$clean = fleet_enroll_inventory_clean($big);
check(count($clean) === 24 && $clean['serial'] === 'S1' && $clean['hostname'] === 'fw1' && !isset($clean['x-bad']) && !isset($clean['nested']) && strlen($clean['long']) === 200,
    'enrollment inventory: bounded, scalar, no control characters');
check(fleet_enroll_inventory_clean('x') === array(), 'enrollment inventory: not a list gives nothing');
