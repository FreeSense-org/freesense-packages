<?php
/* Fleet controller tests: the list of firewalls of a backup run. Loaded by ../run.php (shares its variables). */

$nf = fleet_backup_nodes_write(array('n-one-0001', 'n-two-0002'));
check((decoct(fileperms($nf) & 0777) === '600') && (dirname($nf) === FLEET_DATA) && (fleet_backup_nodes_read($nf) === array('n-one-0001', 'n-two-0002')) && !is_file($nf),
    'the firewalls of a backup run go in a private file in the data folder, which is read once and removed');
file_put_contents(FLEET_DATA . '/other.json', '["x"]');
check((fleet_backup_nodes_read(FLEET_DATA . '/other.json') === array()) && (fleet_backup_nodes_read('/etc/passwd') === array()) && (fleet_backup_nodes_read('') === array()) &&
    (fleet_backup_nodes_read(FLEET_DATA . '/../nodes-0123456789abcdef.json') === array()) && is_file(FLEET_DATA . '/other.json'), 'only a file Fleet wrote is read');
@unlink(FLEET_DATA . '/other.json');
$big = array();
for ($i = 0; $i < 5000; $i++) {
	$big[] = sprintf('n-%08d', $i);
}
check(count(fleet_backup_nodes_read(fleet_backup_nodes_write($big))) === 5000, 'five thousand firewalls fit (they never did on a command line)');
