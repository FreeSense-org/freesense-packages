<?php
/* Fleet controller tests: notices. Loaded by ../run.php (shares its variables). */

$fin = array(array('id' => 1, 'state' => 'done', 'text' => 'Done', 'name' => 'Reboot Lab'), array('id' => 2, 'state' => 'failed', 'text' => 'Backup failed: x', 'name' => 'Back up Aarhus'), array('id' => 3, 'state' => 'running', 'text' => 'x', 'name' => 'y'));
$ts = fleet_nav_toasts($fin, true, true);
check(count($ts) === 2 && $ts[0] === array('text' => 'Reboot Lab: Done', 'kind' => 'pass', 'href' => '/fleet/fleet_activity.php?op=1', 'sticky' => false) && $ts[1]['sticky'] === true && $ts[1]['kind'] === 'block',
    'a notice per finished action; failures stay');
check(count(fleet_nav_toasts($fin, false, true)) === 1 && fleet_nav_toasts($fin, false, false) === array(), 'the settings turn them off');
require_once($argv[1] . '/src/usr/local/www/includes/fs_menu.inc');
check(fs_nav_toasts($ts) === $ts, 'System shows the Fleet notices as they are');
check(fleet_ops_finished_since(0, time() + 100)[0]['name'] !== '', 'finished operations have a name');
