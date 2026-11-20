<?php
/* Fleet controller tests: notices. Loaded by ../run.php (shares its variables). */

$fin = array(array('id' => 1, 'state' => 'done', 'text' => 'Done', 'name' => 'Reboot Lab'), array('id' => 2, 'state' => 'failed', 'text' => 'Backup failed: x', 'name' => 'Back up Aarhus'), array('id' => 3, 'state' => 'running', 'text' => 'x', 'name' => 'y'));
$ts = fleet_nav_toasts($fin, true, true);
check(count($ts) === 2 && $ts[0] === array('text' => 'Reboot Lab: Done', 'kind' => 'pass', 'href' => '/fleet/fleet_activity.php?op=1', 'sticky' => false) && $ts[1]['sticky'] === true && $ts[1]['kind'] === 'block',
    'a notice per finished action; failures stay');
check(count(fleet_nav_toasts($fin, false, true)) === 1 && fleet_nav_toasts($fin, false, false) === array(), 'the settings turn them off');
/* A long text with multibyte letters is cut between characters, so the answer still encodes. */
$tl = fleet_nav_toasts(array(array('state' => 'failed', 'name' => 'Reboot Århus', 'text' => str_repeat('æøå ', 80), 'id' => 5)), true, true);
check((count($tl) === 1) && (mb_strlen($tl[0]['text']) === 200) && (json_encode($tl) !== false), 'a notice is cut at 200 characters without splitting a letter');
require_once($argv[1] . '/src/usr/local/www/includes/fs_menu.inc');
check(fs_nav_toasts($ts) === $ts, 'System shows the Fleet notices as they are');
check(fleet_ops_finished_since(0, time() + 100)[0]['name'] !== '', 'finished operations have a name');
