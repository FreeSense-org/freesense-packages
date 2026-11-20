<?php
/* Fleet controller tests: settings. Loaded by ../run.php (shares its variables). */

$t = fleet_tunables_from(array('silent_offline' => '30', 'backup_parallel' => '0', 'toast_done' => 'off', 'per_page' => '50', 'reboot_timeout' => '7.5', 'show_done' => 'x'));
check($t['silent_offline'] === 30 && $t['backup_parallel'] === 10 && $t['toast_done'] === false && $t['toast_failed'] === true && $t['per_page'] === 50 &&
    $t['reboot_timeout'] === 10 && $t['show_done'] === 90, 'tunables: in range kept, out of range or not whole is the default, booleans on/off');
foreach (FLEET_TUNABLES as $k => $def) {
	check(array_key_exists($def[0], FLEET_SETTINGS_SECTIONS) && $def[5] !== '' && $def[6] !== '', "setting {$k} has a section, a label and help");
}
check(fleet_opt('reboot_timeout') === 10 && fleet_opt('per_page') === 25, 'defaults without a configuration');
