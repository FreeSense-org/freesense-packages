<?php
require_once('config.inc');
require_once('services.inc');

define('FREESENSE_AUTOMATION_MARKER', 'freesense-automation');

function automation_remove_cron_entries() {
	$cron = config_get_path('cron/item', []);
	$cron = array_values(array_filter($cron, fn($item) => ($item['source'] ?? '') !== FREESENSE_AUTOMATION_MARKER));
	config_set_path('cron/item', $cron);
	configure_cron();
}

function automation_sync() {
	$cron = config_get_path('cron/item', []);
	$cron = array_values(array_filter($cron, fn($item) => ($item['source'] ?? '') !== FREESENSE_AUTOMATION_MARKER));
	foreach (config_get_path('installedpackages/automation/tasks', []) as $task) {
		if (($task['enabled'] ?? '') !== 'on') {
			continue;
		}
		$cron[] = [
			'minute' => $task['minute'], 'hour' => $task['hour'],
			'mday' => $task['mday'], 'month' => $task['month'],
			'wday' => $task['wday'], 'who' => 'root',
			'command' => $task['command'], 'source' => FREESENSE_AUTOMATION_MARKER,
		];
	}
	$watchdog = config_get_path('installedpackages/automation/watchdog', []);
	if (!empty($watchdog)) {
		$cron[] = ['minute'=>'*/5','hour'=>'*','mday'=>'*','month'=>'*','wday'=>'*','who'=>'root','command'=>'/usr/local/pkg/automation/automation_watchdog.php','source'=>FREESENSE_AUTOMATION_MARKER];
	}
	config_set_path('cron/item', $cron);
	configure_cron();
}
