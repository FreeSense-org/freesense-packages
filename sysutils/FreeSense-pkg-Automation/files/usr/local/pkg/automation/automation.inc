<?php
require_once('config.inc');
require_once('services.inc');

define('FREESENSE_AUTOMATION_MARKER', 'freesense-automation');

/* Lists are stored as <item> entries; a bare PHP list is not valid in config.xml. */
function automation_get_list(string $name): array {
	$value = config_get_path("installedpackages/automation/{$name}", []);
	if (is_array($value) && array_key_exists('item', $value)) {
		$value = $value['item'];
	}
	if (!is_array($value)) {
		return [];
	}
	$list = [];
	foreach (array_filter($value, 'is_array') as $entry) {
		/* 'service' is a config list tag, so a single value reads back as a
		 * one-element array; flatten such fields back to plain strings. */
		foreach ($entry as $k => $v) {
			if (is_array($v) && count($v) === 1 && array_is_list($v) && !is_array($v[0])) {
				$entry[$k] = $v[0];
			}
		}
		$list[] = $entry;
	}
	return $list;
}

function automation_set_list(string $name, array $list): void {
	config_set_path("installedpackages/automation/{$name}", empty($list) ? '' : ['item' => array_values($list)]);
}

function automation_remove_cron_entries() {
	$cron = config_get_path('cron/item', []);
	$cron = array_values(array_filter($cron, fn($item) => ($item['source'] ?? '') !== FREESENSE_AUTOMATION_MARKER));
	config_set_path('cron/item', $cron);
	configure_cron();
}

function automation_sync() {
	$cron = config_get_path('cron/item', []);
	$cron = array_values(array_filter($cron, fn($item) => ($item['source'] ?? '') !== FREESENSE_AUTOMATION_MARKER));
	foreach (automation_get_list('tasks') as $task) {
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
	$watchdog = automation_get_list('watchdog');
	if (!empty($watchdog)) {
		$cron[] = ['minute'=>'*/5','hour'=>'*','mday'=>'*','month'=>'*','wday'=>'*','who'=>'root','command'=>'/usr/local/pkg/automation/automation_watchdog.php','source'=>FREESENSE_AUTOMATION_MARKER];
	}
	config_set_path('cron/item', $cron);
	configure_cron();
}
