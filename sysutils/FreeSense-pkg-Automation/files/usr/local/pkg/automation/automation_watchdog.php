#!/usr/local/bin/php -f
<?php
require_once('globals.inc');
require_once('config.inc');
require_once('service-utils.inc');
require_once('/usr/local/pkg/automation/automation.inc');

foreach (automation_get_list('watchdog') as $entry) {
	$name = $entry['service'] ?? '';
	if (!preg_match('/^[A-Za-z0-9_.-]{1,64}$/D', $name)) {
		continue;
	}
	if (!is_service_running($name)) {
		logger(LOG_WARNING, "Automation watchdog restarting {$name}");
		service_control_restart($name, ['extras' => ['notifies' => false]]);
	}
}
