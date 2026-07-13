<?php
require_once('config.inc');
require_once('freesense-utils.inc');
require_once('filter.inc');
require_once('services.inc');

define('FREESENSE_CROWDSEC_ALIAS', 'CrowdSecBlocklist');
define('FREESENSE_CROWDSEC_FILE', '/var/db/crowdsec/freesense-blocks.txt');
define('FREESENSE_CROWDSEC_RULE', 'FreeSense CrowdSec decisions');

function crowdsec_ensure_alias_and_rule() {
	$rules = get_filter_rules_list();
	foreach ($rules as $rule) if (($rule['descr'] ?? '') === FREESENSE_CROWDSEC_RULE) return;
	add_filter_rules([['type'=>'block','interface'=>'wan','ipprotocol'=>'inet46','statetype'=>'keep state','source'=>['address'=>FREESENSE_CROWDSEC_ALIAS],'destination'=>['any'=>true],'descr'=>FREESENSE_CROWDSEC_RULE]]);
}

function crowdsec_sync_config() {
	@mkdir(dirname(FREESENSE_CROWDSEC_FILE), 0750, true);
	if (!file_exists(FREESENSE_CROWDSEC_FILE)) file_put_contents(FREESENSE_CROWDSEC_FILE, "");
	$enabled = config_get_path('installedpackages/crowdsec/enable') === 'on';
	$command = '/usr/local/pkg/crowdsec/crowdsec_sync.php';
	install_cron_job($command, $enabled, '*', '*', '*', '*', '*', 'root');
	if ($enabled) {
		crowdsec_ensure_alias_and_rule();
		filter_configure();
		mwexec('/usr/sbin/service crowdsec onestart', true);
	}
}

function crowdsec_remove_config() {
	install_cron_job('/usr/local/pkg/crowdsec/crowdsec_sync.php', false);
	$rules=array_values(array_filter(get_filter_rules_list(), fn($r)=>($r['descr']??'')!==FREESENSE_CROWDSEC_RULE));
	set_filter_rules_list($rules);
	filter_configure();
	@unlink(FREESENSE_CROWDSEC_FILE);
}
