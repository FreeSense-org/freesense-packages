<?php
/*
 * suricata_logs_mgmt.php
 *
 * part of FreeSense (https://www.freesense.org)
 * Copyright (c) 2004-2026 The FreeSense Project
 * Copyright (c) 2003-2004 Manuel Kasper
 * Copyright (c) 2005 Bill Marquette
 * Copyright (c) 2009 Robert Zelaya Sr. Developer
 * Copyright (c) 2023 Bill Meeks
 * All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

require_once("guiconfig.inc");
require_once("/usr/local/pkg/suricata/suricata.inc");

global $g;

$suricatadir = SURICATADIR;

$pconfig = array();

// Grab saved settings from configuration
$pconfig['enable_log_mgmt'] = config_get_path('installedpackages/suricata/config/0/enable_log_mgmt') == 'on' ? 'on' : 'off';
$pconfig['clearlogs'] = config_get_path('installedpackages/suricata/config/0/clearlogs') == 'on' ? 'on' : 'off';
$pconfig['suricataloglimit'] = config_get_path('installedpackages/suricata/config/0/suricataloglimit') == 'on' ? 'on' : 'off';
$pconfig['suricataloglimitsize'] = htmlentities(config_get_path('installedpackages/suricata/config/0/suricataloglimitsize'));
$pconfig['alert_log_limit_size'] = config_get_path('installedpackages/suricata/config/0/alert_log_limit_size', 500);
$pconfig['alert_log_retention'] = config_get_path('installedpackages/suricata/config/0/alert_log_retention', 336);
$pconfig['block_log_limit_size'] = config_get_path('installedpackages/suricata/config/0/block_log_limit_size', 500);
$pconfig['block_log_retention'] = config_get_path('installedpackages/suricata/config/0/block_log_retention', 336);
$pconfig['http_log_limit_size'] = config_get_path('installedpackages/suricata/config/0/http_log_limit_size', 1000);
$pconfig['http_log_retention'] = config_get_path('installedpackages/suricata/config/0/http_log_retention', 168);
$pconfig['stats_log_limit_size'] = config_get_path('installedpackages/suricata/config/0/stats_log_limit_size', 500);
$pconfig['stats_log_retention'] = config_get_path('installedpackages/suricata/config/0/stats_log_retention', 168);
$pconfig['tls_log_limit_size'] = config_get_path('installedpackages/suricata/config/0/tls_log_limit_size', 500);
$pconfig['tls_log_retention'] = config_get_path('installedpackages/suricata/config/0/tls_log_retention', 336);
$pconfig['file_store_retention'] = config_get_path('installedpackages/suricata/config/0/file_store_retention', 168);
$pconfig['file_store_limit_size'] = config_get_path('installedpackages/suricata/config/0/file_store_limit_size');
$pconfig['tls_certs_store_retention'] = config_get_path('installedpackages/suricata/config/0/tls_certs_store_retention', 168);
$pconfig['eve_log_limit_size'] = config_get_path('installedpackages/suricata/config/0/eve_log_limit_size', 5000);
$pconfig['eve_log_retention'] = config_get_path('installedpackages/suricata/config/0/eve_log_retention', 168);
$pconfig['sid_changes_log_limit_size'] = config_get_path('installedpackages/suricata/config/0/sid_changes_log_limit_size', 250);
$pconfig['sid_changes_log_retention'] = config_get_path('installedpackages/suricata/config/0/sid_changes_log_retention', 336);
$pconfig['pkt_capture_file_retention'] = config_get_path('installedpackages/suricata/config/0/pkt_capture_file_retention', 168);

// Load up some arrays with selection values (we use these later).
// The keys in the $retentions array are the retention period
// converted to hours.  The keys in the $log_sizes array are
// the file size limits in KB.
$retentions = array( '0' => gettext('KEEP ALL'), '24' => gettext('1 DAY'), '168' => gettext('7 DAYS'), '336' => gettext('14 DAYS'),
			 '720' => gettext('30 DAYS'), '1080' => gettext("45 DAYS"), '2160' => gettext('90 DAYS'), '4320' => gettext('180 DAYS'),
			 '8766' => gettext('1 YEAR'), '26298' => gettext("3 YEARS") );
$log_sizes = array( '0' => gettext('NO LIMIT'), '50' => gettext('50 KB'), '150' => gettext('150 KB'), '250' => gettext('250 KB'),
			'500' => gettext('500 KB'), '750' => gettext('750 KB'), '1000' => gettext('1 MB'), '2000' => gettext('2 MB'),
			'5000' => gettext("5 MB"), '10000' => gettext("10 MB") );

// Set sensible default for Suricata logging directory size limit
if (empty($pconfig['suricataloglimitsize'])) {
	// Set limit to 20% of slice that is unused */
	$pconfig['suricataloglimitsize'] = round(exec('df -k /var | grep -v "Filesystem" | awk \'{print $4}\'') * .20 / 1024);
}

// Set a default file store size limit
if (!isset($pconfig['file_store_limit_size']))
	$pconfig['file_store_limit_size'] = intval($pconfig['suricataloglimitsize'] * 0.60);

if (isset($_POST['ResetAll'])) {

	// Reset all settings to their defaults
	$pconfig['alert_log_retention'] = "336";
	$pconfig['block_log_retention'] = "336";
	$pconfig['http_log_retention'] = "168";
	$pconfig['stats_log_retention'] = "168";
	$pconfig['tls_log_retention'] = "336";
	$pconfig['file_store_retention'] = "168";
	$pconfig['tls_certs_store_retention'] = "168";
	$pconfig['eve_log_retention'] = "168";
	$pconfig['sid_changes_log_retention'] = "336";
	$pconfig['pkt_capture_file_retention'] = "168";

	$pconfig['alert_log_limit_size'] = "500";
	$pconfig['block_log_limit_size'] = "500";
	$pconfig['http_log_limit_size'] = "1000";
	$pconfig['stats_log_limit_size'] = "500";
	$pconfig['tls_log_limit_size'] = "500";
	$pconfig['eve_log_limit_size'] = "5000";
	$pconfig['sid_changes_log_limit_size'] = "250";
	$pconfig['file_store_limit_size'] = intval($pconfig['suricataloglimitsize'] * 0.60);

	/* Log a message at the top of the page to inform the user */
	$savemsg = gettext("All log management settings on this page have been reset to their defaults.  Click APPLY if you wish to keep these new settings.");
}

if (isset($_POST['save']) || isset($_POST['apply'])) {
	if ($_POST['enable_log_mgmt'] != 'on') {
		config_set_path('installedpackages/suricata/config/0/enable_log_mgmt', $_POST['enable_log_mgmt'] ? 'on' :'off');
		write_config("Suricata pkg: saved updated configuration for LOGS MGMT.");
		sync_suricata_package_config();

		/* forces page to reload new settings */
		header( 'Expires: Sat, 26 Jul 1997 05:00:00 GMT' );
		header( 'Last-Modified: ' . gmdate( 'D, d M Y H:i:s' ) . ' GMT' );
		header( 'Cache-Control: no-store, no-cache, must-revalidate' );
		header( 'Cache-Control: post-check=0, pre-check=0', false );
		header( 'Pragma: no-cache' );
		header("Location: /suricata/suricata_logs_mgmt.php");
		exit;
	}

	if ($_POST['suricataloglimit'] == 'on') {
		if (!is_numericint($_POST['suricataloglimitsize']) || $_POST['suricataloglimitsize'] < 1)
			$input_errors[] = gettext("The 'Log Directory Size Limit' must be an integer value greater than zero.");
	}

	if (!$input_errors) {
		config_set_path('installedpackages/suricata/config/0/enable_log_mgmt', $_POST['enable_log_mgmt'] ? 'on' :'off');
		config_set_path('installedpackages/suricata/config/0/clearlogs', $_POST['clearlogs'] ? 'on' : 'off');
		config_set_path('installedpackages/suricata/config/0/suricataloglimit', $_POST['suricataloglimit'] ? 'on' :'off');
		config_set_path('installedpackages/suricata/config/0/suricataloglimitsize', html_entity_decode($_POST['suricataloglimitsize']));
		config_set_path('installedpackages/suricata/config/0/alert_log_limit_size', $_POST['alert_log_limit_size']);
		config_set_path('installedpackages/suricata/config/0/alert_log_retention', $_POST['alert_log_retention']);
		config_set_path('installedpackages/suricata/config/0/block_log_limit_size', $_POST['block_log_limit_size']);
		config_set_path('installedpackages/suricata/config/0/block_log_retention', $_POST['block_log_retention']);
		config_set_path('installedpackages/suricata/config/0/http_log_limit_size', $_POST['http_log_limit_size']);
		config_set_path('installedpackages/suricata/config/0/http_log_retention', $_POST['http_log_retention']);
		config_set_path('installedpackages/suricata/config/0/stats_log_limit_size', $_POST['stats_log_limit_size']);
		config_set_path('installedpackages/suricata/config/0/stats_log_retention', $_POST['stats_log_retention']);
		config_set_path('installedpackages/suricata/config/0/tls_log_limit_size', $_POST['tls_log_limit_size']);
		config_set_path('installedpackages/suricata/config/0/tls_log_retention', $_POST['tls_log_retention']);
		config_set_path('installedpackages/suricata/config/0/file_store_retention', $_POST['file_store_retention']);
		config_set_path('installedpackages/suricata/config/0/file_store_limit_size', $_POST['file_store_limit_size']);
		config_set_path('installedpackages/suricata/config/0/tls_certs_store_retention', $_POST['tls_certs_store_retention']);
		config_set_path('installedpackages/suricata/config/0/eve_log_limit_size', $_POST['eve_log_limit_size']);
		config_set_path('installedpackages/suricata/config/0/eve_log_retention', $_POST['eve_log_retention']);
		config_set_path('installedpackages/suricata/config/0/sid_changes_log_limit_size', $_POST['sid_changes_log_limit_size']);
		config_set_path('installedpackages/suricata/config/0/sid_changes_log_retention', $_POST['sid_changes_log_retention']);
		config_set_path('installedpackages/suricata/config/0/pkt_capture_file_retention', $_POST['pkt_capture_file_retention']);

		write_config("Suricata pkg: saved updated configuration for LOGS MGMT.");
		sync_suricata_package_config();

		/* forces page to reload new settings */
		header( 'Expires: Sat, 26 Jul 1997 05:00:00 GMT' );
		header( 'Last-Modified: ' . gmdate( 'D, d M Y H:i:s' ) . ' GMT' );
		header( 'Cache-Control: no-store, no-cache, must-revalidate' );
		header( 'Cache-Control: post-check=0, pre-check=0', false );
		header( 'Pragma: no-cache' );
		header("Location: /suricata/suricata_logs_mgmt.php");
		exit;
	}
}

$pglinks = array("", "/suricata/suricata_overview.php", "@self");
$pgtitle = array(gettext("Services"), gettext("Suricata"), gettext("Log management"));
include_once("head.inc");

/* Display Alert message, under form tag or no refresh */
if ($input_errors)
	print_input_errors($input_errors);

if ($savemsg) {
	/* Display save message */
	print_info_box($savemsg);
}

suricata_display_primary_navigation('maintenance');

$form = new Form;

$section = new Form_Section('General', 'logs-general');
$section->addInput(new Form_Checkbox(
	'enable_log_mgmt',
	'Automatic log management',
	'Rotate and prune Suricata logs automatically with the limits below',
	$pconfig['enable_log_mgmt'] == 'on' ? true:false,
	'on'
));
$section->addInput(new Form_Checkbox(
	'clearlogs',
	'Remove logs on uninstall',
	'Delete the Suricata log files when the package is removed',
	$pconfig['clearlogs'] == 'on' ? true:false,
	'on'
));
$section->addInput(new Form_Checkbox(
	'suricataloglimit',
	'Directory size limit',
	'Limit the combined size of all Suricata log directories',
	$pconfig['suricataloglimit'] == 'on' ? true:false,
	'on'
));
$section->addInput(new Form_Input(
	'suricataloglimitsize',
	'Size limit (MB)',
	'text',
	$pconfig['suricataloglimitsize']
))->setHelp('When reached, rotated logs of all interfaces are removed and active logs are truncated. Default is 20% of the free disk space.');
$form->add($section);

$section = new Form_Section('Log size and retention', 'logs-limits');
$group = new Form_Group('Alerts');
$group->add(new Form_Select(
	'alert_log_limit_size',
	'Max Size',
	$pconfig['alert_log_limit_size'],
	$log_sizes
))->setHelp('Max size, default 500 KB.');
$group->add(new Form_Select(
	'alert_log_retention',
	'Retention',
	$pconfig['alert_log_retention'],
	$retentions
))->setHelp('Retention, default 14 DAYS.');
$group->setHelp('Alerts and event details');
$section->add($group);

$group = new Form_Group('Blocks');
$group->add(new Form_Select(
	'block_log_limit_size',
	'Max Size',
	$pconfig['block_log_limit_size'],
	$log_sizes
))->setHelp('Max size, default 500 KB.');
$group->add(new Form_Select(
	'block_log_retention',
	'Retention',
	$pconfig['block_log_retention'],
	$retentions
))->setHelp('Retention, default 14 DAYS.');
$group->setHelp('Blocked IPs and event details');
$section->add($group);

$group = new Form_Group('EVE JSON');
$group->add(new Form_Select(
	'eve_log_limit_size',
	'Max Size',
	$pconfig['eve_log_limit_size'],
	$log_sizes
))->setHelp('Max size, default 5 MB.');
$group->add(new Form_Select(
	'eve_log_retention',
	'Retention',
	$pconfig['eve_log_retention'],
	$retentions
))->setHelp('Retention, default 7 DAYS.');
$group->setHelp('EVE JSON event data');
$section->add($group);

$group = new Form_Group('HTTP');
$group->add(new Form_Select(
	'http_log_limit_size',
	'Max Size',
	$pconfig['http_log_limit_size'],
	$log_sizes
))->setHelp('Max size, default 1 MB.');
$group->add(new Form_Select(
	'http_log_retention',
	'Retention',
	$pconfig['http_log_retention'],
	$retentions
))->setHelp('Retention, default 7 DAYS.');
$group->setHelp('HTTP events and session info');
$section->add($group);

$group = new Form_Group('SID changes');
$group->add(new Form_Select(
	'sid_changes_log_limit_size',
	'Max Size',
	$pconfig['sid_changes_log_limit_size'],
	$log_sizes
))->setHelp('Max size, default 250 KB.');
$group->add(new Form_Select(
	'sid_changes_log_retention',
	'Retention',
	$pconfig['sid_changes_log_retention'],
	$retentions
))->setHelp('Retention, default 14 DAYS.');
$group->setHelp('Changes made by SID management lists');
$section->add($group);

$group = new Form_Group('Statistics');
$group->add(new Form_Select(
	'stats_log_limit_size',
	'Max Size',
	$pconfig['stats_log_limit_size'],
	$log_sizes
))->setHelp('Max size, default 500 KB.');
$group->add(new Form_Select(
	'stats_log_retention',
	'Retention',
	$pconfig['stats_log_retention'],
	$retentions
))->setHelp('Retention, default 7 DAYS.');
$group->setHelp('Performance statistics');
$section->add($group);

$group = new Form_Group('TLS');
$group->add(new Form_Select(
	'tls_log_limit_size',
	'Max Size',
	$pconfig['tls_log_limit_size'],
	$log_sizes
))->setHelp('Max size, default 500 KB.');
$group->add(new Form_Select(
	'tls_log_retention',
	'Retention',
	$pconfig['tls_log_retention'],
	$retentions
))->setHelp('Retention, default 14 DAYS.');
$group->setHelp('TLS handshake details');
$section->add($group);

$section->addInput(new Form_StaticText(
	'',
	'<span class="fs-muted small">' . gettext('Logs that are not enabled on an interface are ignored. A log that reaches its maximum size is rotated with a timestamp; rotated logs are deleted after the retention period.') . '</span>'
));

$form->add($section);

$section = new Form_Section('Captured files', 'logs-captures');
$section->addInput(new Form_Input(
	'file_store_limit_size',
	'File store limit (MB)',
	'text',
	$pconfig['file_store_limit_size']
))->setHelp('Older captured files are purged above this size. 0 means unlimited. Defaults to 60% of the directory size limit.');
$section->addInput(new Form_Select(
	'file_store_retention',
	'File store retention',
	$pconfig['file_store_retention'],
	$retentions
))->setHelp('How long files extracted from HTTP sessions are kept. Default is 7 days.');
$section->addInput(new Form_Select(
	'tls_certs_store_retention',
	'TLS certificate retention',
	$pconfig['tls_certs_store_retention'],
	$retentions
))->setHelp('How long certificates stored by tls.store rules are kept. Default is 7 days.');
$section->addInput(new Form_Select(
	'pkt_capture_file_retention',
	'Packet capture retention',
	$pconfig['pkt_capture_file_retention'],
	$retentions
))->setHelp('How long PCAP files in the interface "pcaps" folder are kept. Default is 7 days.');
$form->add($section);

print($form);

?>

<p class="small fs-muted"><i class="fa-solid fa-circle-info" aria-hidden="true"></i> <?=gettext('These settings apply to every Suricata interface.')?></p>

<script language="JavaScript">
//<![CDATA[
events.push(function(){

	function enable_change() {
		var hide = ! $('#enable_log_mgmt').prop('checked');
		disableInput('alert_log_limit_size', hide);
		disableInput('alert_log_retention', hide);
		disableInput('block_log_limit_size', hide);
		disableInput('block_log_retention', hide);
		disableInput('http_log_limit_size', hide);
		disableInput('http_log_retention', hide);
		disableInput('stats_log_limit_size', hide);
		disableInput('stats_log_retention', hide);
		disableInput('tls_log_limit_size', hide);
		disableInput('tls_log_retention', hide);
		disableInput('eve_log_retention', hide);
		disableInput('eve_log_limit_size', hide);
		disableInput('sid_changes_log_retention', hide);
		disableInput('sid_changes_log_limit_size', hide);
		disableInput('file_store_retention', hide);
		disableInput('file_store_limit_size', hide);
		disableInput('tls_certs_store_retention', hide);
		disableInput('pkt_capture_file_retention', hide);
	}

	function enable_change_dirSize() {
		var hide = ! $('#suricataloglimit').prop('checked');
		disableInput('suricataloglimitsize', hide);
	}

	// ---------- Click checkbox handlers -------------------------------------------------------
	// When 'enable_log_mgmt' is clicked, disable/enable the other page form controls
	$('#enable_log_mgmt').click(function() {
		enable_change();
	});

	// When 'suricataloglimit_on' is clicked, disable/enable the other page form controls
	$('#suricataloglimit').click(function() {
		enable_change_dirSize();
	});

	enable_change();
	enable_change_dirSize();

});
//]]>
</script>

<?php include("foot.inc"); ?>

