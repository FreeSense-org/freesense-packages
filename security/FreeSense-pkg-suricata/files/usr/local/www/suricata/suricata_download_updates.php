<?php
/*
 * suricata_download_updates.php
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
require_once("/usr/local/pkg/suricata/suricata_defs.inc");
require_once("/usr/local/pkg/suricata/suricata.inc");

/* Define some locally required variables from Suricata constants */
$suricatadir = SURICATADIR;
$suricata_rules_upd_log = SURICATA_RULES_UPD_LOGFILE;

$snortdownload = config_get_path('installedpackages/suricata/config/0/enable_vrt_rules') == "on" ? 'on' : 'off';
$emergingthreats = config_get_path('installedpackages/suricata/config/0/enable_etopen_rules') == "on" ? 'on' : 'off';
$etpro = config_get_path('installedpackages/suricata/config/0/enable_etpro_rules') == "on" ? 'on' : 'off';
$snortcommunityrules = config_get_path('installedpackages/suricata/config/0/snortcommunityrules') == "on" ? 'on' : 'off';
$feodotracker_rules = config_get_path('installedpackages/suricata/config/0/enable_feodo_botnet_c2_rules') == "on" ? 'on' : 'off';
$sslbl_rules = config_get_path('installedpackages/suricata/config/0/enable_abuse_ssl_blacklist_rules') == "on" ? 'on' : 'off';
$enable_extra_rules = config_get_path('installedpackages/suricata/config/0/enable_extra_rules') == "on" ? 'on' : 'off';
$extra_rules = config_get_path('installedpackages/suricata/config/0/extra_rules/rule', []);

/* Get last update information if available */
if (file_exists(SURICATADIR . "rulesupd_status")) {
	$status = explode("|", file_get_contents(SURICATADIR . "rulesupd_status"));
	$last_rule_upd_time = date('M-d Y H:i', $status[0]);
	$last_rule_upd_status = gettext($status[1]);
}
else {
	$last_rule_upd_time = gettext("Unknown");
	$last_rule_upd_status = gettext("Unknown");
}

// Check for any custom URLs and extract custom filenames
// if present, else use package default values.
if (config_get_path('installedpackages/suricata/config/0/enable_snort_custom_url') == 'on') {
	$snort_rules_file = trim(substr(config_get_path('installedpackages/suricata/config/0/snort_custom_url'), strrpos(config_get_path('installedpackages/suricata/config/0/snort_custom_url'), '/') + 1));
}
else {
	$snort_rules_file = config_get_path('installedpackages/suricata/config/0/snort_rules_file');
}
if (config_get_path('installedpackages/suricata/config/0/enable_gplv2_custom_url') == 'on') {
	$snort_community_rules_filename = trim(substr(config_get_path('installedpackages/suricata/config/0/gplv2_custom_url'), strrpos(config_get_path('installedpackages/suricata/config/0/gplv2_custom_url'), '/') + 1));
}
else {
	$snort_community_rules_filename = GPLV2_DNLD_FILENAME;
}
if ($etpro == "on") {
	$et_name = "Emerging Threats Pro Rules";
	if (config_get_path('installedpackages/suricata/config/0/enable_etpro_custom_url') == 'on') {
		$emergingthreats_filename = trim(substr(config_get_path('installedpackages/suricata/config/0/etpro_custom_rule_url'), strrpos(config_get_path('installedpackages/suricata/config/0/etpro_custom_rule_url'), '/') + 1));
	}
	else {
		$emergingthreats_filename = ETPRO_DNLD_FILENAME;
	}
}
else {
	$et_name = "Emerging Threats Open Rules";
	if (config_get_path('installedpackages/suricata/config/0/enable_etopen_custom_url') == 'on') {
		$emergingthreats_filename = trim(substr(config_get_path('installedpackages/suricata/config/0/etopen_custom_rule_url'), strrpos(config_get_path('installedpackages/suricata/config/0/etopen_custom_rule_url'), '/') + 1));
	}
	else {
		$emergingthreats_filename = ET_DNLD_FILENAME;
	}
}

$feodotracker_rules_filename = FEODO_TRACKER_DNLD_FILENAME;
$sslbl_rules_filename = ABUSE_SSLBL_DNLD_FILENAME;

/* quick md5 chk of downloaded rules */
if ($snortdownload == 'on') {
	$snort_org_sig_chk_local = 'Not Downloaded';
	$snort_org_sig_date = 'Not Downloaded';
}
else {
	$snort_org_sig_chk_local = 'Not Enabled';
	$snort_org_sig_date = 'Not Enabled';
}
if ($snortdownload == 'on' && file_exists("{$suricatadir}{$snort_rules_file}.md5")){
	$snort_org_sig_chk_local = file_get_contents("{$suricatadir}{$snort_rules_file}.md5");
	$snort_org_sig_date = date(DATE_RFC850, filemtime("{$suricatadir}{$snort_rules_file}.md5"));
}

if ($etpro == "on" || $emergingthreats == "on") {
	$emergingt_net_sig_chk_local = 'Not Downloaded';
	$emergingt_net_sig_date = 'Not Downloaded';
}
else {
	$emergingt_net_sig_chk_local = 'Not Enabled';
	$emergingt_net_sig_date = 'Not Enabled';
}
if (($etpro == "on" || $emergingthreats == "on") && file_exists("{$suricatadir}{$emergingthreats_filename}.md5")) {
	$emergingt_net_sig_chk_local = file_get_contents("{$suricatadir}{$emergingthreats_filename}.md5");
	$emergingt_net_sig_date = date(DATE_RFC850, filemtime("{$suricatadir}{$emergingthreats_filename}.md5"));
}

if ($snortcommunityrules == 'on') {
	$snort_community_sig_chk_local = 'Not Downloaded';
	$snort_community_sig_sig_date = 'Not Downloaded';
}
else {
	$snort_community_sig_chk_local = 'Not Enabled';
	$snort_community_sig_sig_date = 'Not Enabled';
}
if ($snortcommunityrules == 'on' && file_exists("{$suricatadir}{$snort_community_rules_filename}.md5")) {
	$snort_community_sig_chk_local = file_get_contents("{$suricatadir}{$snort_community_rules_filename}.md5");
	$snort_community_sig_sig_date = date(DATE_RFC850, filemtime("{$suricatadir}{$snort_community_rules_filename}.md5"));
}

if ($feodotracker_rules == 'on') {
	$feodotracker_sig_chk_local = 'Not Downloaded';
	$feodotracker_sig_sig_date = 'Not Downloaded';
}
else {
	$feodotracker_sig_chk_local = 'Not Enabled';
	$feodotracker_sig_sig_date = 'Not Enabled';
}
if ($feodotracker_rules == 'on' && file_exists("{$suricatadir}{$feodotracker_rules_filename}.md5")) {
	$feodotracker_sig_chk_local = file_get_contents("{$suricatadir}{$feodotracker_rules_filename}.md5");
	$feodotracker_sig_sig_date = date(DATE_RFC850, filemtime("{$suricatadir}{$feodotracker_rules_filename}.md5"));
}

if ($sslbl_rules == 'on') {
	$sslbl_sig_chk_local = 'Not Downloaded';
	$sslbl_sig_sig_date = 'Not Downloaded';
}
else {
	$sslbl_sig_chk_local = 'Not Enabled';
	$sslbl_sig_sig_date = 'Not Enabled';
}
if ($sslbl_rules == 'on' && file_exists("{$suricatadir}{$sslbl_rules_filename}.md5")) {
	$sslbl_sig_chk_local = file_get_contents("{$suricatadir}{$sslbl_rules_filename}.md5");
	$sslbl_sig_sig_date = date(DATE_RFC850, filemtime("{$suricatadir}{$sslbl_rules_filename}.md5"));
}

/* Check for postback to see if we should clear the update log file. */
if ($_POST['clear']) {
	if (file_exists(SURICATA_RULES_UPD_LOGFILE)) {
		file_put_contents(SURICATA_RULES_UPD_LOGFILE, "");
	}
}

if ($_REQUEST['updatemode']) {
	if ($_REQUEST['updatemode'] == 'force') {
		// Remove the existing MD5 signature files to force a download
		unlink_if_exists("{$suricatadir}{$emergingthreats_filename}.md5");
		unlink_if_exists("{$suricatadir}{$snort_community_rules_filename}.md5");
		unlink_if_exists("{$suricatadir}{$snort_rules_file}.md5");
		unlink_if_exists("{$suricatadir}{$feodotracker_rules_filename}.md5");
		unlink_if_exists("{$suricatadir}{$sslbl_rules_filename}.md5");
		unlink_if_exists("{$suricatadir}" . EXTRARULE_FILE_PREFIX . "*.md5");
	}

	// Launch a background process to download the updates
	$upd_pid = 0;
	$upd_pid = mwexec_bg("/usr/local/bin/php -f /usr/local/pkg/suricata/suricata_check_for_rule_updates.php");
	print $upd_pid;

	// If we failed to launch our background process, throw up an error for the user.
	if ($upd_pid == 0) {
		$input_errors[] = gettext("Failed to launch the background rules package update routine!  Rules update will not be done.");
	} else {
		exit;
	}
}

if ($_REQUEST['ajax'] == 'status') {
	if (is_numeric($_REQUEST['pid'])) {
		// Check for the PID launched as the rules update task
		$rc = shell_exec("/bin/ps -o pid= -p {$_REQUEST['pid']}");

		if (!empty($rc)) {
			print "RUNNING";
		} else {
			print "DONE";
		}
	} else {
		print "DONE";
	}
	exit;
}

/* check for logfile */
if (file_exists("{$suricata_rules_upd_log}")) {
	if (filesize("{$suricata_rules_upd_log}") > 0) {
		$suricata_rules_upd_log_chk = 'yes';
	}
}
else {
	$suricata_rules_upd_log_chk = 'no';
}

if ($_POST['view']&& $suricata_rules_upd_log_chk == 'yes') {
	$contents = file_get_contents($suricata_rules_upd_log);
	if ($contents === FALSE) {
		$input_errors[] = gettext("Unable to read log file: {$suricata_rules_upd_log}");
	}
}

if ($_POST['hide'])
	$contents = "";

$pglinks = array("", "/suricata/suricata_overview.php", "@self");
$pgtitle = array(gettext("Services"), gettext("Suricata"), gettext("Rule updates"));

$any_enabled = !($snortdownload != 'on' && $emergingthreats != 'on' && $etpro != 'on' && $snortcommunityrules != 'on' && $feodotracker_rules != 'on' && $sslbl_rules != 'on' && $enable_extra_rules != 'on');
if ($any_enabled) {
	fs_page_action(gettext('Update rules'), '#', 'fa-download', 'primary', ['id' => 'update', 'title' => gettext('Check for and apply updates to the enabled rule sets')]);
	fs_page_action(gettext('Force update'), '#', 'fa-arrows-rotate', 'secondary', ['id' => 'force', 'title' => gettext('Download all enabled rule sets again')]);
}
include_once("head.inc");

/* Display Alert message */
if ($input_errors) {
	print_input_errors($input_errors);
}
if ($savemsg) {
	print_info_box($savemsg);
}

suricata_display_primary_navigation('updates');

/* One row per rule set: [name, enabled, md5, date] */
$sets = [
	[$et_name, ($etpro == 'on' || $emergingthreats == 'on'), $emergingt_net_sig_chk_local, $emergingt_net_sig_date],
	[gettext("Snort Subscriber Rules"), ($snortdownload == 'on'), $snort_org_sig_chk_local, $snort_org_sig_date],
	[gettext("Snort GPLv2 Community Rules"), ($snortcommunityrules == 'on'), $snort_community_sig_chk_local, $snort_community_sig_sig_date],
	[gettext("Feodo Tracker Botnet C2 IP Rules"), ($feodotracker_rules == 'on'), $feodotracker_sig_chk_local, $feodotracker_sig_sig_date],
	[gettext("ABUSE.ch SSL Blacklist Rules"), ($sslbl_rules == 'on'), $sslbl_sig_chk_local, $sslbl_sig_sig_date],
];
if (($enable_extra_rules == 'on') && !empty($extra_rules)) {
	foreach ($extra_rules as $exrule) {
		$format = (substr($exrule['url'], strrpos($exrule['url'], 'rules')) == 'rules') ? ".rules" : ".tar.gz";
		$rulesfilename = EXTRARULE_FILE_PREFIX . $exrule['name'] . $format;
		if (file_exists("{$suricatadir}{$rulesfilename}.md5")) {
			$sets[] = [sprintf(gettext('Extra: %s'), $exrule['name']), true, trim(file_get_contents("{$suricatadir}{$rulesfilename}.md5")), date(DATE_RFC850, filemtime("{$suricatadir}{$rulesfilename}.md5"))];
		} else {
			$sets[] = [sprintf(gettext('Extra: %s'), $exrule['name']), true, 'Not Downloaded', 'Not Downloaded'];
		}
	}
}
$enabled_count = count(array_filter($sets, function ($s) { return $s[1]; }));
$upd_ok = (stripos($last_rule_upd_status, 'success') !== false);
$upd_unknown = ($last_rule_upd_status === gettext('Unknown'));
?>

<style>
.suri-pad { padding: 1rem; }
</style>

<div class="fs-tiles">
<?php
fs_tile(gettext('Last update'), $last_rule_upd_time);
fs_tile(gettext('Result'), $last_rule_upd_status, $upd_unknown ? null : ($upd_ok ? 'pass' : 'warn'));
fs_tile(gettext('Rule sets enabled'), $enabled_count, null, gettext('Choose rule sets under Advanced > Global settings'));
?>
</div>

<?php if (!$any_enabled): ?>
<?php print_callout(gettext('No rule sets are selected for download.') . ' <a href="/suricata/suricata_global.php">' . gettext('Select rule sets in the global settings') . '</a>.', 'warning'); ?>
<?php endif; ?>

<div class="panel panel-default fs-table">
<?php fs_table_toolbar([
	'title' => gettext('Installed rule sets'),
	'search' => false,
	'noun' => gettext('rule sets'),
	'noun_one' => gettext('rule set'),
]); ?>
	<div class="panel-body table-responsive">
		<table class="table table-hover">
			<thead>
				<tr>
					<th class="fs-col-status"><?=gettext("Status")?></th>
					<th><?=gettext("Rule set")?></th>
					<th><?=gettext("MD5 signature")?></th>
					<th><?=gettext("Signature date")?></th>
				</tr>
			</thead>
			<tbody>
<?php foreach ($sets as [$name, $on, $md5, $date]):
	$downloaded = $on && trim($md5) !== '' && $md5 !== 'Not Downloaded';
?>
				<tr<?=$on ? '' : ' class="fs-row-disabled"'?>>
					<td><?=!$on ? fs_badge('disabled') : ($downloaded ? fs_badge('pass', gettext('Installed')) : fs_badge('warn', gettext('Not downloaded')))?></td>
					<td><?=htmlspecialchars($name)?></td>
					<td class="fs-mono small"><?=$downloaded ? htmlspecialchars(trim($md5)) : '<span class="fs-muted">&ndash;</span>'?></td>
					<td class="small"><?=$downloaded ? htmlspecialchars($date) : '<span class="fs-muted">&ndash;</span>'?></td>
				</tr>
<?php endforeach; ?>
			</tbody>
		</table>
	</div>
	<div class="panel-footer small fs-muted">
		<i class="fa-solid fa-circle-info" aria-hidden="true"></i>
		<?=gettext('The rule download sites are occasionally unavailable. If an update fails, try again later.')?>
	</div>
</div>

<form action="suricata_download_updates.php" enctype="multipart/form-data" method="post" name="iform" id="iform">
<div class="panel panel-default">
	<div class="panel-heading">
		<h2 class="panel-title"><?=gettext("Update log")?></h2>
	</div>
	<div class="panel-body suri-pad">
<?php if ($suricata_rules_upd_log_chk == 'yes'): ?>
		<div class="d-flex flex-wrap gap-2 mb-2">
<?php if (!empty($contents)): ?>
			<button type="submit" value="<?=gettext("Hide"); ?>" name="hide" id="hide" class="btn btn-sm btn-outline-secondary">
				<i class="fa-solid fa-eye-slash icon-embed-btn" aria-hidden="true"></i><?=gettext("Hide log"); ?>
			</button>
<?php else: ?>
			<button type="submit" value="<?=gettext("View"); ?>" name="view" id="view" class="btn btn-sm btn-outline-secondary">
				<i class="fa-regular fa-file-lines icon-embed-btn" aria-hidden="true"></i><?=gettext("View log"); ?>
			</button>
<?php endif; ?>
			<button type="submit" value="<?=gettext("Clear"); ?>" name="clear" id="clear" class="btn btn-sm btn-outline-danger"
				data-fs-confirm="<?=gettext('Clear the rule update log?')?>" data-fs-confirm-action="<?=gettext('Clear')?>">
				<i class="fa-solid fa-trash-can icon-embed-btn" aria-hidden="true"></i><?=gettext("Clear log"); ?>
			</button>
		</div>
<?php else: ?>
		<p class="fs-muted mb-2"><?=gettext("The update log is empty."); ?></p>
<?php endif; ?>
		<p class="small fs-muted mb-0"><?=gettext("The log is limited to 1024 KB and is cleared automatically when it grows larger."); ?></p>
	</div>
<?php if (!empty($contents)): ?>
	<pre class="fs-console" id="suri-updlog"><?=htmlspecialchars($contents)?></pre>
<?php endif; ?>
</div>
</form>

<?php

// "Please wait" dialog shown while the rule sets update
$form = new Form(FALSE);
$modal = new Modal('Updating rules', 'updrulesdlg', false, 'Close');
$modal->addInput(new Form_StaticText (
	null,
	'<p><i class="fa-solid fa-spinner fa-spin-pulse" aria-hidden="true"></i> ' . gettext('Updating the rule sets can take a while.') . '</p>' .
	'<p class="fs-muted mb-0">' . gettext('This dialog closes automatically when the update has finished.') . '</p>'
));
$form->add($modal);
print $form;
?>

<script type="text/javascript">
//<![CDATA[

function checkUpdateStatus(pid) {
	//See if update process is still running
	var repeat = true;
	var ajaxRequest2;
	var processID = pid;
	ajaxRequest2 = $.ajax({
		url: "suricata_download_updates.php",
		type: "post",
		data: { ajax: 'status',
			pid: processID
		      }
	});

	ajaxRequest2.done(function (response, textStatus, jqXHR) {
		if (response == "DONE") {
			// Close the "please wait" modal
			$('#updrulesdlg').modal('hide');
			repeat = false;

			// Reload the page to refresh displayed data
			location.reload(true);
		}
		else {
			repeat = true;
		}
		if (repeat) {
			setTimeout(function(){
				checkUpdateStatus(pid);
				}, 500);
		}
	});
}

function doRuleUpdates(mode) {
	var ajaxRequest1;
	if (typeof mode == "undefined") {
		var mode = "update";
	}

	// Show the "please wait" modal
	$('#updrulesdlg').modal('show');

	if (mode == "update") {
		$('#updbtn').toggleClass('fa-check fa-solid fa-spinner');
	}
	if (mode == "force") {
		$('#forcebtn').toggleClass('fa-download fa-solid fa-spinner');
	}

	ajaxRequest1 = $.ajax({
		url: "suricata_download_updates.php",
		type: "post",
		data: { updatemode: mode }
	});

	// Deal with the results of the above ajax call
	ajaxRequest1.done(function (response, textStatus, jqXHR) {
		checkUpdateStatus(response);
	});
}

events.push(function(){

	//-- Click handlers ---------------------------------
	$('#update').click(function() {
		doRuleUpdates('update');
		return false;
	});

	$('#force').click(function() {
		doRuleUpdates('force');
		return false;
	});

});
//]]>
</script>

<?php include("foot.inc"); ?>

