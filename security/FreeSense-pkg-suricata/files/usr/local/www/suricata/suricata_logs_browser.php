<?php
/*
 * suricata_logs_browser.php
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

if (isset($_POST['instance']) && is_numericint($_POST['instance']))
	$instanceid = $_POST['instance'];
elseif (isset($_GET['instance']) && is_numericint($_GET['instance']))
	$instanceid = htmlspecialchars($_GET['instance']);
if (empty($instanceid))
	$instanceid = 0;

$a_instance = config_get_path('installedpackages/suricata/rule', []);
$suricata_uuid = config_get_path("installedpackages/suricata/rule/{$instanceid}/uuid", '');
$if_real = get_real_interface(config_get_path("installedpackages/suricata/rule/{$instanceid}/interface", ''));

// Construct a pointer to the instance's logging subdirectory
$suricatalogdir = SURICATALOGDIR . "suricata_{$if_real}{$suricata_uuid}/";

// Limit all file access to just the currently selected interface's logging subdirectory
$logfile = htmlspecialchars($suricatalogdir . basename($_POST['file']));

if ($_POST['action'] == 'load') {
	if(!is_file($logfile)) {
		echo "|3|" . gettext("Log file does not exist or that logging feature is not enabled") . ".|";
	} else {
		$data = file_get_contents($logfile);
		if($data === false) {
			echo "|1|" . gettext("Failed to read log file") . ".|";
		} else {
			$data = base64_encode($data);
			echo "|0|{$logfile}|{$data}|";
		}
	}

	exit;
}

if ($_POST['action'] == 'clear') {
	if (basename($logfile) == "sid_changes.log") {
		file_put_contents($logfile, "");
	}

	exit;
}

function build_instance_list() {
	$list = array();

	foreach (config_get_path('installedpackages/suricata/rule', []) as $id => $instance) {
		$list[$id] = '(' . convert_friendly_interface_to_friendly_descr($instance['interface']) . ') ' . $instance['descr'];
	}

	return($list);
}

function build_logfile_list() {
	global $suricatalogdir;

	$list = array();

	$logs = array( "alerts.log", "block.log", "eve.json", "files-json.log", "http.log", "sid_changes.log", "stats.log", "suricata.log", "tls.log" );
	foreach ($logs as $log) {
		$list[$suricatalogdir . $log] = $log;
	}

	return($list);
}

$pglinks = array("", "/suricata/suricata_overview.php", "/suricata/suricata_events.php", "@self");
$pgtitle = array(gettext("Services"), gettext("Suricata"), gettext("Events"), gettext("Log files"));
include_once("head.inc");
suricata_display_primary_navigation('events');

suricata_display_section_navigation('events', 'logs');

if ($input_errors) {
	print_input_errors($input_errors);
}
if ($savemsg) {
	print_info_box($savemsg);
}
?>

<style>
.sf-logpath { overflow-wrap: anywhere; }
.sf-result-actions { display: flex; flex-wrap: wrap; gap: .4rem; margin-left: auto; }
#fileStatus.is-error { color: var(--fs-block); }
</style>

<div class="fs-tool">
	<form class="fs-tool-form" action="/suricata/suricata_logs_browser.php" method="post" id="sf-logform">
		<div class="panel panel-default">
			<div class="panel-heading"><h2 class="panel-title"><?=gettext('Log file')?></h2></div>
			<div class="panel-body">
				<div>
					<label class="form-label" for="instance"><?=gettext('Interface')?></label>
					<select class="form-select" name="instance" id="instance">
<?php foreach (build_instance_list() as $k => $v): ?>
						<option value="<?=fs_h($k)?>"<?=((string)$k === (string)$instanceid) ? ' selected' : ''?>><?=fs_h($v)?></option>
<?php endforeach; ?>
					</select>
				</div>
				<div>
					<label class="form-label" for="logFile"><?=gettext('Log')?></label>
					<select class="form-select" name="logFile" id="logFile">
						<option value="" disabled<?=empty($_POST['file']) ? ' selected' : ''?>><?=gettext('Choose a log file')?></option>
<?php foreach (build_logfile_list() as $k => $v): ?>
						<option value="<?=fs_h($k)?>"<?=(!empty($_POST['file']) && basename($logfile) === $v) ? ' selected' : ''?>><?=fs_h($v)?></option>
<?php endforeach; ?>
					</select>
					<div class="form-text help-block"><?=gettext('Only the log folder of the chosen interface is read.')?></div>
				</div>
			</div>
			<div class="panel-footer">
				<button type="button" class="btn btn-primary" id="sf-view"><i class="fa-solid fa-eye icon-embed-btn" aria-hidden="true"></i><?=gettext('View')?></button>
			</div>
		</div>
	</form>
	<div class="panel panel-default" id="fileOutput">
		<div class="panel-heading">
			<h2 class="panel-title"><?=gettext('Contents')?></h2>
			<div class="sf-result-actions" id="fileRefreshBtn" hidden>
				<button type="button" class="btn btn-sm btn-outline-secondary" id="refresh" title="<?=gettext('Refresh current display')?>"><i class="fa-solid fa-arrow-rotate-right icon-embed-btn" aria-hidden="true"></i><?=gettext('Refresh')?></button>
				<button type="button" class="btn btn-sm btn-outline-secondary" data-fs-copy="#fileContent"><i class="fa-regular fa-copy icon-embed-btn" aria-hidden="true"></i><?=gettext('Copy')?></button>
				<button type="button" class="btn btn-sm btn-outline-danger" id="fileClearBtn" hidden title="<?=gettext('Clear selected log file contents')?>"><i class="fa-solid fa-trash-can icon-embed-btn" aria-hidden="true"></i><?=gettext('Clear')?></button>
			</div>
		</div>
		<div class="fs-tool-verdict" id="filePathBox" hidden>
			<span id="fileStatus" role="status"></span>
			<span class="fs-mono fs-muted sf-logpath" id="fbTarget"></span>
		</div>
		<pre class="fs-console" id="fileContent" hidden></pre>
		<div class="fs-tool-empty" id="fileEmpty"><i class="fa-solid fa-file-lines" aria-hidden="true"></i><span><?=gettext('Choose an interface and a log file to view it.')?></span></div>
	</div>
</div>

<script>
//<![CDATA[
events.push(function() {
	var page = "/suricata/suricata_logs_browser.php";

	function basename(path) {
		return path.replace(/\\/g, '/').replace(/.*\//, '');
	}

	function showMessage(text, isError) {
		$('#filePathBox').prop('hidden', false);
		$('#fileStatus').text(text).toggleClass('is-error', !!isError);
	}

	function loadFile() {
		var file = $('#logFile').val();
		if (!file) {
			return;
		}
		$('#fileEmpty').prop('hidden', true);
		$('#fbTarget').text('');
		showMessage(<?=json_encode(gettext('Loading file…'))?>, false);
		$.ajax(page, {
			type: 'post',
			data: {instance: $('#instance').val(), action: 'load', file: file},
			complete: loadComplete
		});
	}

	function loadComplete(req) {
		var values = req.responseText.split('|');
		values.shift(); values.pop();

		if (values.shift() == '0') {
			var file = values.shift();
			var text = '';
			try { text = atob(values.join('|')); } catch (e) { text = ''; }
			showMessage(<?=json_encode(gettext('Loaded'))?>, false);
			$('#fbTarget').text(file);
			$('#fileRefreshBtn').prop('hidden', false);
			$('#fileClearBtn').prop('hidden', basename(file) != 'sid_changes.log');
			$('#fileContent').text(text).prop('hidden', false);
		} else {
			showMessage(values[0] || <?=json_encode(gettext('The log file could not be read.'))?>, true);
			$('#fbTarget').text(<?=json_encode(gettext('Not available'))?>);
			$('#fileRefreshBtn').prop('hidden', true);
			$('#fileContent').text('').prop('hidden', true);
			$('#fileEmpty').prop('hidden', false);
		}
	}

	function clearFile() {
		window.fsConfirm({
			title: <?=json_encode(gettext('Clear the contents of sid_changes.log?'))?>,
			detail: <?=json_encode(gettext('The log of SID changes for this interface is emptied.'))?>,
			action: <?=json_encode(gettext('Clear'))?>,
			returnFocus: document.getElementById('fileClearBtn')
		}).then(function(yes) {
			if (!yes) {
				return;
			}
			$.ajax(page, {
				type: 'post',
				data: {instance: $('#instance').val(), action: 'clear', file: $('#logFile').val()}
			});
			$('#fileContent').text('');
		});
	}

	$('#logFile, #instance').on('change', loadFile);
	$('#refresh, #sf-view').on('click', loadFile);
	$('#fileClearBtn').on('click', clearFile);
});
//]]>
</script>

<?php include("foot.inc"); ?>
