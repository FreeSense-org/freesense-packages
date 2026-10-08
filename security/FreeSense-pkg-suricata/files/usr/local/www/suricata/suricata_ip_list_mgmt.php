<?php
/*
 * suricata_ip_list_mgmt.php
 *
 * part of FreeSense (https://www.freesense.org)
 * Copyright (c) 2006-2026 Rubicon Communications, LLC (Netgate)
 * Copyright (c) 2025-2026 The FreeSense Project
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

// Hard-code the path where IP Lists are stored
// and disregard any user-supplied path element.
$iprep_path = SURICATA_IPREP_PATH;

// Set default to not show IP List editor controls
$iplist_edit_style = "display: none;";

function suricata_is_iplist_active($iplist) {

	/***************************************************
	 * This function checks all configured Suricata	   *
	 * interfaces to see if the passed IP List is used *
	 * as a whitelist or blacklist by an interface.	   *
	 *                                                 *
	 * Returns: TRUE  if IP List is in use             *
	 *          FALSE if IP List is not in use         *
	 ***************************************************/

	foreach (config_get_path('installedpackages/suricata/rule', []) as $rule) {
		foreach (array_get_path($rule, 'iplist_files/item', []) as $file) {
			if ($file == $iplist)
				return TRUE;
		}
	}
	return FALSE;
}

// If doing a postback, used typed values, else load from stored config
if (!empty($_POST)) {
	$pconfig = $_POST;
}
else {
	$pconfig['et_iqrisk_enable'] = config_get_path('installedpackages/suricata/config/0/et_iqrisk_enable');
	$pconfig['iqrisk_code'] = htmlentities(config_get_path('installedpackages/suricata/config/0/iqrisk_code'));
}

// Validate IQRisk settings if enabled and saving them
if ($_POST['save']) {
	if ($pconfig['et_iqrisk_enable'] == 'on' && empty($pconfig['iqrisk_code']))
		$input_errors[] = gettext("You must provide a valid IQRisk subscription code when IQRisk downloads are enabled!");

	if (!$input_errors) {
		config_set_path('installedpackages/suricata/config/0/et_iqrisk_enable', $_POST['et_iqrisk_enable'] ? 'on' : 'off');
		config_set_path('installedpackages/suricata/config/0/iqrisk_code', trim(html_entity_decode($_POST['iqrisk_code'])));
		write_config("Suricata pkg: modified IP Lists settings.");

		/* Toggle cron task for ET IQRisk updates if setting was changed */
		if (config_get_path('installedpackages/suricata/config/0/et_iqrisk_enable') == 'on' && !suricata_cron_job_exists("/usr/local/pkg/suricata/suricata_etiqrisk_update.php")) {
			install_cron_job("/usr/bin/nice -n20 /usr/local/bin/php-cgi -f /usr/local/pkg/suricata/suricata_etiqrisk_update.php", TRUE, 0, "*/6", "*", "*", "*", "root");
		}
		elseif (config_get_path('installedpackages/suricata/config/0/et_iqrisk_enable') == 'off' && suricata_cron_job_exists("/usr/local/pkg/suricata/suricata_etiqrisk_update.php"))
			install_cron_job("/usr/local/pkg/suricata/suricata_etiqrisk_update.php", FALSE);

		/* Peform a manual ET IQRisk file check/download */
		if (config_get_path('installedpackages/suricata/config/0/et_iqrisk_enable') == 'on')
			include("/usr/local/pkg/suricata/suricata_etiqrisk_update.php");
	}
}

if (isset($_POST['upload'])) {
	if ($_FILES["iprep_fileup"]["error"] == UPLOAD_ERR_OK) {
		$tmp_name = $_FILES["iprep_fileup"]["tmp_name"];
		$name = basename($_FILES["iprep_fileup"]["name"]);
		if (!preg_match('/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/', $name) ||
		    (int)$_FILES["iprep_fileup"]["size"] > 16 * 1024 * 1024) {
			$input_errors[] = gettext('The IP list filename or size is invalid.');
		} elseif (!move_uploaded_file($tmp_name, "{$iprep_path}{$name}")) {
			$input_errors[] = gettext('Failed to store the uploaded IP list.');
		} else {
			chmod("{$iprep_path}{$name}", 0600);
		}
	}
	else
		$input_errors[] = gettext("Failed to upload file {$_FILES["iprep_fileup"]["name"]}");
}

if (isset($_POST['iplist_action']) && isset($_POST['iplist_fname'])) {
	$_POST['iplist_fname'] = basename($_POST['iplist_fname']);
	switch ($_POST['iplist_action']) {
		case 'delete':
			if (!suricata_is_iplist_active($_POST['iplist_fname']))
				unlink_if_exists("{$iprep_path}{$_POST['iplist_fname']}");
			else
				$input_errors[] = gettext("This IP List is currently assigned as a Whitelist or Blackist for an interface and cannot be deleted.");
			break;

		case 'edit':
			$file = $iprep_path . basename($_POST['iplist_fname']);
			$data = file_get_contents($file);
			if ($data !== FALSE) {
				$iplist_data = htmlspecialchars($data);
				$iplist_edit_style = "display: table-row-group;";
				$iplist_name = basename($_POST['iplist_fname']);
				unset($data);
			}
			else {
				$input_errors[] = gettext("An error occurred reading the file.");
			}
			break;

		default:
	}
}

if (isset($_POST['iplist_edit_save']) && isset($_POST['iplist_data'])) {
	if (strlen(basename($_POST['iplist_name'])) > 0) {
		$file = $iprep_path . basename($_POST['iplist_name']);
		$data = str_replace("\r\n", "\n", $_POST['iplist_data']);
		file_put_contents($file, $data);
		unset($data);
	}
	else {
		$input_errors[] = gettext("You must provide a valid filename for the IP List.");
		$iplist_edit_style = "display: table-row-group;";
	}
}

// Get all files in the IP Lists sub-directory as an array
// Leave this as the last thing before spewing the page HTML
// so we can pick up any changes made to files in code above.
$ipfiles = return_dir_as_array($iprep_path);

$pglinks = array("", "/suricata/suricata_overview.php", "@self");
$pgtitle = array(gettext("Services"), gettext("Suricata"), gettext("IP reputation files"));
fs_page_action(gettext('Add IP list'), '#', 'fa-plus', 'primary', [
	'data-fs-modal' => '#iplist-editor',
	'data-fs-modal-title' => gettext('Add IP list'),
	'data-fs-fill' => json_encode(['iplist_name' => '', 'iplist_data' => '']),
]);
fs_page_action(gettext('Upload'), '#', 'fa-upload', 'secondary', ['data-fs-modal' => '#iplist-upload']);

include_once("head.inc");

if ($input_errors) {
	print_input_errors($input_errors);
}

if ($savemsg) {
	print_info_box($savemsg);
}

suricata_display_primary_navigation('lists');
suricata_display_section_navigation('lists', 'iplists');

$form = new Form;
$section = new Form_Section('Emerging Threats IQRisk', 'iprep-iqrisk');
$section->addInput(new Form_Checkbox(
	'et_iqrisk_enable',
	'IQRisk downloads',
	'Download IQRisk IP list updates with a subscription code',
	$pconfig['et_iqrisk_enable'] == 'on' ? true:false,
	'on'
))->setHelp('The lists update every night at midnight. <a href="https://www.proofpoint.com/us/products/et-intelligence" target="_blank" rel="noopener">About ET Intelligence subscriptions</a>.');
$section->addInput(new Form_Input(
	'iqrisk_code',
	'IQRisk subscription code',
	'text',
	$pconfig['iqrisk_code']
))->setHelp('The subscription code from your ET Intelligence account.');
$form->add($section);
print $form;

$editor_open = ($iplist_edit_style !== "display: none;");
?>

<div class="panel panel-default fs-table">
<?php fs_table_toolbar([
	'title' => gettext('IP list files'),
	'search' => gettext('Search files…'),
	'noun' => gettext('files'),
	'noun_one' => gettext('file'),
]); ?>
	<div class="panel-body table-responsive">
		<table class="table table-hover" data-sortable>
			<thead>
				<tr>
					<th data-fs-search><?=gettext("File name")?></th>
					<th><?=gettext("In use")?></th>
					<th><?=gettext("Modified")?></th>
					<th><?=gettext("Size")?></th>
					<th class="fs-col-actions"><span class="visually-hidden"><?=gettext("Actions")?></span></th>
				</tr>
			</thead>
			<tbody>
<?php
$shown = 0;
foreach ($ipfiles as $file):
	if (substr(strrchr($file, "."), 1) == "md5") {
		continue;
	}
	$shown++;
	$active = suricata_is_iplist_active($file);
	$q = rawurlencode($file);
?>
				<tr>
					<td class="fs-mono"><?=htmlspecialchars($file)?></td>
					<td><?=$active ? fs_badge('active', gettext('In use')) : fs_badge('idle', gettext('Not used'))?></td>
					<td class="small"><?=htmlspecialchars(date('Y-m-d H:i', filemtime("{$iprep_path}{$file}")))?></td>
					<td class="fs-mono small"><?=htmlspecialchars(format_bytes(filesize("{$iprep_path}{$file}")))?></td>
					<td class="fs-col-actions"><?=fs_row_actions([
						['edit', "suricata_ip_list_mgmt.php?iplist_action=edit&iplist_fname={$q}", $file, ['attrs' => ['usepost' => '']]],
						['delete', "suricata_ip_list_mgmt.php?iplist_action=delete&iplist_fname={$q}", $file, [
							'thing' => gettext('IP list'),
							'detail' => $active ? gettext('It is assigned to an interface and cannot be deleted until it is unassigned.') : gettext('The file is removed from the firewall.'),
						]],
					])?></td>
				</tr>
<?php endforeach; ?>
<?php if ($shown == 0) {
	fs_empty_row(5, gettext('No IP list files yet. Add or upload a list.'));
} ?>
			</tbody>
		</table>
	</div>
	<div class="panel-footer small fs-muted">
		<i class="fa-solid fa-circle-info" aria-hidden="true"></i>
		<?=gettext('A categories file (category number, short name, description per line) is required. IP lists are CSV files with an IP address, category and reputation score per line. They are stored on the firewall, not in the configuration.')?>
		<a href="https://docs.suricata.io/en/latest/reputation/ipreputation/ip-reputation-format.html" target="_blank" rel="noopener"><?=gettext('File format')?></a>
	</div>
</div>

<div class="modal fade fs-modal-form" id="iplist-editor" tabindex="-1" aria-labelledby="iplist-editor-title" aria-hidden="true"<?=$editor_open ? ' data-fs-open' : ''?>>
	<div class="modal-dialog modal-lg modal-dialog-centered modal-dialog-scrollable"><div class="modal-content">
	<form action="/suricata/suricata_ip_list_mgmt.php" method="post">
		<div class="modal-header">
			<h2 class="modal-title" id="iplist-editor-title"><?=$iplist_name ? gettext('Edit IP list') : gettext('Add IP list')?></h2>
			<button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="<?=gettext('Close')?>"></button>
		</div>
		<div class="modal-body">
			<div class="mb-3">
				<label class="form-label" for="iplist_name"><?=gettext('File name')?></label>
				<input type="text" class="form-control fs-mono" id="iplist_name" name="iplist_name" value="<?=htmlspecialchars($iplist_name)?>" autocomplete="off">
			</div>
			<div>
				<label class="form-label" for="iplist_data"><?=gettext('Contents')?></label>
				<textarea class="form-control fs-mono" wrap="off" rows="16" name="iplist_data" id="iplist_data"><?=$iplist_data?></textarea>
			</div>
		</div>
		<div class="modal-footer">
			<button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal"><?=gettext('Cancel')?></button>
			<button type="submit" class="btn btn-primary" id="iplist_edit_save" name="iplist_edit_save" value="<?=gettext(" Save ")?>"><i class="fa-solid fa-floppy-disk icon-embed-btn" aria-hidden="true"></i><?=gettext('Save')?></button>
		</div>
	</form>
	</div></div>
</div>

<div class="modal fade fs-modal-form" id="iplist-upload" tabindex="-1" aria-labelledby="iplist-upload-title" aria-hidden="true">
	<div class="modal-dialog modal-dialog-centered"><div class="modal-content">
	<form action="/suricata/suricata_ip_list_mgmt.php" enctype="multipart/form-data" method="post">
		<input type="hidden" name="MAX_FILE_SIZE" value="100000000" />
		<div class="modal-header">
			<h2 class="modal-title" id="iplist-upload-title"><?=gettext('Upload IP list')?></h2>
			<button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="<?=gettext('Close')?>"></button>
		</div>
		<div class="modal-body">
			<label class="form-label" for="iprep_fileup"><?=gettext('File')?></label>
			<input type="file" class="form-control" name="iprep_fileup" id="iprep_fileup">
			<div class="form-text"><?=gettext('Up to 16 MB. Letters, digits, dot, dash and underscore in the file name.')?></div>
		</div>
		<div class="modal-footer">
			<button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal"><?=gettext('Cancel')?></button>
			<button type="submit" class="btn btn-primary" name="upload" id="upload" value="<?=gettext("Upload")?>"><i class="fa-solid fa-upload icon-embed-btn" aria-hidden="true"></i><?=gettext('Upload')?></button>
		</div>
	</form>
	</div></div>
</div>

<script type="text/javascript">
//<![CDATA[
	events.push(function(){

		function et_iqrisk_enable() {
			var hide = ! $('#et_iqrisk_enable').prop('checked');
			hideInput('iqrisk_code', hide);
		}

		$('#et_iqrisk_enable').click(function() {
			et_iqrisk_enable();
		});

		et_iqrisk_enable();
	});
//]]>
</script>

<?php include("foot.inc"); ?>
