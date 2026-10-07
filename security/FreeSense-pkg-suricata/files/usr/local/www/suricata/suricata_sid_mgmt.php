<?php
/*
 * suricata_sid_mgmt.php
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

global $g, $rebuild_rules;

$suricatadir = SURICATADIR;
$pconfig = array();

// Grab saved settings from configuration
$a_nat = config_get_path('installedpackages/suricata/rule', []);
$a_list = config_get_path('installedpackages/suricata/sid_mgmt_lists/item', []);
$pconfig['auto_manage_sids'] = config_get_path('installedpackages/suricata/config/0/auto_manage_sids');

// Set default to not show SID modification lists editor controls
$sidmodlist_edit_style = "display: none;";

if (!empty($_POST))
	$pconfig = $_POST;

function suricata_is_sidmodslist_active($sidlist) {

	/*****************************************************
	 * This function checks all the configured Suricata  *
	 * interfaces to see if the passed SID Mods List is  *
	 * used by an interface.                             *
	 *                                                   *
	 * Returns: TRUE  if List is in use                  *
	 *          FALSE if List can be deleted             *
	 *****************************************************/

	foreach (config_get_path('installedpackages/suricata/rule', []) as $rule) {
		if ($rule['enable_sid_file'] == $sidlist) {
			return TRUE;
		}
		if ($rule['disable_sid_file'] == $sidlist) {
			return TRUE;
		}
		if ($rule['modify_sid_file'] == $sidlist) {
			return TRUE;
		}

		// The tests below let the user remove an assigned
		// DROP_SID or REJECT_SID list from an interface
		// that now uses a mode where these list types
		// are no longer applicable.
		if ($rule['blockoffenders'] == 'on' && ($rule['ips_mode'] == 'ips_mode_inline' || $rule['block_drops_only'] == 'on')) {
			if ($rule['drop_sid_file'] == $sidlist) {
				return TRUE;
			}
		}
		if ($rule['blockoffenders'] == 'on' && $rule['ips_mode'] == 'ips_mode_inline') {
			if ($rule['reject_sid_file'] == $sidlist) {
				return TRUE;
			}
		}
	}
	return FALSE;
}

if (isset($_POST['upload'])) {
	if ($_FILES["sidmods_fileup"]["error"] == UPLOAD_ERR_OK) {
		$tmp = array();
		$tmp['name'] = basename($_FILES["sidmods_fileup"]["name"]);
		$tmp['modtime'] = time();
		$tmp_fname = $_FILES["sidmods_fileup"]["tmp_name"];
		$data = file_get_contents($tmp_fname);
		$tmp['content'] = base64_encode(str_replace("\r\n", "\n", $data));

		// Check for duplicate conflicting list name
		foreach ($a_list as $list) {
			if ($list['name'] == $tmp['name']) {
				$input_errors[] = gettext("A list with that name already exists!  Please choose a different name for the list being uploaded.");
				break;
			}
		}
		if (!$input_errors) {
			$a_list[] = $tmp;

			// Write the new configuration
			config_set_path('installedpackages/suricata/sid_mgmt_lists/item', $a_list);
			write_config("Suricata pkg: Uploaded new automatic SID management list.");
		}
	}
	else
		$input_errors[] = gettext("Failed to upload file {$_FILES["sidmods_fileup"]["name"]}");
}

if (isset($_POST['sidlist_delete']) && isset($a_list[$_POST['sidlist_id']])) {
	if (!suricata_is_sidmodslist_active($a_list[$_POST['sidlist_id']]['name'])) {

		// Remove the list from DROP_SID or REJECT_SID if assigned on any interface.
		foreach($a_nat as $k => $rule) {
			if ($rule['drop_sid_file'] == $a_list[$_POST['sidlist_id']]['name']) {
				unset($a_nat[$k]['drop_sid_file']);
			}
			if ($rule['reject_sid_file'] == $a_list[$_POST['sidlist_id']]['name']) {
				unset($a_nat[$k]['reject_sid_file']);
			}
		}

		// Now delete the list itself
		unset($a_list[$_POST['sidlist_id']]);

		// Write the new configuration
		config_set_path('installedpackages/suricata/rule', $a_nat);
		config_set_path('installedpackages/suricata/sid_mgmt_lists/item', $a_list);
		write_config("Suricata pkg: deleted automatic SID management list.");
	}
	else {
		$input_errors[] = gettext("This SID Mods List is currently assigned to an interface and cannot be deleted until the assignment is removed.");
	}
}

if (isset($_POST['sidlist_edit']) && isset($a_list[$_POST['sidlist_id']])) {
	$data = base64_decode($a_list[$_POST['sidlist_id']]['content']);
	$sidmodlist_data = htmlspecialchars($data);
	$sidmodlist_edit_style = "show";
	$sidmodlist_name = $a_list[$_POST['sidlist_id']]['name'];
	$sidmodlist_id = $_POST['sidlist_id'];
	unset($data);
}

if (isset($_POST['save']) && isset($_POST['sidlist_data']) && isset($_POST['listid'])) {
	if (strlen($_POST['sidlist_name']) > 0) {
		$tmp = array();
		$tmp['name'] = basename($_POST['sidlist_name']);
		$tmp['modtime'] = time();
		$tmp['content'] = base64_encode(str_replace("\r\n", "\n", $_POST['sidlist_data']));

		// If this test is TRUE, then we are adding a new list
		if ($_POST['listid'] == count($a_list)) {
			$a_list[] = $tmp;

			// Write the new configuration
			config_set_path('installedpackages/suricata/sid_mgmt_lists/item', $a_list);
			write_config("Suricata pkg: added new automatic SID management list.");
		}
		else {
			$a_list[$_POST['listid']] = $tmp;

			// Write the new configuration
			config_set_path('installedpackages/suricata/sid_mgmt_lists/item', $a_list);
			write_config("Suricata pkg: updated automatic SID management list.");
		}
		unset($tmp);
	}
	else {
		$input_errors[] = gettext("You must provide a valid name for the new SID Mods List.");
		$sidmodlist_edit_style = "display: table-row-group;";
	}
}

if (isset($_POST['save_auto_sid_conf'])) {
	config_set_path('installedpackages/suricata/config/0/auto_manage_sids', $pconfig['auto_manage_sids'] ? "on" : "off");

	// Grab the SID Mods config for the interfaces from the form's controls array
	foreach ($_POST['sid_state_order'] as $k => $v) {
		$a_nat[$k]['sid_state_order'] = $v;
	}
	foreach ($_POST['enable_sid_file'] as $k => $v) {
		if (strcasecmp($v, "None") == 0) {
			unset($a_nat[$k]['enable_sid_file']);
			continue;
		}
		$a_nat[$k]['enable_sid_file'] = $v;
	}
	foreach ($_POST['disable_sid_file'] as $k => $v) {
		if (strcasecmp($v, "None") == 0) {
			unset($a_nat[$k]['disable_sid_file']);
			continue;
		}
		$a_nat[$k]['disable_sid_file'] = $v;
	}
	foreach ($_POST['modify_sid_file'] as $k => $v) {
		if (strcasecmp($v, "None") == 0) {
			unset($a_nat[$k]['modify_sid_file']);
			continue;
		}
		$a_nat[$k]['modify_sid_file'] = $v;
	}

	foreach ($_POST['drop_sid_file'] as $k => $v) {
		if (strcasecmp($v, "None") == 0) {
			unset($a_nat[$k]['drop_sid_file']);
			continue;
		}
		$a_nat[$k]['drop_sid_file'] = $v;
	}

	foreach ($_POST['reject_sid_file'] as $k => $v) {
		if (strcasecmp($v, "None") == 0) {
			unset($a_nat[$k]['reject_sid_file']);
			continue;
		}
		$a_nat[$k]['reject_sid_file'] = $v;
	}

	// Write the new configuration
	config_set_path('installedpackages/suricata/rule', $a_nat);
	write_config("Suricata pkg: updated automatic SID management settings.");

	$intf_msg = "";

	// If any interfaces were marked for restart, then do it
	if (is_array($_POST['torestart'])) {
		foreach ($_POST['torestart'] as $k) {
			// Update the suricata.yaml file and
			// rebuild rules for this interface.
			$rebuild_rules = true;
			suricata_generate_yaml($a_nat[$k]);
			$rebuild_rules = false;

			// Signal Suricata to "live reload" the rules
			suricata_reload_config($a_nat[$k]);

			$intf_msg .= convert_friendly_interface_to_friendly_descr($a_nat[$k]['interface']) . ", ";
		}
		$savemsg = gettext("Changes were applied to these interfaces: " . trim($intf_msg, ' ,') . " and Suricata signaled to live-load the new rules.");

		// Sync to configured CARP slaves if any are enabled
		suricata_sync_on_changes();
	}
}

if (isset($_POST['sidlist_dnload']) &&
    isset($_POST['sidlist_id'])) {
	if (array_key_exists($_POST['sidlist_id'], $a_list)) {
		send_user_download('data',
					base64_decode($a_list[$_POST['sidlist_id']]['content']),
					basename($a_list[$_POST['sidlist_id']]['name']));
	} else {
		$savemsg = gettext("Unable to locate the list specified!");
	}
}

if (isset($_POST['sidlist_dnload_all'])) {
	$file_path = g_get('tmp_path') . '/suricata_sid_conf_files_' . date("Y-m-d-H-i-s") . '.tar.gz';

	// Create a temporary directory to hold the lists as individual files
	$tmpdirname = g_get('tmp_path') . '/sidmods/';
	safe_mkdir($tmpdirname);

	// Walk all saved lists and write them out to individual files
	foreach($a_list as $list) {
		file_put_contents($tmpdirname . basename($list['name']), base64_decode($list['content']));
		touch($tmpdirname . basename($list['name']), $list['modtime']);
	}

	// Put all the files into a single tar gzip archive
	exec('/usr/bin/tar -C ' . escapeshellarg($tmpdirname) . ' --strip-components 1 -czf ' . escapeshellarg($file_path) . ' .');

	if (file_exists($file_path)) {
		// Remove all the temporary files and directory if created
		if (is_dir($tmpdirname)) {
			rmdir_recursive($tmpdirname);
		}
		send_user_download('file', $file_path);
		unlink_if_exists($file_path);
		exit;
	} else {
		$savemsg = gettext("An error occurred while creating the gzip archive!");
	}

	// Remove all the temporary files and directory if created
	if (is_dir($tmpdirname)) {
		rmdir_recursive($tmpdirname);
	}
	unlink_if_exists($file_path);
}

// Get all the SID Mods Lists as an array
// Leave this as the last thing before spewing the page HTML
// so we can pick up any changes made in code above.
$sidmodlists = config_get_path('installedpackages/suricata/sid_mgmt_lists/item', []);
$sidmodselections = Array();
$sidmodselections[] = "None";
foreach ($sidmodlists as $list) {
	$sidmodselections[] = $list['name'];
}

$pglinks = array("", "/suricata/suricata_overview.php", "@self");
$pgtitle = array(gettext("Services"), gettext("Suricata"), gettext("SID management"));
fs_page_action(gettext('Add list'), '#', 'fa-plus', 'primary', [
	'data-fs-modal' => '#sidlist_editor',
	'data-fs-modal-title' => gettext('Add SID management list'),
	'data-fs-fill' => json_encode(['listid' => count($a_list), 'sidlist_name' => '', 'sidlist_data' => '']),
]);
fs_page_action(gettext('Import'), '#', 'fa-upload', 'secondary', ['data-fs-modal' => '#uploader']);
if (!empty($sidmodlists)) {
	fs_page_action(gettext('Download all'), 'suricata_sid_mgmt.php?sidlist_dnload_all=1', 'fa-download', 'secondary', ['usepost' => '']);
}
include_once("head.inc");

/* Display Alert message, under form tag or no refresh */
if ($input_errors) {
	print_input_errors($input_errors);
}

if ($savemsg) {
	print_info_box($savemsg, 'success');
}

suricata_display_primary_navigation('policies');
suricata_display_section_navigation('policies', 'sid');

$editor_open = ($sidmodlist_edit_style != "display: none;");

/* <select> for one interface/list-type cell; keeps the original names and ids */
$sid_select = function ($field, $k, $current, $choices, $label) {
	$html = '<select name="' . $field . '[' . $k . ']" id="' . $field . '[' . $k . ']" class="form-select form-select-sm" aria-label="' . htmlspecialchars($label) . '">';
	foreach ($choices as $value => $text) {
		$html .= '<option value="' . htmlspecialchars($value) . '"' . (($value == $current) ? ' selected' : '') . '>' . htmlspecialchars($text) . '</option>';
	}
	return $html . '</select>';
};
$list_choices = array_combine($sidmodselections, array_map('gettext', $sidmodselections));
?>
<style>
.suri-pad { padding: 1rem; }
.suri-sid-assign td { min-width: 9rem; }
.suri-sid-assign td:first-child, .suri-sid-assign td:nth-child(2) { min-width: 0; }
</style>

<div class="panel panel-default fs-table">
<?php fs_table_toolbar([
	'title' => gettext('SID management lists'),
	'search' => gettext('Search lists…'),
	'noun' => gettext('lists'),
	'noun_one' => gettext('list'),
]); ?>
	<div class="panel-body table-responsive">
		<table class="table table-hover" data-sortable>
			<thead>
				<tr>
					<th data-fs-search><?=gettext("Name")?></th>
					<th><?=gettext("In use")?></th>
					<th><?=gettext("Modified")?></th>
					<th class="fs-col-actions"><span class="visually-hidden"><?=gettext("Actions")?></span></th>
				</tr>
			</thead>
			<tbody>
<?php foreach ($sidmodlists as $i => $list):
	$active = suricata_is_sidmodslist_active($list['name']);
?>
				<tr>
					<td class="fs-mono"><?=htmlspecialchars($list['name'])?></td>
					<td><?=$active ? fs_badge('active', gettext('In use')) : fs_badge('idle', gettext('Not used'))?></td>
					<td class="small"><?=htmlspecialchars(date('Y-m-d H:i', $list['modtime'] + 0))?></td>
					<td class="fs-col-actions"><?=fs_row_actions([
						['edit', "suricata_sid_mgmt.php?sidlist_edit=0&sidlist_id={$i}", $list['name'], ['attrs' => ['usepost' => '']]],
						['custom', "suricata_sid_mgmt.php?sidlist_dnload=0&sidlist_id={$i}", $list['name'], [
							'icon' => 'fa-solid fa-download', 'label' => sprintf(gettext('Download %s'), $list['name']), 'post' => true]],
						['delete', "suricata_sid_mgmt.php?sidlist_delete=0&sidlist_id={$i}", $list['name'], [
							'thing' => gettext('SID management list'),
							'detail' => $active ? gettext('It is assigned to an interface and cannot be deleted until it is unassigned.') : null,
						]],
					])?></td>
				</tr>
<?php endforeach; ?>
<?php if (empty($sidmodlists)) {
	fs_empty_row(4, gettext('No SID management lists yet. Add a list or import one.'));
} ?>
			</tbody>
		</table>
	</div>
	<div class="panel-footer small fs-muted">
		<i class="fa-solid fa-circle-info" aria-hidden="true"></i>
		<?=gettext('Lists use the PulledPork / Oinkmaster format (enablesid, disablesid, modifysid, dropsid). Sample lists are included.')?>
	</div>
</div>

<form action="suricata_sid_mgmt.php" method="post" enctype="multipart/form-data" name="iform" id="iform">
	<input type="hidden" name="MAX_FILE_SIZE" value="100000000" />
	<input type="hidden" name="sidlist_id" id="sidlist_id" value=""/>

	<div class="panel panel-default">
		<div class="panel-heading"><h2 class="panel-title"><?=gettext("Automatic SID management")?></h2></div>
		<div class="panel-body suri-pad">
			<div class="form-check">
				<input type="checkbox" class="form-check-input" id="auto_manage_sids" name="auto_manage_sids" value="on"<?=($pconfig['auto_manage_sids'] == 'on') ? ' checked' : ''?> />
				<label class="form-check-label" for="auto_manage_sids"><?=gettext("Apply the assigned SID management lists automatically after every rule update")?></label>
			</div>
			<div class="form-text"><?=gettext("Rules are enabled, disabled or modified with the lists assigned to each interface below.")?></div>
		</div>
	</div>

	<div class="panel panel-default fs-table">
<?php fs_table_toolbar([
	'title' => gettext('Interface assignments'),
	'search' => false,
	'noun' => gettext('interfaces'),
	'noun_one' => gettext('interface'),
]); ?>
		<div class="panel-body table-responsive">
			<table class="table table-hover suri-sid-assign">
				<thead>
					<tr>
						<th title="<?=gettext('Apply the new configuration and rebuild the rules of this interface when saving')?>"><?=gettext("Rebuild")?></th>
						<th><?=gettext("Interface")?></th>
						<th><?=gettext("State order")?></th>
						<th><?=gettext("Enable list")?></th>
						<th><?=gettext("Disable list")?></th>
						<th><?=gettext("Modify list")?></th>
						<th><?=gettext("Drop list")?></th>
						<th><?=gettext("Reject list")?></th>
					</tr>
				</thead>
				<tbody>
<?php
$assigned = 0;
foreach ($a_nat as $k => $natent):
	// Skip any instance whose firewall interface is missing
	if (get_real_interface($natent['interface']) == "") {
		continue;
	}
	$assigned++;
	$ifname = convert_friendly_interface_to_friendly_descr($natent['interface']);
	$drop_ok = ($natent['blockoffenders'] == 'on' && ($natent['ips_mode'] == 'ips_mode_inline' || $natent['block_drops_only'] == 'on'));
	$reject_ok = ($natent['blockoffenders'] == 'on' && $natent['ips_mode'] == 'ips_mode_inline');
?>
					<tr>
						<td><input type="checkbox" class="form-check-input" name="torestart[]" id="torestart[]" value="<?=$k;?>" aria-label="<?=htmlspecialchars(sprintf(gettext('Rebuild rules for %s when saving'), $ifname))?>" /></td>
						<td><?=htmlspecialchars($ifname)?></td>
						<td><?=$sid_select('sid_state_order', $k, $natent['sid_state_order'], array("disable_enable" => "Disable, Enable", "enable_disable" => "Enable, Disable"), sprintf(gettext('State order for %s'), $ifname))?></td>
						<td><?=$sid_select('enable_sid_file', $k, $natent['enable_sid_file'], $list_choices, sprintf(gettext('Enable list for %s'), $ifname))?></td>
						<td><?=$sid_select('disable_sid_file', $k, $natent['disable_sid_file'], $list_choices, sprintf(gettext('Disable list for %s'), $ifname))?></td>
						<td><?=$sid_select('modify_sid_file', $k, $natent['modify_sid_file'], $list_choices, sprintf(gettext('Modify list for %s'), $ifname))?></td>
						<td>
<?php if ($drop_ok): ?>
							<?=$sid_select('drop_sid_file', $k, $natent['drop_sid_file'], $list_choices, sprintf(gettext('Drop list for %s'), $ifname))?>
<?php else: ?>
							<input type="hidden" name="drop_sid_file[<?=$k?>]" id="drop_sid_file[<?=$k?>]" value="<?=htmlspecialchars(isset($natent['drop_sid_file']) ? $natent['drop_sid_file'] : 'None')?>">
							<span class="fs-muted" title="<?=gettext('Only with blocking on drops or Inline IPS mode')?>"><?=gettext("N/A")?></span>
<?php endif; ?>
						</td>
						<td>
<?php if ($reject_ok): ?>
							<?=$sid_select('reject_sid_file', $k, $natent['reject_sid_file'], $list_choices, sprintf(gettext('Reject list for %s'), $ifname))?>
<?php else: ?>
							<input type="hidden" name="reject_sid_file[<?=$k?>]" id="reject_sid_file[<?=$k?>]" value="<?=htmlspecialchars(isset($natent['reject_sid_file']) ? $natent['reject_sid_file'] : 'None')?>">
							<span class="fs-muted" title="<?=gettext('Only in Inline IPS mode')?>"><?=gettext("N/A")?></span>
<?php endif; ?>
						</td>
					</tr>
<?php endforeach; ?>
<?php if ($assigned == 0) {
	fs_empty_row(8, gettext('No Suricata interfaces yet.'));
} ?>
				</tbody>
			</table>
		</div>
		<div class="panel-footer small fs-muted">
			<i class="fa-solid fa-circle-info" aria-hidden="true"></i>
			<?=gettext('Tick Rebuild to apply the changes and live-load the new rules on that interface when saving; otherwise only the assignments are saved. State order decides whether enable or disable runs last (the last action wins). "None" skips that list.')?>
		</div>
	</div>

	<div class="fs-actionbar fs-actionbar--plain">
		<button type="submit" id="save_auto_sid_conf" name="save_auto_sid_conf" class="btn btn-primary" value="<?=gettext("Save");?>">
			<i class="fa-solid fa-floppy-disk icon-embed-btn" aria-hidden="true"></i><?=gettext("Save");?>
		</button>
	</div>
</form>

<div class="modal fade fs-modal-form" id="sidlist_editor" tabindex="-1" aria-labelledby="sidlist-editor-title" aria-hidden="true"<?=$editor_open ? ' data-fs-open' : ''?>>
	<div class="modal-dialog modal-lg modal-dialog-centered modal-dialog-scrollable"><div class="modal-content">
	<form action="suricata_sid_mgmt.php" method="post">
		<input type="hidden" name="listid" id="listid" value="<?=htmlspecialchars($sidmodlist_id);?>" />
		<div class="modal-header">
			<h2 class="modal-title" id="sidlist-editor-title"><?=gettext("Edit SID management list")?></h2>
			<button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="<?=gettext('Close')?>"></button>
		</div>
		<div class="modal-body">
			<div class="mb-3">
				<label class="form-label" for="sidlist_name"><?=gettext('List name')?></label>
				<input type="text" class="form-control fs-mono" id="sidlist_name" name="sidlist_name" value="<?=htmlspecialchars($sidmodlist_name);?>" autocomplete="off" />
			</div>
			<div>
				<label class="form-label" for="sidlist_data"><?=gettext('Contents')?></label>
				<textarea class="form-control fs-mono" wrap="off" rows="18" name="sidlist_data" id="sidlist_data"><?=$sidmodlist_data;?></textarea>
			</div>
		</div>
		<div class="modal-footer">
			<button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal"><?=gettext('Cancel')?></button>
			<button type="submit" class="btn btn-primary" id="save" name="save" value="<?=gettext("Save");?>"><i class="fa-solid fa-floppy-disk icon-embed-btn" aria-hidden="true"></i><?=gettext("Save");?></button>
		</div>
	</form>
	</div></div>
</div>

<div class="modal fade fs-modal-form" id="uploader" tabindex="-1" aria-labelledby="uploader-title" aria-hidden="true">
	<div class="modal-dialog modal-dialog-centered"><div class="modal-content">
	<form action="suricata_sid_mgmt.php" method="post" enctype="multipart/form-data">
		<input type="hidden" name="MAX_FILE_SIZE" value="100000000" />
		<div class="modal-header">
			<h2 class="modal-title" id="uploader-title"><?=gettext("Import SID management list")?></h2>
			<button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="<?=gettext('Close')?>"></button>
		</div>
		<div class="modal-body">
			<label class="form-label" for="sidmods_fileup"><?=gettext('File')?></label>
			<input type="file" class="form-control" name="sidmods_fileup" id="sidmods_fileup" />
			<div class="form-text"><?=gettext('The file name becomes the list name and must not exist yet.')?></div>
		</div>
		<div class="modal-footer">
			<button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal"><?=gettext('Cancel')?></button>
			<button type="submit" class="btn btn-primary" name="upload" id="upload" value="<?=gettext("Upload");?>"><i class="fa-solid fa-upload icon-embed-btn" aria-hidden="true"></i><?=gettext("Upload");?></button>
		</div>
	</form>
	</div></div>
</div>

<?php
include("foot.inc"); ?>
