<?php
/*
 * suricata_ip_reputation.php
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
$iprep_path = SURICATA_IPREP_PATH;

if (isset($_POST['id']) && is_numericint($_POST['id']))
	$id = $_POST['id'];
elseif (isset($_GET['id']) && is_numericint($_GET['id']))
	$id = htmlspecialchars($_GET['id']);

if (!is_numericint($id)) {
	header("Location: /suricata/suricata_interfaces.php");
	exit;
}

$a_nat = config_get_path("installedpackages/suricata/rule/{$id}", []);

// If doing a postback, used typed values, else load from stored config
if (!empty($_POST)) {
	$pconfig = $_POST;
}
else {
	$pconfig = $a_nat;
}

if ($_POST['mode'] == 'iprep_catlist_add' && isset($_POST['iplist'])) {
	$pconfig = $_POST;

	// Test the supplied IP List file to see if it exists
	if (file_exists($iprep_path . basename($_POST['iplist']))) {
		if (!$input_errors) {
			$a_nat['iprep_catlist'] = basename($_POST['iplist']);
			config_set_path("installedpackages/suricata/rule/{$id}", $a_nat);
			write_config("Suricata pkg: added new IP Rep Categories file for IP REPUTATION preprocessor.");
			mark_subsystem_dirty('suricata_iprep');
		}
	}
	else
		$input_errors[] = gettext("The file '{$_POST['iplist']}' could not be found.");

	$pconfig['iprep_catlist'] = $a_nat['iprep_catlist'];
	$pconfig['iplist_files'] = $a_nat['iplist_files'];
}

if ($_POST['mode'] == 'iplist_add' && isset($_POST['iplist'])) {
	$pconfig = $_POST;

	// Test the supplied IP List file to see if it exists
	if (file_exists($iprep_path . basename($_POST['iplist']))) {
		// See if the file is already assigned to the interface
		foreach (array_get_path($a_nat, 'iplist_files/item', []) as $f) {
			if ($f == basename($_POST['iplist'])) {
				$input_errors[] = gettext("The file {$f} is already assigned as a whitelist file.");
				break;
			}
		}
		if (!$input_errors) {
			if (!is_array($a_nat['iplist_files'])){
				$a_nat['iplist_files'] = array( "item" => array() );
			}

			$a_nat['iplist_files']['item'][] = basename($_POST['iplist']);
			config_set_path("installedpackages/suricata/rule/{$id}", $a_nat);
			write_config("Suricata pkg: added new whitelist file for IP REPUTATION preprocessor.");
			mark_subsystem_dirty('suricata_iprep');
		}
	}
	else
		$input_errors[] = gettext("The file '{$_POST['iplist']}' could not be found.");

	$pconfig['iprep_catlist'] = $a_nat['iprep_catlist'];
	$pconfig['iplist_files'] = $a_nat['iplist_files'];
}

if ($_POST['iprep_catlist_del']) {
	$pconfig = $_POST;
	unset($a_nat['iprep_catlist']);
	config_set_path("installedpackages/suricata/rule/{$id}", $a_nat);
	write_config("Suricata pkg: deleted blacklist file for IP REPUTATION preprocessor.");
	mark_subsystem_dirty('suricata_iprep');
	$pconfig['iprep_catlist'] = $a_nat['iprep_catlist'];
	$pconfig['iplist_files'] = $a_nat['iplist_files'];
}

if ($_POST['iplist_del'] && is_numericint($_POST['list_id'])) {
	$pconfig = $_POST;
	unset($a_nat['iplist_files']['item'][$_POST['list_id']]);
	config_set_path("installedpackages/suricata/rule/{$id}", $a_nat);
	write_config("Suricata pkg: deleted whitelist file for IP REPUTATION preprocessor.");
	mark_subsystem_dirty('suricata_iprep');
	$pconfig['iplist_files'] = $a_nat['iplist_files'];
	$pconfig['iprep_catlist'] = $a_nat['iprep_catlist'];
}

if ($_POST['save']) {

	$pconfig['iprep_catlist'] = $a_nat['iprep_catlist'];
	$pconfig['iplist_files'] = $a_nat['iplist_files'];

	// Validate HOST TABLE values
	if ($_POST['host_memcap'] < 1000000 || !is_numericint($_POST['host_memcap']))
		$input_errors[] = gettext("The value for 'Host Memcap' must be a numeric integer greater than 1MB (1,048,576!");
	if ($_POST['host_hash_size'] < 1024 || !is_numericint($_POST['host_hash_size']))
		$input_errors[] = gettext("The value for 'Host Hash Size' must be a numeric integer greater than 1024!");
	if ($_POST['host_prealloc'] < 10 || !is_numericint($_POST['host_prealloc']))
		$input_errors[] = gettext("The value for 'Host Preallocations' must be a numeric integer greater than 10!");

	// Validate CATEGORIES FILE
	if ($_POST['enable_iprep'] == 'on') {
		if (empty($a_nat['iprep_catlist']))
			$input_errors[] = gettext("Assignment of a 'Categories File' is required when IP Reputation is enabled!");
	}

	// If no errors write to conf
	if (!$input_errors) {
		$a_nat['enable_iprep'] = $_POST['enable_iprep'] ? 'on' : 'off';
		$a_nat['host_memcap'] = str_replace(",", "", $_POST['host_memcap']);
		$a_nat['host_hash_size'] = str_replace(",", "", $_POST['host_hash_size']);
		$a_nat['host_prealloc'] = str_replace(",", "", $_POST['host_prealloc']);

		config_set_path("installedpackages/suricata/rule/{$id}", $a_nat);
		write_config("Suricata pkg: modified IP REPUTATION preprocessor settings for {$a_nat['interface']}.");

		// Update the suricata conf file for this interface
		$rebuild_rules = false;
		suricata_generate_yaml($a_nat);

		// Soft-restart Suricata to live-load new variables
		suricata_reload_config($a_nat);

		// Sync to configured CARP slaves if any are enabled
		suricata_sync_on_changes();

		$savemsg = gettext("IP reputation system changes have been saved");
	}
}

$if_friendly = convert_friendly_interface_to_friendly_descr($a_nat['interface']);
$pglinks = array("", "/suricata/suricata_overview.php", "/suricata/suricata_interfaces.php", "/suricata/suricata_interfaces_edit.php?id={$id}", "@self");
$pgtitle = array(gettext("Services"), gettext("Suricata"), gettext("Interfaces"), htmlspecialchars($a_nat['descr'] ?: $if_friendly), gettext("IP reputation"));
include_once("head.inc");
suricata_display_primary_navigation('interfaces');

/* Interface context (same block on every per-interface Suricata page): settings switch + summary */
$sf_rule = config_get_path("installedpackages/suricata/rule/{$id}", []);
$sf_real = get_real_interface($sf_rule['interface'] ?? '');
$sf_name = convert_friendly_interface_to_friendly_descr($sf_rule['interface'] ?? '');
echo '<nav class="fs-viewswitch" aria-label="' . fs_h(gettext('Interface settings')) . '">';
foreach (array(
	array('suricata_interfaces_edit.php', gettext('Settings')),
	array('suricata_rulesets.php', gettext('Categories')),
	array('suricata_rules.php', gettext('Rules')),
	array('suricata_flow_stream.php', gettext('Flow & stream')),
	array('suricata_app_parsers.php', gettext('App parsers')),
	array('suricata_define_vars.php', gettext('Variables')),
	array('suricata_ip_reputation.php', gettext('IP reputation')),
) as $sf_v) {
	echo '<a href="/suricata/' . $sf_v[0] . '?id=' . (int)$id . '"' . (($sf_v[0] === basename(__FILE__)) ? ' aria-current="page"' : '') . '>' . fs_h($sf_v[1]) . '</a>';
}
echo '</nav>';
if (($sf_rule['blockoffenders'] ?? '') != 'on') {
	$sf_mode = gettext('Detection only');
} elseif (($sf_rule['ips_mode'] ?? '') == 'ips_mode_inline') {
	$sf_mode = gettext('Inline IPS');
} else {
	$sf_mode = gettext('Legacy blocking');
}
$sf_running = !empty($sf_rule['uuid']) && suricata_is_running($sf_rule['uuid'], $sf_real);
fs_summary_card(array(
	'icon' => 'fa-shield-halved',
	'title' => $sf_rule['descr'] ?? '',
	'placeholder' => $sf_name,
	'subtitle' => sprintf(gettext('Suricata on %s'), $sf_name),
	'badges' => array(
		fs_badge((($sf_rule['enable'] ?? '') == 'on') ? 'enabled' : 'disabled'),
		$sf_running ? fs_badge('up', gettext('Running')) : fs_badge('down', gettext('Stopped')),
	),
	'meta' => $sf_real,
	'label' => gettext('Interface summary'),
	'facts' => array(
		array(gettext('Mode'), $sf_mode),
		array(gettext('Rule categories'), (string)count(array_filter(explode('||', $sf_rule['rulesets'] ?? '')))),
		array(gettext('Home net'), (($sf_rule['homelistname'] ?? 'default') == 'default') ? gettext('Default') : $sf_rule['homelistname']),
		array(gettext('Suppress list'), (empty($sf_rule['suppresslistname']) || $sf_rule['suppresslistname'] == 'default') ? '' : $sf_rule['suppresslistname'], 'empty' => gettext('None')),
	),
	'actions' => array(array(gettext('Alerts'), '/suricata/suricata_alerts.php?instance=' . (int)$id, 'fa-bell')),
));

/* Display Alert message */
if ($input_errors)
	print_input_errors($input_errors);

if ($savemsg)
	print_info_box($savemsg, 'success');

$sf_filedate = function ($f) use ($iprep_path) {
	if (!file_exists("{$iprep_path}{$f}")) {
		return null;
	}
	return date('M-d Y g:i a', filemtime("{$iprep_path}{$f}"));
};
$sec_state = COLLAPSIBLE | (!empty($input_errors) ? SEC_OPEN : SEC_CLOSED);
?>

<style>
.sf-chooser { margin: 0 var(--fs-sp-4) var(--fs-sp-3); padding: var(--fs-sp-3); border: 1px dashed var(--fs-border); border-radius: var(--fs-r-sm); overflow-x: auto; }
.sf-chooser .fbFile { cursor: pointer; }
.sf-chooser .fbFile:hover { color: var(--fs-coral-text); }
.sf-chooser .fbClose { cursor: pointer; }
.sf-notes { display: flex; flex-wrap: wrap; gap: .4rem 1.5rem; margin: -.5rem 0 var(--fs-sp-5); color: var(--fs-text-muted); font-size: var(--fs-fs-sm); }
</style>

<form action="/suricata/suricata_ip_reputation.php" method="post" id="iform" class="form-horizontal">
	<input type="hidden" name="id" id="id" value="<?=(int)$id?>">
	<input type="hidden" name="mode" id="mode" value="">
	<input type="hidden" name="iplist" id="iplist" value="">
	<input type="hidden" name="list_id" id="list_id" value="">
<?php
$section = new Form_Section('IP reputation');
$section->addInput(new Form_Checkbox(
	'enable_iprep',
	'Enable',
	'Use IP reputation lists on this interface. Default is off; a categories file is required.',
	$pconfig['enable_iprep'] == 'on' ? true:false,
	'on'
));
print($section);
?>

<div class="panel panel-default fs-table">
<?php
	fs_table_toolbar(array(
		'title' => gettext('Categories file'),
		'search' => false,
		'noun' => gettext('files'),
		'noun_one' => gettext('file'),
		'actions' => empty($pconfig['iprep_catlist'])
		    ? '<button type="button" class="btn btn-sm btn-primary" name="iprep_catlist_add" id="iprep_catlist_add" title="' . fs_h(gettext('Assign a Categories file')) . '"><i class="fa-solid fa-plus icon-embed-btn" aria-hidden="true"></i>' . fs_h(gettext('Assign file')) . '</button>'
		    : '<button type="button" class="btn btn-sm btn-outline-secondary" name="iprep_catlist_add" id="iprep_catlist_add" title="' . fs_h(gettext('Assign a Categories file')) . '"><i class="fa-solid fa-arrow-right-arrow-left icon-embed-btn" aria-hidden="true"></i>' . fs_h(gettext('Replace')) . '</button>',
	));
?>
	<div id="iprep_catlistChooser" class="sf-chooser" hidden></div>
	<div class="panel-body table-responsive">
		<table class="table table-hover">
			<thead>
				<tr>
					<th><?=gettext("File name")?></th>
					<th><?=gettext("Modified")?></th>
					<th class="fs-col-actions"><span class="visually-hidden"><?=gettext('Actions')?></span></th>
				</tr>
			</thead>
			<tbody>
<?php if (!empty($pconfig['iprep_catlist'])):
	$filedate = $sf_filedate($pconfig['iprep_catlist']);
?>
				<tr>
					<td class="fs-mono"><?=htmlspecialchars($pconfig['iprep_catlist'])?></td>
					<td><?=($filedate === null) ? fs_badge('warn', gettext('File missing')) : fs_h($filedate)?></td>
					<td class="fs-col-actions"><div class="fs-actions">
						<button type="submit" class="fs-action fs-action--delete" name="iprep_catlist_del[]" value="0" id="iprep_catlist_delX" data-sf-list="0"
							title="<?=gettext('Remove this Categories file')?>" aria-label="<?=gettext('Remove this Categories file')?>"
							data-fs-confirm="<?=fs_h(sprintf(gettext('Remove the categories file “%s”?'), $pconfig['iprep_catlist']))?>" data-fs-confirm-detail="<?=gettext('The file stays on disk; it is only unassigned from this interface.')?>" data-fs-confirm-action="<?=gettext('Remove')?>"><i class="fa-solid fa-xmark" aria-hidden="true"></i></button>
					</div></td>
				</tr>
<?php else: ?>
<?php	fs_empty_row(3, gettext('No categories file assigned.')); ?>
<?php endif; ?>
			</tbody>
		</table>
	</div>
</div>

<div class="panel panel-default fs-table">
<?php
	$lists = array_get_path($pconfig, 'iplist_files/item', []);
	fs_table_toolbar(array(
		'title' => gettext('IP reputation lists'),
		'search' => false,
		'noun' => gettext('lists'),
		'noun_one' => gettext('list'),
		'actions' => '<button type="button" class="btn btn-sm btn-primary" name="iplist_add" id="iplist_add" title="' . fs_h(gettext('Assign an IP reputation list file')) . '"><i class="fa-solid fa-plus icon-embed-btn" aria-hidden="true"></i>' . fs_h(gettext('Assign list')) . '</button>',
	));
?>
	<div id="iplistChooser" class="sf-chooser" hidden></div>
	<div class="panel-body table-responsive">
		<table class="table table-hover">
			<thead>
				<tr>
					<th><?=gettext("File name")?></th>
					<th><?=gettext("Modified")?></th>
					<th class="fs-col-actions"><span class="visually-hidden"><?=gettext('Actions')?></span></th>
				</tr>
			</thead>
			<tbody>
<?php foreach ($lists as $k => $f):
	$filedate = $sf_filedate($f);
?>
				<tr>
					<td class="fs-mono"><?=htmlspecialchars($f)?></td>
					<td><?=($filedate === null) ? fs_badge('warn', gettext('File missing')) : fs_h($filedate)?></td>
					<td class="fs-col-actions"><div class="fs-actions">
						<button type="submit" class="fs-action fs-action--delete" name="iplist_del[]" value="0" data-sf-list="<?=(int)$k?>"
							title="<?=fs_h(sprintf(gettext('Remove %s'), $f))?>" aria-label="<?=fs_h(sprintf(gettext('Remove %s'), $f))?>"
							data-fs-confirm="<?=fs_h(sprintf(gettext('Remove the IP reputation list “%s”?'), $f))?>" data-fs-confirm-detail="<?=gettext('The file stays on disk; it is only unassigned from this interface.')?>" data-fs-confirm-action="<?=gettext('Remove')?>"><i class="fa-solid fa-xmark" aria-hidden="true"></i></button>
					</div></td>
				</tr>
<?php endforeach; ?>
<?php
	if (empty($lists)) {
		fs_empty_row(3, gettext('No IP reputation lists assigned.'));
	}
?>
			</tbody>
		</table>
	</div>
</div>

<?php
$section = new Form_Section('Host table', 'sf-hosttable', $sec_state);
$section->addInput(new Form_Input(
	'host_memcap',
	'Host memory cap',
	'number',
	$pconfig['host_memcap'],
	['min' => '1048576']
))->setHelp('Bytes. Default is 33,554,432 (32 MB); at least 1,048,576 (1 MB).');
$section->addInput(new Form_Input(
	'host_hash_size',
	'Host hash size',
	'number',
	$pconfig['host_hash_size'],
	['min' => '1024']
))->setHelp('Default is 4096; at least 1024.');
$section->addInput(new Form_Input(
	'host_prealloc',
	'Preallocated hosts',
	'number',
	$pconfig['host_prealloc'],
	['min' => '10']
))->setHelp('Host table entries to preallocate. Default is 1000; at least 10. Larger lists can benefit from a higher value.');
print($section);
?>

<div class="sf-notes">
	<span><?=gettext('Upload categories and list files on the IP Lists page. Assigning or removing a file is saved at once; Save applies the settings and reloads Suricata.')?></span>
</div>

<div class="fs-actionbar">
	<button type="submit" class="btn btn-primary" name="save" id="save" value="Save"><i class="fa-solid fa-floppy-disk icon-embed-btn" aria-hidden="true"></i><?=gettext('Save')?></button>
</div>
</form>

<script type="text/javascript">
//<![CDATA[
events.push(function() {
	var form = document.getElementById('iform');

	// Remove a file: the confirmed click sets which list, then the form posts
	document.addEventListener('click', function(e) {
		var btn = e.target.closest('button[data-sf-list]');
		if (!btn || e.defaultPrevented) {
			return;
		}
		$('#list_id').val(btn.getAttribute('data-sf-list'));
	});

	// Show the file chooser (loaded over AJAX) and wire its entries
	function choose(container, mode) {
		var box = $('#' + container);
		box.text(<?=json_encode(gettext('Loading…'))?>).prop('hidden', false);
		$.ajax("/suricata/suricata_iprep_list_browser.php?container=" + container + "&target=iplist&val=" + new Date().getTime(), {
			type: 'get',
			complete: function(req) {
				box.html(req.responseText);
				box.find('.fbClose').on('click', function() {
					box.prop('hidden', true);
				});
				box.find('.fbFile').on('click', function() {
					$('#iplist').val(this.id);
					$('#mode').val(mode);
					form.submit();
				});
			}
		});
	}

	$('#iprep_catlist_add').on('click', function() {
		choose('iprep_catlistChooser', 'iprep_catlist_add');
	});
	$('#iplist_add').on('click', function() {
		choose('iplistChooser', 'iplist_add');
	});
});
//]]>
</script>

<?php include("foot.inc");
?>
