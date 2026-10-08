<?php
/*
 * suricata_suppress.php
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

$a_suppress = config_get_path('installedpackages/suricata/suppress/item', []);
$id_gen = count($a_suppress);

function suricata_suppresslist_used($supplist) {

	/****************************************************************/
	/* This function tests if the passed Suppress List is currently */
	/* assigned to an interface.  It returns TRUE if the list is	*/
	/* in use.							*/
	/*								*/
	/* Returns:  TRUE if list is in use, else FALSE			*/
	/****************************************************************/

	foreach (config_get_path('installedpackages/suricata/rule', []) as $value) {
		if ($value['suppresslistname'] == $supplist)
			return true;
	}
	return false;
}

function suricata_find_suppresslist_interface($supplist) {

	/****************************************************************/
	/* This function finds the first (if more than one) interface   */
	/* configured to use the passed Suppress List and returns the   */
	/* index of the interface in the ['rule'] config array.		*/
	/*								*/
	/* Returns: index of interface in ['rule'] config array or	*/
	/*		  FALSE if no interface found.			*/
	/****************************************************************/

	foreach (config_get_path('installedpackages/suricata/rule', []) as $rule => $value) {
		if ($value['suppresslistname'] == $supplist)
			return $rule;
	}
	return false;
}

if (isset($_POST['del_btn'])) {
	$need_save = false;
	if (is_array($_POST['del']) && count($_POST['del'])) {
		foreach ($_POST['del'] as $itemi) {
			/* make sure list is not being referenced by any interface */
			if (suricata_suppresslist_used($a_suppress[$itemi]['name'])) {
				$input_errors[] = gettext("Suppression List '{$a_suppress[$itemi]['name']}' is currently assigned to a Suricata interface and cannot be deleted.  Unassign it from all Suricata interfaces first.");
			} else {
				unset($a_suppress[$itemi]);
				$need_save = true;
			}
		}
		if ($need_save) {
			config_set_path('installedpackages/suricata/suppress/item', $a_suppress);
			write_config("Suricata pkg: deleted SUPPRESSION LIST.");
			sync_suricata_package_config();
			header("Location: /suricata/suricata_suppress.php");
			return;
		}
	}
}

$pglinks = array("", "/suricata/suricata_overview.php", "@self");
$pgtitle = array(gettext("Services"), gettext("Suricata"), gettext("Suppress lists"));
fs_page_action(gettext('Add suppress list'), "suricata_suppress_edit.php?id={$id_gen}", 'fa-plus');
include_once("head.inc");

if ($input_errors) {
	print_input_errors($input_errors);
}
if ($savemsg) {
	print_info_box($savemsg);
}

suricata_display_primary_navigation('lists');
suricata_display_section_navigation('lists', 'suppress');
?>

<form action="/suricata/suricata_suppress.php" method="post">
<input type="hidden" name="list_id" id="list_id" value=""/>
<div class="panel panel-default fs-table">
<?php fs_table_toolbar([
	'title' => gettext('Suppress lists'),
	'search' => gettext('Search suppress lists…'),
	'noun' => gettext('suppress lists'),
	'noun_one' => gettext('suppress list'),
	'filters' => ['used' => [gettext('All lists'), 'yes' => gettext('Assigned'), 'no' => gettext('Not assigned')]],
	'bulk' => [
		['name' => 'del_btn', 'label' => gettext('Delete'), 'icon' => 'fa-trash-can', 'variant' => 'danger',
		 'confirm' => gettext('Delete the selected suppress lists? Lists assigned to an interface are kept.')],
	],
]); ?>
	<div class="panel-body table-responsive">
		<table id="maintable" class="table table-hover table-rowdblclickedit" data-sortable>
			<thead>
				<tr>
					<th class="fs-col-select"><input type="checkbox" data-fs-select-all aria-label="<?=gettext('Select all')?>"></th>
					<th data-fs-search><?=gettext("Name")?></th>
					<th><?=gettext("Assigned")?></th>
					<th><?=gettext("Entries")?></th>
					<th data-fs-search><?=gettext("Description")?></th>
					<th class="fs-col-actions"><span class="visually-hidden"><?=gettext("Actions")?></span></th>
				</tr>
			</thead>
			<tbody>
<?php $i = 0; foreach ($a_suppress as $list):
	$used = suricata_suppresslist_used($list['name']);
	$entries = 0;
	foreach (explode("\n", base64_decode($list['suppresspassthru'] ?? '')) as $line) {
		$line = trim($line);
		if ($line !== '' && $line[0] !== '#') {
			$entries++;
		}
	}
	$actions = [['edit', "suricata_suppress_edit.php?id={$i}", $list['name']]];
	if ($used) {
		$actions[] = ['custom', "/suricata/suricata_interfaces_edit.php?id=" . suricata_find_suppresslist_interface($list['name']), $list['name'], [
			'icon' => 'fa-solid fa-arrow-right', 'label' => sprintf(gettext('Open the first interface using %s'), $list['name'])]];
	}
	$actions[] = ['delete', "suricata_suppress.php?del_btn=1&del[]={$i}", $list['name'], [
		'thing' => gettext('suppress list'),
		'detail' => $used ? gettext('It is assigned to a Suricata interface and cannot be deleted until it is unassigned.') : null,
	]];
?>
				<tr data-fs-filter-used="<?=$used ? 'yes' : 'no'?>">
					<td><input type="checkbox" name="del[]" value="<?=$i?>" data-fs-select aria-label="<?=htmlspecialchars(sprintf(gettext('Select %s'), $list['name']))?>"></td>
					<td><a href="suricata_suppress_edit.php?id=<?=$i?>"><?=htmlspecialchars($list['name'])?></a></td>
					<td><?=$used ? fs_badge('active', gettext('In use')) : fs_badge('idle', gettext('Not assigned'))?></td>
					<td class="fs-mono"><?=(int)$entries?></td>
					<td><?=htmlspecialchars($list['descr'])?></td>
					<td class="fs-col-actions"><?=fs_row_actions($actions)?></td>
				</tr>
<?php $i++; endforeach; ?>
<?php if (empty($a_suppress)) {
	fs_empty_row(6, gettext('No suppress lists yet.'), "suricata_suppress_edit.php?id={$id_gen}", gettext('Add suppress list'));
} ?>
			</tbody>
		</table>
	</div>
	<div class="panel-footer small fs-muted">
		<i class="fa-solid fa-circle-info" aria-hidden="true"></i>
		<?=gettext('Suppress lists filter or suppress alerts. Assign a list on the interface settings and restart Suricata on that interface. A list in use cannot be deleted.')?>
	</div>
</div>
</form>

<?php include("foot.inc"); ?>
