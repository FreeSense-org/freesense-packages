<?php
/*
 * suricata_passlist.php
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

$a_passlist = config_get_path('installedpackages/suricata/passlist/item', []);

// Calculate the next Pass List index ID
$id_gen = count(config_get_path('installedpackages/suricata/passlist/item', []));

function suricata_is_passlist_used($list) {

	/**********************************************
	 * This function tests the provided Pass List *
	 * to determine if it is assigned to an	      *
	 * interface.                                 *
	 *                                            *
	 * On Entry: $list -> Pass List name to test  *
	 *                                            *
	 * Returns: TRUE if Pass List is in use or    *
	 *		  FALSE if not in use         *
	 **********************************************/

	foreach(config_get_path('installedpackages/suricata/rule', []) as $v) {
		if (isset($v['passlistname']) && $v['passlistname'] == $list)
			return TRUE;
		if (isset($v['homelistname']) && $v['homelistname'] == $list)
			return TRUE;
		if (isset($v['externallistname']) && $v['externallistname'] == $list)
			return TRUE;
	}
	return FALSE;
}

if (isset($_POST['del_btn'])) {

	// User checked one or more checkboxes and clicked 'Delete' button,
	// so process the array of checked passlist entries.
	$need_save = false;
	if (is_array($_POST['del']) && count($_POST['del'])) {
		foreach ($_POST['del'] as $itemi) {
			/* make sure list is not being referenced by any interface */
			if (suricata_is_passlist_used($a_passlist[$itemi]['name'])) {
				$input_errors[] = gettext("Pass List '{$a_passlist[$itemi]['name']}' is currently assigned to a Suricata interface and cannot be deleted.  Unassign it from all Suricata interfaces first.");
			} else {
				unset($a_passlist[$itemi]);
				$need_save = true;
			}
		}
		if ($need_save && empty($input_errors)) {
			config_set_path('installedpackages/suricata/passlist/item', $a_passlist);
			write_config("Suricata pkg: deleted PASS LIST.");
			sync_suricata_package_config();
			header("Location: /suricata/suricata_passlist.php");
			return;
		}
	}
}
else {
	// User clicked the 'trash can' icon beside a single list entry
	unset($delbtn_list);
	$need_save = false;

	foreach ($_POST as $pn => $pd) {
		if (preg_match("/cdel_(\d+)/", $pn, $matches)) {
			$delbtn_list = $matches[1];
		}
	}
	if (is_numeric($delbtn_list) && $a_passlist[$delbtn_list]) {
		if (suricata_is_passlist_used($a_passlist[$delbtn_list]['name'])) {
			$input_errors[] = gettext("This Pass List '{$a_passlist[$delbtn_list]['name']}' is currently assigned to a Suricata interface and cannot be deleted.  Unassign it from all Suricata interfaces first.");
		}
		else {
			unset($a_passlist[$delbtn_list]);
			config_set_path('installedpackages/suricata/passlist/item', $a_passlist);
			write_config("Suricata pkg: deleted PASS LIST.");
			sync_suricata_package_config();
			header("Location: /suricata/suricata_passlist.php");
			return;
		}
	}
}

$pglinks = array("", "/suricata/suricata_overview.php", "@self");
$pgtitle = array(gettext("Services"), gettext("Suricata"), gettext("Pass lists"));
fs_page_action(gettext('Add pass list'), "suricata_passlist_edit.php?id={$id_gen}", 'fa-plus');
include_once("head.inc");

/* Display Alert message */
if ($input_errors) {
	print_input_errors($input_errors);
}
if ($savemsg) {
	print_info_box($savemsg);
}

suricata_display_primary_navigation('lists');
suricata_display_section_navigation('lists', 'passlist');
?>

<form action="/suricata/suricata_passlist.php" method="post">
<input type="hidden" name="list_id" id="list_id" value=""/>
<div class="panel panel-default fs-table">
<?php fs_table_toolbar([
	'title' => gettext('Pass lists'),
	'search' => gettext('Search pass lists…'),
	'noun' => gettext('pass lists'),
	'noun_one' => gettext('pass list'),
	'filters' => ['used' => [gettext('All lists'), 'yes' => gettext('Assigned'), 'no' => gettext('Not assigned')]],
	'bulk' => [
		['name' => 'del_btn', 'label' => gettext('Delete'), 'icon' => 'fa-trash-can', 'variant' => 'danger',
		 'confirm' => gettext('Delete the selected pass lists? Lists assigned to an interface are kept.')],
	],
]); ?>
	<div class="panel-body table-responsive">
		<table id="maintable" class="table table-hover table-rowdblclickedit" data-sortable>
			<thead>
				<tr>
					<th class="fs-col-select"><input type="checkbox" data-fs-select-all aria-label="<?=gettext('Select all')?>"></th>
					<th data-fs-search><?=gettext("Name")?></th>
					<th><?=gettext("Assigned")?></th>
					<th data-fs-search><?=gettext("Contents")?></th>
					<th data-fs-search><?=gettext("Description")?></th>
					<th class="fs-col-actions"><span class="visually-hidden"><?=gettext("Actions")?></span></th>
				</tr>
			</thead>
			<tbody>
<?php foreach ($a_passlist as $i => $list):
	$used = suricata_is_passlist_used($list['name']);
	$auto = [];
	foreach (['localnets' => gettext('Local networks'), 'wangateips' => gettext('Gateways'), 'wandnsips' => gettext('DNS servers'),
	    'vips' => gettext('Virtual IPs'), 'vpnips' => gettext('VPNs')] as $key => $text) {
		if (($list[$key] ?? 'yes') == 'yes') {
			$auto[] = $text;
		}
	}
	$addrs = array_filter((array)($list['address']['item'] ?? []));
?>
				<tr data-fs-filter-used="<?=$used ? 'yes' : 'no'?>">
					<td><input type="checkbox" id="frc<?=$i?>" name="del[]" value="<?=$i?>" data-fs-select aria-label="<?=htmlspecialchars(sprintf(gettext('Select %s'), $list['name']))?>"></td>
					<td><a href="suricata_passlist_edit.php?id=<?=$i?>"><?=htmlspecialchars($list['name'])?></a></td>
					<td><?=$used ? fs_badge('active', gettext('In use')) : fs_badge('idle', gettext('Not assigned'))?></td>
					<td>
						<div class="fs-chips">
<?php foreach ($auto as $text): ?>
							<span class="fs-chip"><?=htmlspecialchars($text)?></span>
<?php endforeach; ?>
<?php if ($addrs): ?>
							<span class="fs-chip fs-chip--mono" title="<?=htmlspecialchars(implode(', ', $addrs))?>"><?=htmlspecialchars(sprintf(ngettext('%d custom entry', '%d custom entries', count($addrs)), count($addrs)))?></span>
<?php endif; ?>
						</div>
					</td>
					<td><?=htmlspecialchars($list['descr'])?></td>
					<td class="fs-col-actions"><?=fs_row_actions([
						['edit', "suricata_passlist_edit.php?id={$i}", $list['name']],
						['delete', "suricata_passlist.php?cdel_{$i}=cdel_{$i}", $list['name'], [
							'thing' => gettext('pass list'),
							'detail' => $used ? gettext('It is assigned to a Suricata interface and cannot be deleted until it is unassigned.') : null,
						]],
					])?></td>
				</tr>
<?php endforeach; ?>
<?php if (empty($a_passlist)) {
	fs_empty_row(6, gettext('No pass lists yet. Interfaces use the default pass list.'), "suricata_passlist_edit.php?id={$id_gen}", gettext('Add pass list'));
} ?>
			</tbody>
		</table>
	</div>
	<div class="panel-footer small fs-muted">
		<i class="fa-solid fa-circle-info" aria-hidden="true"></i>
		<?=gettext('Hosts on a pass list are never blocked. The default list covers the WAN address and gateway, DNS servers, VPNs and local networks. Assign a custom list on the interface settings, then restart Suricata on that interface.')?>
	</div>
</div>
</form>

<?php include("foot.inc"); ?>
