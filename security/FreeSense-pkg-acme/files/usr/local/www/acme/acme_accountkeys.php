<?php
/*
 * acme_accountkeys.php
 *
 * part of FreeSense (https://www.freesense.org/)
 * Copyright (c) 2016 PiBa-NL
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

namespace pfsense_pkg\acme;

$shortcut_section = "acme";
require_once("guiconfig.inc");
require_once("certs.inc");
require_once("acme/acme.inc");
require_once("acme/acme_gui.inc");
require_once("acme/acme_utils.inc");
require_once("acme/pkg_acme_tabs.inc");

$changedesc = "Services: ACME: Account Keys";

if ($_POST) {
	$pconfig = $_POST;

	if ($_POST['del_x']) {
		/* delete selected rules */
		$deleted = false;
		if (is_array($_POST['rule']) && count($_POST['rule'])) {
			$selected = array();
			foreach($_POST['rule'] as $selection) {
				$selected[] = get_accountkey_id($selection);
			}
			foreach ($selected as $itemnr) {
				config_del_path("installedpackages/acme/accountkeys/item/{$itemnr}");
				$deleted = true;
			}
			if ($deleted) {
				write_config("ACME, deleting accountkey(s)");
			}
			header("Location: acme_accountkeys.php");
			exit;
		}
	} else {

		// from '\src\usr\local\www\vpn_ipsec.php'
		/* yuck - IE won't send value attributes for image buttons, while Mozilla does - so we use .x/.y to find move button clicks instead... */
		// TODO: this. is. nasty.
		unset($delbtn, $delbtnp2, $movebtn, $movebtnp2, $togglebtn, $togglebtnp2);
		/* the target name comes from the button value: PHP turns "." and spaces in
		 * POST field names into "_", so the field name itself is not usable */
		foreach ($_POST as $pn => $pd) {
			if ((strpos($pn, 'move_') === 0) && is_string($pd) && (strpos($pd, 'move_') === 0)) {
				$movebtn = substr($pd, 5);
			}
		}
		//

		/* move selected p1 entries before this */
		if (isset($movebtn) && is_array($_POST['rule']) && count($_POST['rule'])) {
			$moveto = get_accountkey_id($movebtn);
			$selected = array();
			foreach($_POST['rule'] as $selection) {
				$selected[] = get_accountkey_id($selection);
			}
			$a_accountkeys = config_get_path('installedpackages/acme/accountkeys/item', []);
			array_moveitemsbefore($a_accountkeys, $moveto, $selected);
			config_set_path('installedpackages/acme/accountkeys/item', $a_accountkeys);

			write_config($changedesc);
		}
	}
} else {
	$result = null;//haproxy_check_config($retval);
	if ($result) {
		$savemsg = gettext($result);
	}
}

if ($_POST['act'] == "del") {
	$id = $_POST['id'];
	$id = get_accountkey_id($id);
	if (config_get_path("installedpackages/acme/accountkeys/item/{$id}") !== null) {
		if (!$input_errors) {
			config_del_path("installedpackages/acme/accountkeys/item/{$id}");
			$changedesc .= " Accountkey delete";
			write_config($changedesc);
		}
		header("Location: acme_accountkeys.php");
		exit;
	}
}

$a_accountkeys = config_get_path('installedpackages/acme/accountkeys/item', []);
$custom_ids = array_column(config_get_path('installedpackages/acme/customacme/servers', []) ?: [], 'intid');
$cert_count = [];
foreach (config_get_path('installedpackages/acme/certificates/item', []) as $certificate) {
	if (is_array($certificate) && !empty($certificate['acmeaccount'])) {
		$cert_count[$certificate['acmeaccount']] = ($cert_count[$certificate['acmeaccount']] ?? 0) + 1;
	}
}

$pgtitle = array(gettext("Services"), gettext("ACME"), gettext("Account keys"));
$pglinks = array("", "acme_certificates.php", "@self");
fs_page_action(gettext('Add account key'), 'acme_accountkeys_edit.php', 'fa-plus');
include("head.inc");
if ($input_errors) {
	print_input_errors($input_errors);
}
if ($savemsg) {
	print_info_box($savemsg);
}

display_top_tabs_active($acme_tab_array['acme'], "accountkeys");
?>
<style>
.fs-acme-sub { display: block; font-size: var(--fs-fs-xs); color: var(--fs-text-muted); }
</style>
<form action="acme_accountkeys.php" method="post">
<div class="panel panel-default fs-table">
<?php fs_table_toolbar([
	'title' => gettext('Account keys'),
	'search' => gettext('Search account keys…'),
	'noun' => gettext('account keys'),
	'noun_one' => gettext('account key'),
	'filters' => [
		'kind' => [gettext('All servers'), 'production' => gettext('Production'), 'staging' => gettext('Staging'), 'custom' => gettext('Custom')],
	],
	'bulk' => [
		['name' => 'del_x', 'label' => gettext('Delete'), 'icon' => 'fa-trash-can', 'variant' => 'danger',
		 'value' => gettext('Delete selected backends'), 'confirm' => gettext('Delete the selected account keys?')],
	],
]); ?>
	<div class="panel-body table-responsive">
		<table class="table table-hover table-rowdblclickedit" data-sortable>
			<thead>
				<tr>
					<th class="fs-col-select" data-sortable="false"><input type="checkbox" data-fs-select-all aria-label="<?=gettext('Select all')?>"></th>
					<th data-fs-search><?=gettext('Name')?></th>
					<th data-fs-search><?=gettext('ACME server')?></th>
					<th data-fs-search><?=gettext('E-mail')?></th>
					<th data-sortable-type="numeric"><?=gettext('Certificates')?></th>
					<th class="fs-col-actions" data-sortable="false"><span class="visually-hidden"><?=gettext('Actions')?></span></th>
				</tr>
			</thead>
			<tbody>
<?php
$shown = 0;
foreach ($a_accountkeys as $accountkey):
	if (empty($accountkey) || !is_array($accountkey)) {
		continue;
	}
	$shown++;
	$name = (string)$accountkey['name'];
	$accountname = htmlspecialchars($name);
	$server = $accountkey['acmeserver'] ?? '';
	$known = array_key_exists($server, $a_acmeserver);
	$sname = $known ? $a_acmeserver[$server]['name'] : '';
	$sshort = trim(preg_replace('/\s*\(.*$/', '', $sname));
	$kind = in_array($server, $custom_ids, true) ? 'custom' : ((stripos($sname, 'staging') !== false || stripos($sname, 'testing') !== false) ? 'staging' : 'production');
	$certs = $cert_count[$name] ?? 0;
?>
				<tr data-fs-filter-kind="<?=$kind?>">
					<td><input type="checkbox" id="frc<?=$accountname?>" name="rule[]" value="<?=$accountname?>" data-fs-select aria-label="<?=htmlspecialchars(sprintf(gettext('Select %s'), $name))?>"></td>
					<td>
						<a href="acme_accountkeys_edit.php?id=<?=htmlspecialchars(urlencode($name))?>"><strong><?=$accountname?></strong></a>
<?php if (!empty($accountkey['descr'])): ?>
						<span class="fs-acme-sub"><?=htmlspecialchars($accountkey['descr'])?></span>
<?php endif; ?>
					</td>
					<td>
<?php if ($known): ?>
						<span title="<?=htmlspecialchars($sname)?>"><?=htmlspecialchars($sshort ?: $sname)?></span>
<?php	if ($kind == 'staging'): ?>
						<span class="fs-chip fs-chip--muted"><?=gettext('Staging')?></span>
<?php	elseif ($kind == 'custom'): ?>
						<span class="fs-chip fs-chip--muted"><?=gettext('Custom')?></span>
<?php	endif; ?>
						<span class="fs-acme-sub fs-mono"><?=htmlspecialchars($server)?></span>
<?php else: ?>
						<?=fs_badge('warn', gettext('Unknown server'), gettext('The ACME server stored on this key no longer exists.'))?>
						<span class="fs-acme-sub fs-mono"><?=htmlspecialchars($server)?></span>
<?php endif; ?>
					</td>
					<td><?=!empty($accountkey['email']) ? htmlspecialchars($accountkey['email']) : '<span class="fs-muted">—</span>'?></td>
					<td data-value="<?=$certs?>"><?=$certs?></td>
					<td class="fs-col-actions">
						<button class="d-none" type="submit" id="move_<?=htmlspecialchars($name)?>" name="move_<?=htmlspecialchars($name)?>" value="move_<?=htmlspecialchars($name)?>" tabindex="-1" aria-hidden="true"></button>
						<?=fs_row_actions([
							['edit', 'acme_accountkeys_edit.php?id=' . urlencode($name), $name],
							['copy', 'acme_accountkeys_edit.php?dup=' . urlencode($name), $name],
							['custom', '#', $name, ['icon' => 'fa-anchor', 'label' => sprintf(gettext('Move selected account keys before %s'), $name),
							    'attrs' => ['data-acme-move' => 'move_' . $name]]],
							['delete', 'acme_accountkeys.php?act=del&id=' . rawurlencode($name), $name, ['thing' => gettext('account key'),
							    'detail' => $certs ? sprintf(ngettext('%d certificate uses this key and stops renewing.', '%d certificates use this key and stop renewing.', $certs), $certs) : null]],
						])?>
					</td>
				</tr>
<?php endforeach; ?>
<?php if ($shown == 0) {
	fs_empty_row(6, gettext('No account keys yet. Certificates need a registered account key.'), 'acme_accountkeys_edit.php', gettext('Add account key'));
} ?>
			</tbody>
		</table>
	</div>
</div>
</form>

<script type="text/javascript">
//<![CDATA[
events.push(function() {
	/* move the checked rows before this one (hidden move_<name> submit button) */
	$(document).on('click', '[data-acme-move]', function (e) {
		e.preventDefault();
		var btn = document.getElementById(this.getAttribute('data-acme-move'));
		if (btn) {
			btn.click();
		}
	});
});
//]]>
</script>
<?php include("foot.inc");
