<?php
/*
 * suricata_interfaces.php
 *
 * part of FreeSense (https://www.freesense.org)
 * Copyright (c) 2006-2026 Rubicon Communications, LLC (Netgate)
 * Copyright (c) 2025-2026 The FreeSense Project
 * Copyright (c) 2003-2004 Manuel Kasper
 * Copyright (c) 2005 Bill Marquette
 * Copyright (c) 2009 Robert Zelaya Sr. Developer
 * Copyright (c) 2025 Bill Meeks
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
$suricatalogdir = SURICATALOGDIR;
$rcdir = RCFILEPREFIX;
$suri_starting = array();

if (is_numeric($_POST['id']))
	$id = $_POST['id'];
else
	$id = 0;

$a_nat = config_get_path('installedpackages/suricata/rule', []);
$id_gen = count($a_nat);

// Get list of configured firewall interfaces
$ifaces = get_configured_interface_list();

if (isset($_POST['del_x'])) {
	/* delete selected interfaces */
	if (is_array($_POST['rule']) && count($_POST['rule'])) {
		foreach ($_POST['rule'] as $rulei) {
			$if_real = get_real_interface($a_nat[$rulei]['interface']);
			$if_friendly = convert_friendly_interface_to_friendly_descr($a_nat[$rulei]['interface']);
			$suricata_uuid = $a_nat[$rulei]['uuid'];

			// Check that we still have the real interface defined in FreeSense.
			// The real interface will return as an empty string if it has
			// been removed in FreeSense.
			if ($if_real == "") {
				rmdir_recursive("{$suricatalogdir}suricata_{$if_real}{$suricata_uuid}");
				rmdir_recursive("{$suricatadir}suricata_{$suricata_uuid}_*");
				logger(LOG_NOTICE, localize_text("Deleted the Suricata instance on a previously removed FreeSense interface per user request..."), LOG_PREFIX_PKG_SURICATA);
			}
			else {
				// Delete the interface sub-directories and then the instance itself
				logger(LOG_NOTICE, localize_text("Stopping Suricata on %s(%s) due to Suricata instance deletion...", $if_friendly, $if_real), LOG_PREFIX_PKG_SURICATA);
				suricata_stop($a_nat[$rulei], $if_real);
				rmdir_recursive("{$suricatalogdir}suricata_{$if_real}{$suricata_uuid}");
				rmdir_recursive("{$suricatadir}suricata_{$suricata_uuid}_{$if_real}");
				logger(LOG_NOTICE, localize_text("Deleted Suricata instance on %s(%s) per user request...", $if_friendly, $if_real), LOG_PREFIX_PKG_SURICATA);
			}

			// Finally, delete the interface's config entry entirely
			unset($a_nat[$rulei]);
		}

		/* If all the Suricata interfaces are removed, then unset the config array. */
		if (empty($a_nat))
			unset($a_nat);

		config_set_path('installedpackages/suricata/rule', $a_nat);
		write_config("Suricata pkg: deleted one or more Suricata interfaces.");
		sleep(2);

		sync_suricata_package_config();

		header( 'Expires: Sat, 26 Jul 1997 05:00:00 GMT' );
		header( 'Last-Modified: ' . gmdate( 'D, d M Y H:i:s' ) . ' GMT' );
		header( 'Cache-Control: no-store, no-cache, must-revalidate' );
		header( 'Cache-Control: post-check=0, pre-check=0', false );
		header( 'Pragma: no-cache' );
		header("Location: /suricata/suricata_interfaces.php");
		exit;
	}
} else {
	unset($delbtn_list);
	foreach ($_POST as $pn => $pd) {
		if (preg_match("/ldel_(\d+)/", $pn, $matches)) {
			$delbtn_list = $matches[1];
		}
	}

	if (is_numeric($delbtn_list) && $a_nat[$delbtn_list]) {
		$if_real = get_real_interface($a_nat[$delbtn_list]['interface']);
		$if_friendly = convert_friendly_interface_to_friendly_descr($a_nat[$delbtn_list]['interface']);
		$suricata_uuid = $a_nat[$delbtn_list]['uuid'];

		// Check that we still have the real interface defined in FreeSense.
		// The real interface will return as an empty string if it has
		// been removed in FreeSense.
		if ($if_real == "") {
			rmdir_recursive("{$suricatalogdir}suricata_{$if_real}{$suricata_uuid}");
			rmdir_recursive("{$suricatadir}suricata_{$suricata_uuid}_*");
			logger(LOG_NOTICE, localize_text("Deleted the Suricata instance on a previously removed FreeSense interface per user request..."), LOG_PREFIX_PKG_SURICATA);
		}
		else {
			// Delete the interface sub-directories and then the instance itself
			logger(LOG_NOTICE, localize_text("Stopping Suricata on %s(%s) due to Suricata instance deletion...", $if_friendly, $if_real), LOG_PREFIX_PKG_SURICATA);
			suricata_stop($a_nat[$delbtn_list], $if_real);
			rmdir_recursive("{$suricatalogdir}suricata_{$if_real}{$suricata_uuid}");
			rmdir_recursive("{$suricatadir}suricata_{$suricata_uuid}_{$if_real}");
			logger(LOG_NOTICE, localize_text("Deleted Suricata instance on %s(%s) per user request...", $if_friendly, $if_real), LOG_PREFIX_PKG_SURICATA);
		}

		// Finally, delete the interface's config entry entirely
		unset($a_nat[$delbtn_list]);

		// Save updated configuration
		config_set_path('installedpackages/suricata/rule', $a_nat);
		write_config("Suricata pkg: deleted one or more Suricata interfaces.");
		sleep(2);
		sync_suricata_package_config();
		header( 'Expires: Sat, 26 Jul 1997 05:00:00 GMT' );
		header( 'Last-Modified: ' . gmdate( 'D, d M Y H:i:s' ) . ' GMT' );
		header( 'Cache-Control: no-store, no-cache, must-revalidate' );
		header( 'Cache-Control: post-check=0, pre-check=0', false );
		header( 'Pragma: no-cache' );
		header("Location: /suricata/suricata_interfaces.php");
		exit;
	}
}

/* start/stop Suricata */
if ($_POST['toggle']) {
	// Ensure the interface index is legit, else bail and redisplay this page
	if (!is_numeric($_POST['id']) || intval($_POST['id']) >= $id_gen) {
		header( 'Expires: Sat, 26 Jul 1997 05:00:00 GMT' );
		header( 'Last-Modified: ' . gmdate( 'D, d M Y H:i:s' ) . ' GMT' );
		header( 'Cache-Control: no-store, no-cache, must-revalidate' );
		header( 'Cache-Control: post-check=0, pre-check=0', false );
		header( 'Pragma: no-cache' );
		header("Location: /suricata/suricata_interfaces.php");
		exit;
	}
	$suricatacfg = config_get_path("installedpackages/suricata/rule/{$_POST['id']}");
	$if_real = get_real_interface($suricatacfg['interface']);
	$if_friendly = convert_friendly_interface_to_friendly_descr($suricatacfg['interface']);
	$id = $_POST['id'];

	// Suricata can take several seconds to startup, so to
	// make the GUI more responsive, startup commands are
	// executed as a background process.  The commands
	// are written to a PHP file in the 'tmp_path' which
	// is executed by a PHP command line session launched
	// as a background task.

	// Create steps for the background task to start Suricata.
	// These commands will be handed off to a CLI PHP session
	// for background execution as a self-deleting PHP file.
	$start_lck_file = "{$g['varrun_path']}/suricata_{$if_real}{$suricatacfg['uuid']}_starting.lck";
	$suricata_start_cmd = <<<EOD
	<?php
	require_once("/usr/local/pkg/suricata/suricata.inc");
	require_once("service-utils.inc");
	global \$g, \$rebuild_rules;
	\$suricatacfg = config_get_path("installedpackages/suricata/rule/{$id}", []);
	\$rebuild_rules = true;
	touch("{$start_lck_file}");
	sync_suricata_package_config();
	\$rebuild_rules = false;
	suricata_start(\$suricatacfg, "{$if_real}");
	unlink_if_exists("{$start_lck_file}");
	unlink(__FILE__);
	?>
EOD;

	switch ($_POST['toggle']) {
		case 'start':
			file_put_contents("{$g['tmp_path']}/suricata_{$if_real}{$suricatacfg['uuid']}_startcmd.php", $suricata_start_cmd);
			if (suricata_is_running($suricatacfg['uuid'], $if_real)) {
				logger(LOG_NOTICE, localize_text("Restarting Suricata on %s(%s) per user request...", $if_friendly, $if_real), LOG_PREFIX_PKG_SURICATA);
				suricata_stop($suricatacfg, $if_real);
				mwexec_bg("/usr/local/bin/php -f {$g['tmp_path']}/suricata_{$if_real}{$suricatacfg['uuid']}_startcmd.php");
			}
			else {
				// Forcefully remove the PID file if it exists but a Suricata instance with that PID is not running.
				// This allows the user the start Suricata in the event of a failed previous start due to a config error.
				if (!suricata_is_running($suricatacfg['uuid'], $if_real)) {
					unlink_if_exists("{$g['varrun_path']}/suricata_{$if_real}{$suricatacfg['uuid']}.pid");
				}
				logger(LOG_NOTICE, localize_text("Starting Suricata on %s(%s) per user request...", $if_friendly, $if_real), LOG_PREFIX_PKG_SURICATA);
				mwexec_bg("/usr/local/bin/php -f {$g['tmp_path']}/suricata_{$if_real}{$suricatacfg['uuid']}_startcmd.php");
			}
			$suri_starting[$id] = TRUE;
			break;
		case 'stop':
			if (suricata_is_running($suricatacfg['uuid'], $if_real)) {
				logger(LOG_NOTICE, localize_text("Stopping Suricata on %s(%s) per user request...", $if_friendly, $if_real), LOG_PREFIX_PKG_SURICATA);
				suricata_stop($suricatacfg, $if_real);
			}
			unset($suri_starting[$id]);
			unlink_if_exists($start_lck_file);
			break;
		default:
			unset($suri_starting[$id]);
			unlink_if_exists('{$start_lck_file}');
	}
	unset($suricata_start_cmd);
}

/* Ajax call to periodically check Suricata status */
/* on each configured interface.                   */
if ($_POST['status'] == 'check') {
	$list = array();

	// Iterate configured Suricata interfaces and get status of each
	// into an associative array.  Return the array to the Ajax
	// caller as a JSON object.
	foreach ($a_nat as $intf) {
		// Skip status update for any missing real interface
		if (($if_real = get_real_interface($intf['interface'])) == "") {
			continue;
		}
		$intf_key = "suricata_" . get_real_interface($intf['interface']) . $intf['uuid'];
		if ($intf['enable'] == "on") {
			if (suricata_is_running($intf['uuid'], get_real_interface($intf['interface']))) {
				$list[$intf_key] = "RUNNING";
			}
			elseif (file_exists("{$g['varrun_path']}/{$intf_key}_starting.lck") || file_exists("{$g['varrun_path']}/suricata_pkg_starting.lck")) {
				$list[$intf_key] = "STARTING";
				$suri_starting[$id] = TRUE;
			}
			else {
				$list[$intf_key] = "STOPPED";
			}
		}
		else {
			$list[$intf_key] = "DISABLED";
		}
	}

	// Return a JSON encoded array as the page output
	echo json_encode($list);
	exit;
}

$pglinks = array("", "/suricata/suricata_overview.php", "@self");
$pgtitle = array(gettext("Services"), gettext("Suricata"), gettext("Interfaces"));

if ($id_gen < count($ifaces)) {
	fs_page_action(gettext('Add interface'), "suricata_interfaces_edit.php?id={$id_gen}", 'fa-plus');
}

include_once("head.inc");

if ($input_errors) {
	print_input_errors($input_errors);
}
if ($savemsg) {
	print_info_box($savemsg);
}

suricata_display_primary_navigation('interfaces');

$pkg_starting = file_exists("{$g['varrun_path']}/suricata_pkg_starting.lck");
$can_clone = ($id_gen < count($ifaces));
$no_rules_footnote = false;
?>
<style>
.suri-if-name { font-weight: 600; }
.suri-if-sub { display: flex; flex-wrap: wrap; align-items: center; gap: .35rem; margin-top: .15rem; }
.suri-mode { display: flex; flex-direction: column; align-items: flex-start; gap: .2rem; }
.suri-ifs td { vertical-align: middle; }
.suri-ifs .fs-chips { max-width: 22rem; }
</style>

<form action="suricata_interfaces.php" method="post" enctype="multipart/form-data" name="iform" id="iform">
<input type="hidden" name="id" id="id" value="">
<input type="hidden" name="toggle" id="toggle" value="">

<div class="panel panel-default fs-table suri-ifs">
<?php fs_table_toolbar([
	'title' => gettext('Suricata interfaces'),
	'search' => gettext('Search interfaces…'),
	'noun' => gettext('interfaces'),
	'noun_one' => gettext('interface'),
	'filters' => [
		'state' => [gettext('All states'), 'running' => gettext('Running'), 'stopped' => gettext('Stopped'), 'disabled' => gettext('Disabled')],
		'mode' => [gettext('All modes'), 'ids' => gettext('IDS'), 'legacy' => gettext('IPS legacy'), 'inline' => gettext('IPS inline')],
	],
	'bulk' => [
		['name' => 'del_x', 'label' => gettext('Delete'), 'icon' => 'fa-trash-can', 'variant' => 'danger',
		 'confirm' => gettext('Delete the selected Suricata interfaces? Their logs and settings are removed.')],
	],
]); ?>
	<div class="panel-body table-responsive">
		<table id="maintable" class="table table-hover table-rowdblclickedit" data-sortable>
			<thead>
				<tr>
					<th class="fs-col-select"><input type="checkbox" data-fs-select-all aria-label="<?=gettext('Select all')?>"></th>
					<th class="fs-col-status"><?=gettext("Status")?></th>
					<th data-fs-search><?=gettext("Interface")?></th>
					<th data-fs-search><?=gettext("Mode")?></th>
					<th data-fs-search><?=gettext("Rule sets")?></th>
					<th data-fs-search><?=gettext("Description")?></th>
					<th class="fs-col-actions"><span class="visually-hidden"><?=gettext("Actions")?></span></th>
				</tr>
			</thead>
			<tbody>
<?php
	$nnats = $i = 0;
	foreach ($a_nat as $natent):
		/* A null real interface indicates it has been removed from the system. */
		$if_real = get_real_interface($natent['interface']);
		$missing = ($if_real == "");
		if ($missing) {
			$natent['enable'] = "off";
		}
		$if_name = $missing ? gettext("Missing (removed?)") : convert_friendly_interface_to_friendly_descr($natent['interface']);
		$suricata_uuid = $natent['uuid'];
		$label = ($natent['descr'] ?? '') !== '' ? $natent['descr'] : $if_name;

		/* Flag enabled interfaces that have no rules at all */
		$no_rules = ($natent['enable'] != "off") && empty($natent['customrules']) && empty($natent['rulesets']) && empty($natent['ips_policy']);
		if ($no_rules) {
			$no_rules_footnote = true;
		}

		$enabled = (config_get_path("installedpackages/suricata/rule/{$nnats}/enable") == "on") && !$missing;
		if (!$enabled) {
			$state = 'disabled';
		} elseif (suricata_is_running($suricata_uuid, $if_real)) {
			$state = 'running';
		} elseif (!empty($suri_starting[$nnats]) || $pkg_starting) {
			$state = 'starting';
		} else {
			$state = 'stopped';
		}

		$blocking = (config_get_path("installedpackages/suricata/rule/{$nnats}/blockoffenders") == 'on');
		$ips_mode = config_get_path("installedpackages/suricata/rule/{$nnats}/ips_mode");
		if ($blocking && $ips_mode == 'ips_mode_inline') {
			$mode_key = 'inline';
			$mode_label = gettext('IPS inline');
		} elseif ($blocking && $ips_mode == 'ips_mode_legacy') {
			$mode_key = 'legacy';
			$mode_label = gettext('IPS legacy');
		} else {
			$mode_key = 'ids';
			$mode_label = gettext('IDS');
		}
		$mpm = config_get_path("installedpackages/suricata/rule/{$nnats}/mpm_algo");
		$sources = suricata_ruleset_summary($natent);

		$actions = [];
		$actions[] = ['custom', "suricata_interfaces.php?toggle=start&id={$nnats}", $label, [
			'icon' => 'fa-solid fa-play', 'label' => sprintf(gettext('Start Suricata on %s'), $label), 'post' => true,
			'attrs' => ['class' => 'fs-action' . (($state === 'stopped') ? '' : ' d-none'), 'data-suri-act' => 'start']]];
		$actions[] = ['custom', "suricata_interfaces.php?toggle=start&id={$nnats}", $label, [
			'icon' => 'fa-solid fa-arrow-rotate-right', 'label' => sprintf(gettext('Restart Suricata on %s'), $label), 'post' => true,
			'attrs' => ['class' => 'fs-action' . (($state === 'running') ? '' : ' d-none'), 'data-suri-act' => 'restart']]];
		$actions[] = ['custom', "suricata_interfaces.php?toggle=stop&id={$nnats}", $label, [
			'icon' => 'fa-solid fa-stop', 'label' => sprintf(gettext('Stop Suricata on %s'), $label), 'post' => true,
			'confirm' => sprintf(gettext('Stop Suricata on “%s”?'), $label),
			'detail' => gettext('Traffic on this interface is no longer inspected until Suricata is started again.'),
			'confirm_action' => gettext('Stop'),
			'attrs' => ['class' => 'fs-action' . (($state === 'running' || $state === 'starting') ? '' : ' d-none'), 'data-suri-act' => 'stop']]];
		$actions[] = ['edit', "suricata_interfaces_edit.php?id={$nnats}", $label];
		if ($can_clone) {
			$actions[] = ['copy', "suricata_interfaces_edit.php?id={$nnats}&action=dup", $label];
		}
		$actions[] = ['delete', "suricata_interfaces.php?ldel_{$nnats}=ldel_{$nnats}", $label, [
			'thing' => gettext('Suricata interface'),
			'detail' => gettext('Suricata is stopped on this interface and its logs and settings are removed.'),
		]];
?>
				<tr id="fr<?=$nnats?>" data-fs-filter-state="<?=($state === 'starting') ? 'running' : $state?>" data-fs-filter-mode="<?=$mode_key?>"
				    data-suri-key="<?=htmlspecialchars("suricata_{$if_real}{$suricata_uuid}")?>"<?=($state === 'disabled') ? ' class="fs-row-disabled"' : ''?>>
					<td><input type="checkbox" id="frc<?=$nnats?>" name="rule[]" value="<?=$i?>" data-fs-select aria-label="<?=htmlspecialchars(sprintf(gettext('Select %s'), $label))?>"></td>
					<td class="suri-state">
<?php
		switch ($state) {
			case 'running':
				echo fs_badge('up', gettext('Running'));
				break;
			case 'starting':
				echo fs_badge('pending', gettext('Starting'));
				break;
			case 'stopped':
				echo fs_badge('down', gettext('Stopped'));
				break;
			default:
				echo fs_badge('disabled');
		}
?>
					</td>
					<td>
						<a class="suri-if-name" href="suricata_interfaces_edit.php?id=<?=$nnats?>"><?=htmlspecialchars($if_name)?></a>
						<div class="suri-if-sub">
							<?php if (!$missing): ?><span class="fs-mono fs-muted small"><?=htmlspecialchars($if_real)?></span><?php else: ?><?=fs_badge('warn', gettext('Interface missing'))?><?php endif; ?>
						</div>
					</td>
					<td>
						<div class="suri-mode">
							<span class="fs-chip fs-chip--strong"><?=htmlspecialchars($mode_label)?></span>
							<span class="fs-muted small" title="<?=gettext('Multi-pattern matcher')?>"><?=gettext('MPM')?> <span class="fs-mono"><?=htmlspecialchars($mpm != '' ? strtolower($mpm) : gettext('unknown'))?></span></span>
						</div>
					</td>
					<td>
<?php if ($no_rules): ?>
						<span class="fs-chip is-warn" title="<?=gettext('This interface has no rules defined')?>"><?=gettext('No rules')?><i class="fa-solid fa-triangle-exclamation" aria-hidden="true"></i></span>
<?php elseif (empty($sources)): ?>
						<span class="fs-muted">&ndash;</span>
<?php else: ?>
						<div class="fs-chips">
<?php foreach ($sources as $src => $count): ?>
							<span class="fs-chip"<?=$count ? ' title="' . htmlspecialchars(sprintf(gettext('%d rule categories'), $count)) . '"' : ''?>><?=htmlspecialchars($src)?><?=$count ? ' <span class="fs-muted">' . (int)$count . '</span>' : ''?></span>
<?php endforeach; ?>
						</div>
<?php endif; ?>
					</td>
					<td><?=htmlspecialchars($natent['descr'])?></td>
					<td class="fs-col-actions"><?=fs_row_actions($actions)?></td>
				</tr>
<?php
		$i++;
		$nnats++;
	endforeach;
	unset($suri_starting);

	if (empty($a_nat)) {
		fs_empty_row(7, gettext('No Suricata interfaces yet.'), $can_clone ? "suricata_interfaces_edit.php?id={$id_gen}" : null, $can_clone ? gettext('Add interface') : null);
	}
?>
			</tbody>
		</table>
	</div>
	<div class="panel-footer small fs-muted">
		<i class="fa-solid fa-circle-info" aria-hidden="true"></i>
		<?=gettext('Configure the global settings before adding an interface. New settings take effect when Suricata restarts on the interface.')?>
<?php if ($no_rules_footnote): ?>
		<br><i class="fa-solid fa-triangle-exclamation" aria-hidden="true"></i>
		<?=gettext('An interface marked “No rules” has no rule categories, IPS policy or custom rules selected.')?>
<?php endif; ?>
	</div>
</div>
</form>

<script type="text/javascript">
//<![CDATA[
(function () {
	var labels = {
		RUNNING: ['pass', 'fa-circle-check', <?=json_encode(gettext('Running'))?>],
		STARTING: ['warn', 'fa-hourglass-half', <?=json_encode(gettext('Starting'))?>],
		STOPPED: ['block', 'fa-circle-xmark', <?=json_encode(gettext('Stopped'))?>]
	};

	function badge(state) {
		var def = labels[state];
		var span = document.createElement('span');
		span.className = 'fs-badge fs-badge--' + def[0];
		var icon = document.createElement('i');
		icon.className = 'fa-solid ' + def[1];
		icon.setAttribute('aria-hidden', 'true');
		span.appendChild(icon);
		span.appendChild(document.createTextNode(def[2]));
		return span;
	}

	function showStatus(responseData) {
		var data;
		try {
			data = (typeof responseData === 'string') ? JSON.parse(responseData) : responseData;
		} catch (e) {
			return;
		}
		document.querySelectorAll('tr[data-suri-key]').forEach(function (row) {
			var state = data[row.getAttribute('data-suri-key')];
			if (!state || state === 'DISABLED' || !labels[state] || row.getAttribute('data-suri-state') === state) {
				return;
			}
			row.setAttribute('data-suri-state', state);
			row.setAttribute('data-fs-filter-state', (state === 'STOPPED') ? 'stopped' : 'running');
			var cell = row.querySelector('.suri-state');
			cell.replaceChildren(badge(state));
			var show = {
				start: state === 'STOPPED',
				restart: state === 'RUNNING',
				stop: state !== 'STOPPED'
			};
			Object.keys(show).forEach(function (act) {
				var a = row.querySelector('[data-suri-act="' + act + '"]');
				if (a) {
					a.classList.toggle('d-none', !show[act]);
				}
			});
		});
	}

	function check_status() {
		// Ask this page for the status of each configured interface (JSON), then poll again.
		$.ajax("/suricata/suricata_interfaces.php", {
			type: 'post',
			data: { status: 'check' },
			success: showStatus,
			complete: function () {
				setTimeout(check_status, 2000);
			}
		});
	}

	setTimeout(check_status, 2000);
})();
//]]>
</script>

<?php
include("foot.inc");
?>
