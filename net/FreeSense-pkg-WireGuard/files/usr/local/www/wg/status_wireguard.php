<?php
/*
 * status_wireguard.php
 *
 * part of FreeSense (https://www.freesense.org)
 * Copyright (c) 2021 R. Christian McDonald (https://github.com/rcmcdonald91)
 * Copyright (c) 2021 Vajonam
 * Copyright (c) 2020 Ascrod
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

##|+PRIV
##|*IDENT=page-status-wireguard
##|*NAME=Status: WireGuard
##|*DESCR=Allow access to the 'Status: WireGuard' page.
##|*MATCH=status_wireguard.php*
##|-PRIV

// FreeSense includes
require_once('guiconfig.inc');
require_once('util.inc');

// WireGuard includes
require_once('wireguard/includes/wg.inc');
require_once('wireguard/includes/wg_guiconfig.inc');

global $wgg;

// Initialize $wgg state
wg_globals();

if ($_POST) {
	if (isset($_POST['apply'])) {
		$ret_code = 0;

		if (is_subsystem_dirty($wgg['subsystems']['wg'])) {
			if (wg_is_service_running()) {
				$tunnels_to_apply = wg_apply_list_get('tunnels');
				$sync_status = wg_tunnel_sync($tunnels_to_apply, true, true);
				$ret_code |= $sync_status['ret_code'];
			}

			if ($ret_code == 0) {
				clear_subsystem_dirty($wgg['subsystems']['wg']);
			}
		}
	}
}

$shortcut_section = "wireguard";

$pgtitle = array(gettext("Status"), gettext("WireGuard"));
$pglinks = array("", "@self");

$a_devices = wg_get_status();

$peers_hidden = wg_status_peers_hidden();

/* totals for the summary tiles */
$tot = array('up' => 0, 'peers' => 0, 'active' => 0, 'rx' => 0, 'tx' => 0);
foreach ($a_devices as $device) {
	$tot['up'] += ($device['status'] == 'up') ? 1 : 0;
	$tot['rx'] += (float)$device['transfer_rx'];
	$tot['tx'] += (float)$device['transfer_tx'];
	foreach ($device['peers'] as $peer) {
		$tot['peers']++;
		$hs = intval($peer['latest_handshake']);
		$tot['active'] += (($hs > 0) && (abs(time() - $hs) < 300)) ? 1 : 0;
	}
}

if (isAllowedPage('wg/vpn_wg_tunnels.php')) {
	fs_page_action(gettext('Tunnels'), '/wg/vpn_wg_tunnels.php', 'fa-gear', 'secondary');
}

include("head.inc");

wg_print_service_warning();

if (isset($_POST['apply'])) {
	print_apply_result_box($ret_code);
}

wg_print_config_apply_box();

wg_display_tabs('status');

wg_ui_styles();
?>

<style>
.wg-st-head { display: flex; flex-wrap: wrap; align-items: center; gap: .5rem 1rem; padding: .85rem 1rem; border-bottom: 1px solid var(--fs-border); }
.wg-st-title { margin: 0; font-size: var(--fs-fs-md); font-weight: 600; color: var(--fs-text-strong); }
.wg-st-title .fs-mono { color: var(--fs-text-muted); font-weight: 500; margin-right: .35rem; }
.wg-st-head .fs-actions { margin-left: auto; }
.wg-st-facts { display: flex; flex-wrap: wrap; gap: .25rem 1.25rem; margin: 0; padding: .75rem 1rem; border-bottom: 1px solid var(--fs-border); font-size: var(--fs-fs-sm); }
.wg-st-facts div { display: flex; gap: .4rem; align-items: baseline; min-width: 0; }
.wg-st-facts dt { color: var(--fs-text-muted); font-weight: 500; }
.wg-st-facts dd { margin: 0; color: var(--fs-text-strong); font-variant-numeric: tabular-nums; min-width: 0; }
.wg-st-facts dd .wg-line { display: inline; margin-right: .5rem; }
.wg-st-peers-toggle { margin: .5rem 1rem; }
.wg-st-peers[hidden] { display: none; }
</style>

<?php if (!empty($a_devices)): ?>
<div class="fs-tiles">
<?php
	fs_tile(gettext('Tunnels up'), sprintf('%d / %d', $tot['up'], count($a_devices)), ($tot['up'] == count($a_devices)) ? 'up' : 'down');
	fs_tile(gettext('Active peers'), sprintf('%d / %d', $tot['active'], $tot['peers']), null, gettext('Handshake in the last 5 minutes'));
	fs_tile(gettext('Received'), format_bytes($tot['rx']));
	fs_tile(gettext('Sent'), format_bytes($tot['tx']));
?>
</div>
<?php endif; ?>

<?php
foreach ($a_devices as $device_name => $device):
	$tun_qs = 'tun=' . rawurlencode($device_name);
	$is_up = ($device['status'] == 'up');
	$cfg = is_array($device['config']) ? $device['config'] : array();
	$did = 'wgst-' . preg_replace('/[^A-Za-z0-9_-]/', '', $device_name);
	$actions = array(['edit', "vpn_wg_tunnels_edit.php?{$tun_qs}", $device_name]);
?>
<div class="panel panel-default fs-table" id="<?=htmlspecialchars($did)?>">
	<div class="wg-st-head">
		<h2 class="wg-st-title"><span class="fs-mono"><?=htmlspecialchars($device_name)?></span><?=htmlspecialchars($cfg['descr'] ?? '')?></h2>
		<?=$is_up ? fs_badge('up') : fs_badge('down')?>
		<?=fs_row_actions($actions)?>
	</div>
	<dl class="wg-st-facts">
		<div><dt><?=gettext('Peers')?></dt><dd><?=count($device['peers'])?></dd></div>
		<div><dt><?=gettext('Listen port')?></dt><dd class="fs-mono"><?=htmlspecialchars($device['listen_port'])?></dd></div>
		<div><dt><?=gettext('MTU')?></dt><dd class="fs-mono"><?=htmlspecialchars($device['mtu'])?></dd></div>
		<div><dt><?=gettext('Received')?></dt><dd><?=htmlspecialchars(format_bytes($device['transfer_rx']))?></dd></div>
		<div><dt><?=gettext('Sent')?></dt><dd><?=htmlspecialchars(format_bytes($device['transfer_tx']))?></dd></div>
		<div><dt><?=gettext('Address')?></dt><dd><?=!empty($cfg) ? wg_ui_tunnel_addresses($cfg, 3) : '<span class="fs-muted">—</span>'?></dd></div>
		<div><dt><?=gettext('Public key')?></dt><dd><?=wg_ui_key($device['public_key'], $device_name, 16)?></dd></div>
	</dl>
<?php	if (count($device['peers']) > 0): ?>
	<button type="button" class="wg-toggle wg-st-peers-toggle" data-wg-toggle data-wg-peers-toggle aria-expanded="<?=$peers_hidden ? 'false' : 'true'?>" aria-controls="<?=htmlspecialchars($did)?>-peers">
		<i class="fa-solid fa-chevron-down" aria-hidden="true"></i><?=gettext('Peers')?> <span class="fs-count"><?=count($device['peers'])?></span>
	</button>
	<div class="wg-st-peers" id="<?=htmlspecialchars($did)?>-peers"<?=$peers_hidden ? ' hidden' : ''?>>
<?php if (count($device['peers']) > 5) {
	fs_table_toolbar([
		'search' => gettext('Search peers…'),
		'noun' => gettext('peers'),
		'noun_one' => gettext('peer'),
	]);
} ?>
		<div class="panel-body table-responsive">
			<table class="table table-hover" data-sortable>
				<thead>
					<tr>
						<th class="fs-col-status"><?=gettext('Handshake')?></th>
						<th data-fs-search><?=gettext('Peer')?></th>
						<th data-fs-search><?=gettext('Endpoint')?></th>
						<th data-fs-search class="d-none d-md-table-cell"><?=gettext('Allowed IPs')?></th>
						<th><?=gettext('Latest handshake')?></th>
						<th><?=gettext('Received')?></th>
						<th><?=gettext('Sent')?></th>
						<th class="fs-col-actions"><span class="visually-hidden"><?=gettext('Actions')?></span></th>
					</tr>
				</thead>
				<tbody>
<?php		foreach ($device['peers'] as $peer):
			$pcfg = is_array($peer['config']) ? $peer['config'] : array();
			$pname = !empty($pcfg['descr']) ? $pcfg['descr'] : wg_truncate_pretty($peer['public_key'], 12);
			$pidx = wg_peer_get_array_idx($peer['public_key'], $device_name);
			$allowed = array_values(array_filter(array_map('trim', explode(',', (string)$peer['allowed_ips'])), fn($x) => ($x !== '') && ($x !== '(none)')));
			$hs = intval($peer['latest_handshake']);
			$pactions = array();
			if (is_numericint($pidx)) {
				$pactions[] = ['edit', "vpn_wg_peers_edit.php?peer={$pidx}", $pname];
			}
?>
					<tr>
						<td data-value="<?=$hs?>"><?=wg_ui_handshake_badge($hs)?></td>
						<td>
							<?=htmlspecialchars($pname)?>
							<span class="wg-sub"><?=wg_ui_key($peer['public_key'], $pname, 10)?></span>
						</td>
						<td class="fs-mono"><?=(($peer['endpoint'] ?? '') !== '' && $peer['endpoint'] !== '(none)') ? htmlspecialchars($peer['endpoint']) : '<span class="fs-muted">' . gettext('Unknown') . '</span>'?></td>
						<td class="d-none d-md-table-cell"><?=wg_ui_address_list($allowed, 2)?></td>
						<td class="wg-num" data-value="<?=$hs?>"><?=htmlspecialchars(wg_human_time_diff("@{$hs}"))?></td>
						<td class="fs-mono wg-num" data-value="<?=htmlspecialchars(trim($peer['transfer_rx']))?>"><?=htmlspecialchars(format_bytes($peer['transfer_rx']))?></td>
						<td class="fs-mono wg-num" data-value="<?=htmlspecialchars(trim($peer['transfer_tx']))?>"><?=htmlspecialchars(format_bytes($peer['transfer_tx']))?></td>
						<td class="fs-col-actions"><?=fs_row_actions($pactions)?></td>
					</tr>
<?php		endforeach; ?>
				</tbody>
			</table>
		</div>
	</div>
<?php	else: ?>
	<div class="panel-body table-responsive">
		<table class="table"><tbody>
<?php		fs_empty_row(1, gettext('No peers are configured on this tunnel.'), "vpn_wg_peers_edit.php?{$tun_qs}", gettext('Add peer')); ?>
		</tbody></table>
	</div>
<?php	endif; ?>
</div>
<?php endforeach; ?>

<?php if (empty($a_devices)): ?>
<div class="panel panel-default fs-table">
	<div class="panel-body table-responsive">
		<table class="table"><tbody>
<?php
	if (empty(config_get_path('installedpackages/wireguard/tunnels/item'))) {
		fs_empty_row(1, gettext('No WireGuard tunnels yet.'), '/wg/vpn_wg_tunnels_edit.php', gettext('Add tunnel'));
	} else {
		fs_empty_row(1, gettext('No WireGuard status information is available. Is the service running?'));
	}
?>
		</tbody></table>
	</div>
</div>
<?php endif; ?>

<div class="panel panel-default fs-table">
<?php fs_table_toolbar([
	'title' => gettext('Package versions'),
	'search' => false,
	'noun' => gettext('packages'),
	'noun_one' => gettext('package'),
]); ?>
	<div class="panel-body table-responsive">
		<table class="table table-hover">
			<thead>
				<tr>
					<th><?=gettext('Name')?></th>
					<th><?=gettext('Version')?></th>
					<th><?=gettext('Comment')?></th>
				</tr>
			</thead>
			<tbody>
<?php foreach (wg_pkg_info() as ['name' => $name, 'version' => $version, 'comment' => $comment]): ?>
				<tr>
					<td class="fs-mono"><?=htmlspecialchars($name)?></td>
					<td class="fs-mono"><?=htmlspecialchars($version)?></td>
					<td><?=htmlspecialchars($comment)?></td>
				</tr>
<?php endforeach; ?>
			</tbody>
		</table>
	</div>
</div>

<script type="text/javascript">
//<![CDATA[
events.push(function() {
	wgRegCopyHandler();
	wgRegNestedRows(document);
});
//]]>
</script>

<?php
include('wireguard/includes/wg_foot.inc');
include('foot.inc');
?>
