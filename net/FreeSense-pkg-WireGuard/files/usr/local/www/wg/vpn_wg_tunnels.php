<?php
/*
 * vpn_wg_tunnels.php
 *
 * part of FreeSense (https://www.freesense.org)
 * Copyright (c) 2021-2026 Rubicon Communications, LLC (Netgate)
 * Copyright (c) 2025-2026 The FreeSense Project
 * Copyright (c) 2021 R. Christian McDonald (https://github.com/rcmcdonald91)
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
##|*IDENT=page-vpn-wireguard
##|*NAME=VPN: WireGuard
##|*DESCR=Allow access to the 'VPN: WireGuard' page.
##|*MATCH=vpn_wg_tunnels.php*
##|-PRIV

// FreeSense includes
require_once('functions.inc');
require_once('guiconfig.inc');
require_once('freesense-utils.inc');
require_once('service-utils.inc');

// WireGuard includes
require_once('wireguard/includes/wg.inc');
require_once('wireguard/includes/wg_guiconfig.inc');

global $wgg;

// Initialize $wgg state
wg_globals();

$pconfig = [];

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

	if (isset($_POST['tun'])) {
		$tun_name = $_POST['tun'];

		/* Check if the submitted tunnel exists
		 * https://redmine.freesense.org/issues/12731
		 */
		$tun_found = false;
		foreach (config_get_path('installedpackages/wireguard/tunnels/item', []) as $tunnel) {
			if ($tunnel['name'] == $tun_name) {
				$tun_found = true;
				break;
			}
		}

		if ($tun_found) {
			switch ($_POST['act']) {
				case 'download':
					wg_download_tunnel($tun_name, '/wg/vpn_wg_tunnels.php');
					exit();
					break;
				case 'toggle':
					$res = wg_toggle_tunnel($tun_name);
					break;
				case 'delete':
					$res = wg_delete_tunnel($tun_name);
					break;
				default:
					// Shouldn't be here, so bail out.
					header('Location: /wg/vpn_wg_tunnels.php');
					break;
			}
			$input_errors = $res['input_errors'];
		} else {
			/* User submitted a tunnel that does not exist, so bail.
			 * https://redmine.freesense.org/issues/12731
			 */
			$input_errors = array(gettext("The requested tunnel does not exist."));
		}

		if (empty($input_errors)) {
			if (wg_is_service_running() && $res['changes']) {
				mark_subsystem_dirty($wgg['subsystems']['wg']);

				// Add tunnel to the list to apply
				wg_apply_list_add('tunnels', $res['tuns_to_sync']);
			}
		}
	}
}

$shortcut_section = 'wireguard';

$pgtitle = array(gettext('VPN'), gettext('WireGuard'), gettext('Tunnels'));
$pglinks = array('', '@self', '@self');

$tunnels = config_get_path('installedpackages/wireguard/tunnels/item', []);
$all_peers = config_get_path('installedpackages/wireguard/peers/item', []);

$counts = array('enabled' => 0, 'assigned' => 0);
foreach ($tunnels as $tunnel) {
	$counts['enabled'] += ($tunnel['enabled'] == 'yes') ? 1 : 0;
	$counts['assigned'] += is_wg_tunnel_assigned($tunnel['name']) ? 1 : 0;
}

// Large lists start with their peers folded away
$peers_open = (count($all_peers) <= 10);

fs_page_action(gettext('Add tunnel'), 'vpn_wg_tunnels_edit.php', 'fa-plus');

include('head.inc');

wg_print_service_warning();

if (isset($_POST['apply'])) {
	print_apply_result_box($ret_code);
}

wg_print_config_apply_box();

if (!empty($input_errors)) {
	print_input_errors($input_errors);
}

wg_display_tabs('tunnels');

wg_ui_styles();
?>

<?php if (!empty($tunnels)): ?>
<div class="fs-tiles">
<?php
	$disabled = count($tunnels) - $counts['enabled'];
	fs_tile(gettext('Tunnels'), count($tunnels), null, $counts['assigned'] ? sprintf(gettext('%d assigned to an interface'), $counts['assigned']) : null);
	fs_tile(gettext('Enabled'), $counts['enabled'], null, $disabled ? sprintf(gettext('%d disabled'), $disabled) : null);
	fs_tile(gettext('Peers'), count($all_peers));
	fs_tile(gettext('Service'), wg_is_service_running() ? gettext('Running') : gettext('Stopped'), wg_is_service_running() ? 'up' : 'down');
?>
</div>
<?php endif; ?>

<form name="mainform" method="post">
<div class="panel panel-default fs-table" id="wg-tunnels">
<?php fs_table_toolbar([
	'title' => gettext('WireGuard tunnels'),
	'search' => gettext('Search tunnels…'),
	'noun' => gettext('tunnels'),
	'noun_one' => gettext('tunnel'),
	'filters' => [
		'state' => [gettext('All states'), 'enabled' => gettext('Enabled'), 'disabled' => gettext('Disabled')],
	],
]); ?>
	<div class="panel-body table-responsive">
		<table class="table table-hover">
			<thead>
				<tr>
					<th class="fs-col-status d-none d-sm-table-cell"><?=gettext('Status')?></th>
					<th data-fs-search><?=gettext('Tunnel')?></th>
					<th data-fs-search class="d-none d-sm-table-cell"><?=gettext('Addresses')?></th>
					<th data-fs-search class="d-none d-md-table-cell"><?=gettext('Listen port')?></th>
					<th data-fs-search class="d-none d-lg-table-cell"><?=gettext('Public key')?></th>
					<th class="fs-col-actions"><span class="visually-hidden"><?=gettext('Actions')?></span></th>
				</tr>
			</thead>
			<tbody>
<?php
foreach ($tunnels as $i => $tunnel):
	$name = $tunnel['name'];
	$enabled = ($tunnel['enabled'] == 'yes');
	$peers = wg_tunnel_get_peers_config($name);
	$badge = $enabled ? fs_badge('enabled') : fs_badge('disabled');
	$qs = 'tun=' . rawurlencode($name);
	$search = array();
	foreach ($peers as [$peer_idx, $peer, $peer_new]) {
		$search[] = $peer['descr'] . ' ' . $peer['endpoint'] . ' ' . implode(' ', wg_ui_address_strings($peer['allowedips']['row'] ?? array()));
	}
?>
				<tr id="wgt<?=$i?>" data-fs-filter-state="<?=$enabled ? 'enabled' : 'disabled'?>"<?=$enabled ? '' : ' class="fs-row-disabled"'?>>
					<td class="d-none d-sm-table-cell"><?=$badge?></td>
					<td>
						<a class="wg-tun-link fs-mono" href="vpn_wg_tunnels_edit.php?<?=htmlspecialchars($qs)?>"><?=htmlspecialchars($name)?></a>
<?php	if (!empty($tunnel['descr'])): ?>
						<span class="wg-sub"><?=htmlspecialchars($tunnel['descr'])?></span>
<?php	endif; ?>
						<div class="d-sm-none mt-1"><?=wg_ui_tunnel_addresses($tunnel, 1)?></div>
						<div class="d-sm-none mt-1"><?=$badge?></div>
						<span hidden><?=htmlspecialchars(implode(' ', $search))?></span>
					</td>
					<td class="d-none d-sm-table-cell"><?=wg_ui_tunnel_addresses($tunnel)?></td>
					<td class="d-none d-md-table-cell fs-mono"><?=htmlspecialchars($tunnel['listenport'])?></td>
					<td class="d-none d-lg-table-cell"><?=wg_ui_key($tunnel['publickey'], $name)?></td>
					<td class="fs-col-actions">
<?=fs_row_actions([
						['custom', "vpn_wg_peers_edit.php?{$qs}", $name, ['icon' => 'fa-user-plus', 'label' => sprintf(gettext('Add a peer to %s'), $name)]],
						['edit', "vpn_wg_tunnels_edit.php?{$qs}", $name],
						['custom', "vpn_wg_tunnels.php?act=download&{$qs}", $name, ['icon' => 'fa-download', 'post' => true,
						    'label' => sprintf(gettext('Download the configuration of %s'), $name)]],
						['toggle', "vpn_wg_tunnels.php?act=toggle&{$qs}", $name, ['enabled' => $enabled, 'attrs' => $enabled ? [
						    'data-fs-confirm' => sprintf(gettext('Disable tunnel “%s”?'), $name),
						    'data-fs-confirm-detail' => gettext('Its peers lose their connection until the tunnel is enabled again.'),
						    'data-fs-confirm-action' => gettext('Disable')] : []]],
						['delete', "vpn_wg_tunnels.php?act=delete&{$qs}", $name, ['thing' => gettext('tunnel'),
						    'detail' => count($peers) ? gettext('Its peers are kept but no longer assigned to a tunnel.') : null]],
					])?>
					</td>
				</tr>
				<tr class="wg-children<?=$enabled ? '' : ' fs-row-disabled'?>" data-fs-static data-wg-parent="wgt<?=$i?>">
					<td class="d-none d-sm-table-cell"></td>
					<td colspan="5" class="contains-table">
						<div class="wg-children-box">
							<div class="wg-children-head">
<?php	if (!empty($peers)): ?>
								<button type="button" class="wg-toggle" data-wg-toggle aria-expanded="<?=$peers_open ? 'true' : 'false'?>" aria-controls="wgpeers-<?=$i?>">
									<i class="fa-solid fa-chevron-down" aria-hidden="true"></i><?=gettext('Peers')?> <span class="fs-count"><?=count($peers)?></span>
								</button>
<?php	else: ?>
								<span class="wg-children-empty"><?=gettext('No peers yet.')?></span>
<?php	endif; ?>
								<a class="wg-children-add" href="vpn_wg_peers_edit.php?<?=htmlspecialchars($qs)?>"><i class="fa-solid fa-plus icon-embed-btn" aria-hidden="true"></i><?=gettext('Add peer')?><span class="visually-hidden"> <?=htmlspecialchars(sprintf(gettext('to %s'), $name))?></span></a>
							</div>
<?php	if (!empty($peers)): ?>
							<div id="wgpeers-<?=$i?>" class="table-responsive"<?=$peers_open ? '' : ' hidden'?>>
								<table class="table table-hover">
									<thead>
										<tr>
											<th class="fs-col-status d-none d-sm-table-cell"><?=gettext('Status')?></th>
											<th><?=gettext('Peer')?></th>
											<th class="d-none d-sm-table-cell"><?=gettext('Allowed IPs')?></th>
											<th class="d-none d-md-table-cell"><?=gettext('Endpoint')?></th>
											<th class="fs-col-actions"><span class="visually-hidden"><?=gettext('Actions')?></span></th>
										</tr>
									</thead>
									<tbody>
<?php		foreach ($peers as [$peer_idx, $peer, $peer_new]):
			$pname = !empty($peer['descr']) ? $peer['descr'] : wg_truncate_pretty($peer['publickey'], 12);
			$penabled = ($peer['enabled'] == 'yes');
			$pbadge = !$penabled ? fs_badge('disabled') : ($enabled ? fs_badge('enabled') : fs_badge('disabled', gettext('Inactive'), gettext('The tunnel of this peer is disabled')));
?>
										<tr<?=($penabled && $enabled) ? '' : ' class="fs-row-disabled"'?>>
											<td class="d-none d-sm-table-cell"><?=$pbadge?></td>
											<td>
												<a href="vpn_wg_peers_edit.php?peer=<?=intval($peer_idx)?>"><?=htmlspecialchars($pname)?></a>
												<span class="wg-sub"><?=wg_ui_key($peer['publickey'], $pname, 10)?></span>
												<div class="d-sm-none mt-1"><?=wg_ui_address_list(wg_ui_address_strings($peer['allowedips']['row'] ?? array()), 1)?></div>
												<div class="d-sm-none mt-1"><?=$pbadge?></div>
											</td>
											<td class="d-none d-sm-table-cell"><?=wg_ui_address_list(wg_ui_address_strings($peer['allowedips']['row'] ?? array()))?></td>
											<td class="d-none d-md-table-cell"><?=wg_ui_endpoint($peer)?></td>
											<td class="fs-col-actions">
<?=fs_row_actions([
												['edit', "vpn_wg_peers_edit.php?peer={$peer_idx}", $pname],
												['toggle', "vpn_wg_peers.php?act=toggle&peer={$peer_idx}", $pname, ['enabled' => $penabled]],
												['delete', "vpn_wg_peers.php?act=delete&peer={$peer_idx}", $pname, ['thing' => gettext('peer')]],
											])?>
											</td>
										</tr>
<?php		endforeach; ?>
									</tbody>
								</table>
							</div>
<?php	endif; ?>
						</div>
					</td>
				</tr>
<?php
endforeach;

if (empty($tunnels)) {
	fs_empty_row(6, gettext('No WireGuard tunnels yet.'), 'vpn_wg_tunnels_edit.php', gettext('Add tunnel'));
}
?>
			</tbody>
		</table>
	</div>
</div>
</form>

<script type="text/javascript">
//<![CDATA[
events.push(function() {
	wgRegCopyHandler();
	wgRegNestedRows(document.getElementById('wg-tunnels'));
});
//]]>
</script>

<?php
include('wireguard/includes/wg_foot.inc');
include('foot.inc');
?>
