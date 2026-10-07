<?php
/*
 * vpn_wg_peers.php
 *
 * part of FreeSense (https://www.freesense.org)
 * Copyright (c) 2004-2026 The FreeSense Project
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
##|*MATCH=vpn_wg_peers.php*
##|-PRIV

// FreeSense includes
require_once('functions.inc');
require_once('guiconfig.inc');

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

	if (isset($_POST['peer'])) {
		$peer_idx = $_POST['peer'];

		switch ($_POST['act']) {
			case 'toggle':
				$res = wg_toggle_peer($peer_idx);
				break;

			case 'delete':
				$res = wg_delete_peer($peer_idx);
				break;

			default:
				// Shouldn't be here, so bail out.
				header('Location: /wg/vpn_wg_peers.php');
				break;
		}

		$input_errors = $res['input_errors'];

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

$pgtitle = array(gettext('VPN'), gettext('WireGuard'), gettext('Peers'));
$pglinks = array('', '/wg/vpn_wg_tunnels.php', '@self');

$peers = config_get_path('installedpackages/wireguard/peers/item', []);

$tunnel_state = array();
foreach (config_get_path('installedpackages/wireguard/tunnels/item', []) as $tunnel) {
	$tunnel_state[$tunnel['name']] = ($tunnel['enabled'] == 'yes');
}

$counts = array('enabled' => 0, 'dynamic' => 0, 'unassigned' => 0);
$tunnel_filter = array(gettext('All tunnels'));
foreach ($peers as $peer) {
	$counts['enabled'] += ($peer['enabled'] == 'yes') ? 1 : 0;
	$counts['dynamic'] += empty($peer['endpoint']) ? 1 : 0;
	if (!isset($tunnel_state[$peer['tun']])) {
		$counts['unassigned']++;
	}
}
foreach (array_keys($tunnel_state) as $tun_name) {
	$tunnel_filter[$tun_name] = $tun_name;
}
if ($counts['unassigned'] > 0) {
	$tunnel_filter['unassigned'] = gettext('Unassigned');
}

fs_page_action(gettext('Add peer'), 'vpn_wg_peers_edit.php', 'fa-plus');

include('head.inc');

wg_print_service_warning();

if (isset($_POST['apply'])) {
	print_apply_result_box($ret_code);
}

wg_print_config_apply_box();

if (!empty($input_errors)) {
	print_input_errors($input_errors);
}

wg_display_tabs('peers');

wg_ui_styles();
?>

<?php if (!empty($peers)): ?>
<div class="fs-tiles">
<?php
	$disabled = count($peers) - $counts['enabled'];
	fs_tile(gettext('Peers'), count($peers), null, $counts['unassigned'] ? sprintf(gettext('%d without a tunnel'), $counts['unassigned']) : null);
	fs_tile(gettext('Enabled'), $counts['enabled'], null, $disabled ? sprintf(gettext('%d disabled'), $disabled) : null);
	fs_tile(gettext('Dynamic endpoints'), $counts['dynamic']);
	fs_tile(gettext('Tunnels'), count($tunnel_state));
?>
</div>
<?php endif; ?>

<form name="mainform" method="post">
<div class="panel panel-default fs-table">
<?php fs_table_toolbar([
	'title' => gettext('WireGuard peers'),
	'search' => gettext('Search peers…'),
	'noun' => gettext('peers'),
	'noun_one' => gettext('peer'),
	'filters' => [
		'tunnel' => $tunnel_filter,
		'state' => [gettext('All states'), 'enabled' => gettext('Enabled'), 'disabled' => gettext('Disabled')],
	],
]); ?>
	<div class="panel-body table-responsive">
		<table class="table table-hover table-rowdblclickedit" data-sortable>
			<thead>
				<tr>
					<th class="fs-col-status d-none d-sm-table-cell"><?=gettext('Status')?></th>
					<th data-fs-search><?=gettext('Peer')?></th>
					<th data-fs-search class="d-none d-sm-table-cell"><?=gettext('Tunnel')?></th>
					<th data-fs-search><?=gettext('Allowed IPs')?></th>
					<th data-fs-search class="d-none d-md-table-cell"><?=gettext('Endpoint')?></th>
					<th data-fs-search class="d-none d-lg-table-cell"><?=gettext('Public key')?></th>
					<th class="fs-col-actions"><span class="visually-hidden"><?=gettext('Actions')?></span></th>
				</tr>
			</thead>
			<tbody>
<?php
foreach ($peers as $peer_idx => $peer):
	$name = !empty($peer['descr']) ? $peer['descr'] : wg_truncate_pretty($peer['publickey'], 12);
	$enabled = ($peer['enabled'] == 'yes');
	$has_tunnel = isset($tunnel_state[$peer['tun']]);
	$active = $enabled && $has_tunnel && $tunnel_state[$peer['tun']];
	if (!$enabled) {
		$badge = fs_badge('disabled');
	} elseif (!$has_tunnel) {
		$badge = fs_badge('warn', gettext('No tunnel'), gettext('This peer is not assigned to a tunnel'));
	} elseif (!$active) {
		$badge = fs_badge('disabled', gettext('Inactive'), gettext('The tunnel of this peer is disabled'));
	} else {
		$badge = fs_badge('enabled');
	}
	$keepalive = intval($peer['persistentkeepalive'] ?? 0);
?>
				<tr data-fs-filter-tunnel="<?=htmlspecialchars($has_tunnel ? $peer['tun'] : 'unassigned')?>" data-fs-filter-state="<?=$enabled ? 'enabled' : 'disabled'?>"<?=$active ? '' : ' class="fs-row-disabled"'?>>
					<td class="d-none d-sm-table-cell"><?=$badge?></td>
					<td>
						<a href="vpn_wg_peers_edit.php?peer=<?=intval($peer_idx)?>"><strong><?=htmlspecialchars($name)?></strong></a>
<?php	if ($keepalive > 0): ?>
						<span class="wg-sub"><?=htmlspecialchars(sprintf(gettext('Keep alive %d s'), $keepalive))?></span>
<?php	endif; ?>
						<span class="wg-sub d-sm-none fs-mono"><?=htmlspecialchars($has_tunnel ? $peer['tun'] : gettext('Unassigned'))?></span>
						<div class="d-sm-none mt-1"><?=$badge?></div>
					</td>
					<td class="d-none d-sm-table-cell">
<?php	if ($has_tunnel): ?>
						<a class="fs-mono" href="vpn_wg_tunnels_edit.php?tun=<?=htmlspecialchars(rawurlencode($peer['tun']))?>"><?=htmlspecialchars($peer['tun'])?></a>
<?php	else: ?>
						<span class="fs-muted"><?=gettext('Unassigned')?></span>
<?php	endif; ?>
					</td>
					<td><?=wg_ui_address_list(wg_ui_address_strings($peer['allowedips']['row'] ?? array()))?></td>
					<td class="d-none d-md-table-cell"><?=wg_ui_endpoint($peer)?></td>
					<td class="d-none d-lg-table-cell"><?=wg_ui_key($peer['publickey'], $name)?></td>
					<td class="fs-col-actions">
<?=fs_row_actions([
						['edit', "vpn_wg_peers_edit.php?peer={$peer_idx}", $name],
						['toggle', "vpn_wg_peers.php?act=toggle&peer={$peer_idx}", $name, ['enabled' => $enabled]],
						['delete', "vpn_wg_peers.php?act=delete&peer={$peer_idx}", $name, ['thing' => gettext('peer')]],
					])?>
					</td>
				</tr>
<?php
endforeach;

if (empty($peers)) {
	fs_empty_row(7, gettext('No WireGuard peers yet.'), 'vpn_wg_peers_edit.php', gettext('Add peer'));
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
});
//]]>
</script>

<?php
include('wireguard/includes/wg_foot.inc');
include('foot.inc');
?>
