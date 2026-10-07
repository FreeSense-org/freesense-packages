<?php
/*
 * vpn_wg_tunnels_edit.php
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
##|*NAME=VPN: WireGuard: Edit
##|*DESCR=Allow access to the 'VPN: WireGuard' page.
##|*MATCH=vpn_wg_tunnels_edit.php*
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

$pconfig = [];

// Always assume we are creating a new tunnel
$is_new = true;

if (isset($_REQUEST['tun'])) {
	$tun = $_REQUEST['tun'];
	$tun_idx = wg_tunnel_get_array_idx($_REQUEST['tun']);
}

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

	if (isset($_POST['act'])) {
		switch ($_POST['act']) {
			case 'save':
				$res = wg_do_tunnel_post($_POST);
				$input_errors = $res['input_errors'];
				$pconfig = $res['pconfig'];
		
				if (empty($input_errors)) {
					if (wg_is_service_running() && $res['changes']) {
						// Everything looks good so far, so mark the subsystem dirty
						mark_subsystem_dirty($wgg['subsystems']['wg']);

						// Add tunnel to the list to apply
						wg_apply_list_add('tunnels', $res['tuns_to_sync']);
					}
		
					// Save was successful
					header('Location: /wg/vpn_wg_tunnels.php');
				}

				break;

			case 'genkeys':
				// Process ajax call requesting new key pair
				print(wg_gen_keypair(true));
				exit;
				break;

			case 'genpubkey':
				// Process ajax call calculating the public key from a private key
				print(wg_gen_publickey($_POST['privatekey'], true));
				exit;
				break;

			default:
				// Shouldn't be here, so bail out.
				header('Location: /wg/vpn_wg_tunnels.php');
				break;
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
				header('Location: /wg/vpn_wg_tunnels.php');
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

// A dirty string hack
$s = fn($x) => $x;

// Looks like we are editing an existing tunnel
if (is_numericint($tun_idx) && is_array(config_get_path("installedpackages/wireguard/tunnels/item/{$tun_idx}"))) {
	$pconfig = config_get_path("installedpackages/wireguard/tunnels/item/{$tun_idx}");

	// Supress warning and allow peers to be added via the 'Add Peer' link
	$is_new = false;
// Looks like we are creating a new tunnel
} else {
	// Default to enabled
	$pconfig['enabled'] = 'yes';
	$pconfig['name'] = next_wg_if();
}

// Save the MTU settings prior to re(saving)
$pconfig['mtu'] = get_interface_mtu($pconfig['name']);
if (!$is_new) {
	config_set_path("installedpackages/wireguard/tunnels/item/{$tun_idx}/mtu", $pconfig['mtu']);
}

$shortcut_section = "wireguard";

$saved_tunnel = $is_new ? null : config_get_path("installedpackages/wireguard/tunnels/item/{$tun_idx}");
$is_assigned = is_wg_tunnel_assigned($pconfig['name']);

$pgtitle = array(gettext("VPN"), gettext("WireGuard"), gettext("Tunnels"));
$pglinks = array("", "/wg/vpn_wg_tunnels.php", "/wg/vpn_wg_tunnels.php");
if ($is_new) {
	$pgtitle[] = gettext('Add tunnel');
	$pglinks[] = '@self';
} else {
	$pgtitle[] = htmlspecialchars($pconfig['name']);
	$pgtitle[] = gettext('Edit tunnel');
	$pglinks[] = '';
	$pglinks[] = '@self';
}

if (!$is_new) {
	fs_page_action(gettext('Add peer'), 'vpn_wg_peers_edit.php?tun=' . rawurlencode($pconfig['name']), 'fa-user-plus', 'secondary');
}

include("head.inc");

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

/* Header summary: the saved tunnel (or the defaults of a new one) */
$summary = $saved_tunnel ?? array('name' => $pconfig['name'], 'enabled' => 'yes', 'descr' => '', 'listenport' => '', 'publickey' => '');
$summary_peers = $is_new ? array() : wg_tunnel_get_peers_config($summary['name']);
if ($is_assigned) {
	[$sum_assigned, $sum_ifname, $sum_ifdescr] = wg_ui_tunnel_assignment($summary['name']);
	$addr_fact = array(gettext('Assigned to'), "{$sum_ifdescr} ({$sum_ifname})", 'href' => '/interfaces.php?if=' . rawurlencode($sum_ifname));
} else {
	$addr_fact = array(gettext('Addresses'), '', 'chips' => wg_ui_address_strings($summary['addresses']['row'] ?? array()), 'empty' => gettext('None'));
}
fs_summary_card([
	'icon' => 'fa-shield-halved',
	'title' => $summary['descr'] ?? '',
	'placeholder' => $is_new ? gettext('New tunnel') : $summary['name'],
	'subtitle' => gettext('WireGuard tunnel'),
	'badges' => [$is_new ? fs_badge('info', gettext('Not saved yet')) : (($summary['enabled'] == 'yes') ? fs_badge('enabled') : fs_badge('disabled'))],
	'meta' => $summary['name'],
	'label' => gettext('Tunnel summary'),
	'facts' => [
		[gettext('Listen port'), $summary['listenport'] ?? '', 'mono' => true, 'empty' => $is_new ? sprintf(gettext('%s (suggested)'), next_wg_port()) : gettext('Not set')],
		$addr_fact,
		[gettext('Peers'), $is_new ? '' : (string)count($summary_peers), 'empty' => gettext('Save the tunnel first')],
		[gettext('Public key'), wg_truncate_pretty($summary['publickey'] ?? '', 16), 'mono' => true, 'empty' => gettext('Not generated yet')],
	],
	'actions' => $is_new ? [] : [[gettext('Status'), '/wg/status_wireguard.php', 'fa-chart-line']],
]);

$form = new Form(false);

$form->addGlobal(new Form_Input(
	'index',
	'',
	'hidden',
	$tun_idx
));

/* ---- General */
$section = new Form_Section(gettext('General'));

$tun_enable = new Form_Checkbox(
	'enabled',
	'Enable',
	gettext('Enable tunnel'),
	$pconfig['enabled'] == 'yes'
);

$tun_enable->setHelp('A tunnel must be enabled before it can be assigned to an interface.');

// Disable the tunnel enabled button if interface is assigned in FreeSense
if ($is_assigned) {
	$tun_enable->setDisabled();
	$tun_enable->setHelp('The tunnel is assigned to an interface, so it cannot be disabled.');

	// We still want to POST this field, make it a hidden field now
	$form->addGlobal(new Form_Input(
		'enabled',
		'',
		'hidden',
		'yes'
	));
}

$section->addInput($tun_enable);

$section->addInput(new Form_Input(
	'descr',
	'Description',
	'text',
	$pconfig['descr'],
	['placeholder' => 'Description']
))->setHelp('For administrative reference (not parsed).');

$section->addInput(new Form_Input(
	'listenport',
	'*Listen Port',
	'text',
	$pconfig['listenport'],
	['placeholder' => next_wg_port(), 'autocomplete' => 'new-password']
))->addClass('trim')
  ->setHelp('UDP port this tunnel uses to talk to its peers.');

$form->add($section);

/* ---- Keys */
$section = new Form_Section(gettext('Keys'));

$group = new Form_Group('*Interface Keys');

$group->add(new Form_Input(
	'privatekey',
	'Private Key',
	wg_secret_input_type(),
	$pconfig['privatekey'],
	['autocomplete' => 'new-password']
))->addClass('trim fs-mono')
  ->setHelp('Private key (required).');

$group->add(new Form_Input(
	'publickey',
	'Public Key',
	'text',
	$pconfig['publickey']
))->addClass('trim fs-mono')
  ->setHelp('Public key, derived from the private key. <a id="copypubkey" href="#" role="button" data-success-text="Copied" data-timeout="3000">Copy</a>')->setReadonly();

$group->add(new Form_Button(
	'genkeys',
	'Generate',
	null,
	'fa-solid fa-key'
))->addClass('btn-outline-secondary btn-sm')
  ->setHelp('New key pair')
  ->setWidth(1);

$section->add($group);

$form->add($section);

/* ---- Addresses / assignment */
$section = new Form_Section(gettext('Interface'));

$section->setAttribute('id', 'addresses');

if (!$is_assigned) {
	$section->addInput(new Form_StaticText(
		'Assignment',
		"<span class='fs-muted'>{$s(htmlspecialchars(gettext('Not assigned.')))}</span> <a href='/interfaces_assign.php'><i class='fa-solid fa-sitemap icon-embed-btn' aria-hidden='true'></i>{$s(htmlspecialchars(gettext('Interface assignments')))}</a>"
	))->setHelp('The addresses below apply only while the tunnel is not assigned to an interface.');

	$section->addInput(new Form_StaticText(
		'Firewall Rules',
		"<a href='/firewall_rules.php?if={$s(htmlspecialchars(rawurlencode($wgg['ifgroupentry']['ifname'])))}'><i class='fa-solid fa-shield-halved icon-embed-btn' aria-hidden='true'></i>{$s(htmlspecialchars(gettext('WireGuard interface group')))}</a>"
	));

	// Init the addresses array if necessary
	if (!is_array($pconfig['addresses'])
	    || !is_array($pconfig['addresses']['row'])
	    || empty($pconfig['addresses']['row'])) {
			array_init_path($pconfig, 'addresses/row/0');

			// Hack to ensure empty lists default to /128 mask
			$pconfig['addresses']['row'][0]['mask'] = '128';
		}

	$last = count($pconfig['addresses']['row']) - 1;

	foreach ($pconfig['addresses']['row'] as $counter => $item) {
		$group = new Form_Group($counter == 0 ? 'Interface Addresses' : '');

		$group->addClass('repeatable');

		$group->add(new Form_IpAddress(
			"address{$counter}",
			'Interface Address',
			$item['address'],
			'BOTH'
		))->addClass('trim')
		  ->setHelp($counter == $last ? 'Address<br />IPv4 or IPv6 address of the tunnel interface.' : '')
		  ->addMask("address_subnet{$counter}", $item['mask'])
		  ->setWidth(4);

		$group->add(new Form_Input(
			"address_descr{$counter}",
			'Description',
			'text',
			$item['descr']
		))->setHelp($counter == $last ? 'Description' : '')
		  ->setWidth(4);

		$group->add(new Form_Button(
			"deleterow{$counter}",
			'Delete',
			null,
			'fa-solid fa-trash-can'
		))->addClass('btn-warning btn-sm');

		$section->add($group);
	}

	$section->addInput(new Form_Button(
		'addrow',
		'Add Address',
		null,
		'fa-solid fa-plus'
	))->addClass('btn-success btn-sm addbtn');
} else {
	$wg_pfsense_if = wg_get_pfsense_interface_info($pconfig['name']);

	$section->addInput(new Form_StaticText(
		'Assignment',
		"<a href='/interfaces_assign.php'><i class='fa-solid fa-sitemap icon-embed-btn' aria-hidden='true'></i>{$s(htmlspecialchars($wg_pfsense_if['descr']))} ({$s(htmlspecialchars($wg_pfsense_if['name']))})</a>"
	))->setHelp('Addresses are set on the assigned interface.');

	$section->addInput(new Form_StaticText(
		'Interface',
		"<a href='/interfaces.php?if={$s(htmlspecialchars(rawurlencode($wg_pfsense_if['name'])))}'><i class='fa-solid fa-ethernet icon-embed-btn' aria-hidden='true'></i>{$s(htmlspecialchars(gettext('Interface configuration')))}</a>"
	));

	$section->addInput(new Form_StaticText(
		'Firewall Rules',
		"<a href='/firewall_rules.php?if={$s(htmlspecialchars(rawurlencode($wg_pfsense_if['name'])))}'><i class='fa-solid fa-shield-halved icon-embed-btn' aria-hidden='true'></i>{$s(htmlspecialchars(gettext('Firewall rules')))}</a>"
	));
}

$form->add($section);

$form->addGlobal(new Form_Input(
	'mtu',
	'',
	'hidden',
	$pconfig['mtu']
));

$form->addGlobal(new Form_Input(
	'is_new',
	'',
	'hidden',
	$is_new
));

$form->addGlobal(new Form_Input(
	'act',
	'',
	'hidden',
	'save'
));

$save = new Form_Button(
	'saveform',
	gettext('Save tunnel'),
	null,
	'fa-solid fa-floppy-disk'
);
$save->addClass('btn-primary');
$form->addGlobal($save);

fs_form_cancel($form, '/wg/vpn_wg_tunnels.php');

print($form);

$tun_qs = 'tun=' . rawurlencode($pconfig['name']);
?>

<div class="panel panel-default fs-table" id="peers">
<?php fs_table_toolbar([
	'title' => gettext('Peers'),
	'search' => (count($summary_peers) > 5) ? gettext('Search peers…') : false,
	'noun' => gettext('peers'),
	'noun_one' => gettext('peer'),
	'actions' => $is_new ? '' : '<a class="btn btn-sm btn-outline-secondary" href="vpn_wg_peers_edit.php?' . htmlspecialchars($tun_qs) . '"><i class="fa-solid fa-plus icon-embed-btn" aria-hidden="true"></i>' . htmlspecialchars(gettext('Add peer')) . '</a>',
]); ?>
	<div class="panel-body table-responsive">
		<table id="peertable" class="table table-hover table-rowdblclickedit" data-sortable>
			<thead>
				<tr>
					<th class="fs-col-status d-none d-sm-table-cell"><?=gettext('Status')?></th>
					<th data-fs-search><?=gettext('Peer')?></th>
					<th data-fs-search><?=gettext('Allowed IPs')?></th>
					<th data-fs-search class="d-none d-md-table-cell"><?=gettext('Endpoint')?></th>
					<th data-fs-search class="d-none d-lg-table-cell"><?=gettext('Public key')?></th>
					<th class="fs-col-actions"><span class="visually-hidden"><?=gettext('Actions')?></span></th>
				</tr>
			</thead>
			<tbody>
<?php
foreach ($summary_peers as [$peer_idx, $peer, $peer_new]):
	$pname = !empty($peer['descr']) ? $peer['descr'] : wg_truncate_pretty($peer['publickey'], 12);
	$penabled = ($peer['enabled'] == 'yes');
	$pbadge = $penabled ? fs_badge('enabled') : fs_badge('disabled');
?>
				<tr<?=$penabled ? '' : ' class="fs-row-disabled"'?>>
					<td class="d-none d-sm-table-cell"><?=$pbadge?></td>
					<td>
						<a href="vpn_wg_peers_edit.php?peer=<?=intval($peer_idx)?>"><strong><?=htmlspecialchars($pname)?></strong></a>
						<div class="d-sm-none mt-1"><?=$pbadge?></div>
					</td>
					<td><?=wg_ui_address_list(wg_ui_address_strings($peer['allowedips']['row'] ?? array()))?></td>
					<td class="d-none d-md-table-cell"><?=wg_ui_endpoint($peer)?></td>
					<td class="d-none d-lg-table-cell"><?=wg_ui_key($peer['publickey'], $pname)?></td>
					<td class="fs-col-actions">
<?=fs_row_actions([
						['edit', "vpn_wg_peers_edit.php?peer={$peer_idx}", $pname],
						['toggle', "vpn_wg_tunnels_edit.php?act=toggle&peer={$peer_idx}&{$tun_qs}", $pname, ['enabled' => $penabled]],
						['delete', "vpn_wg_tunnels_edit.php?act=delete&peer={$peer_idx}&{$tun_qs}", $pname, ['thing' => gettext('peer')]],
					])?>
					</td>
				</tr>
<?php
endforeach;

if ($is_new) {
	fs_empty_row(6, gettext('Save the tunnel before adding peers.'));
} elseif (empty($summary_peers)) {
	fs_empty_row(6, gettext('No peers on this tunnel yet.'), 'vpn_wg_peers_edit.php?' . $tun_qs, gettext('Add peer'));
}
?>
			</tbody>
		</table>
	</div>
</div>

<?php $genKeyWarning = gettext("Overwrite key pair? Click 'ok' to overwrite keys."); ?>

<script type="text/javascript">
//<![CDATA[
events.push(function() {
	// Supress "Delete" button if there are fewer than two rows
	checkLastRow();

	wgRegTrimHandler();
	wgRegCopyHandler();

	$('#copypubkey').click(function () {
		var $this = $(this);
		var originalText = $this.text();

		try {
			// The 'modern' way, this only works with https
			navigator.clipboard.writeText($('#publickey').val());
		} catch {
			console.warn("Failed to copy text using navigator.clipboard, falling back to commands");
			$('#publickey').select();
			document.execCommand("copy");
		}

		$this.text($this.attr('data-success-text'));

		setTimeout(function() {
			$this.text(originalText);
		}, $this.attr('data-timeout'));

		// Prevents the browser from scrolling
		return false;
	});

	// These are action buttons, not submit buttons
	$("#genkeys").prop('type', 'button');

	// Request a new public/private key pair
	$('#genkeys').click(function(event) {
		if ($('#privatekey').val().length == 0 || confirm(<?=json_encode($genKeyWarning)?>)) {
			ajaxRequest = $.ajax({
				url: '/wg/vpn_wg_tunnels_edit.php',
				type: 'post',
				data: {act: 'genkeys'},
				success: function(response, textStatus, jqXHR) {
					resp = JSON.parse(response);
					$('#publickey').val(resp.pubkey);
					$('#privatekey').val(resp.privkey);
				}
			});
		}
	});

	// Request a new public key when private key is changed
	$('#privatekey').change(function(event) {
		ajaxRequest = $.ajax(
			{
				url: '/wg/vpn_wg_tunnels_edit.php',
				type: 'post',
				data: {
					act: 'genpubkey',
					privatekey: $('#privatekey').val()
				},
			success: function(response, textStatus, jqXHR) {
				resp = JSON.parse(response);
				$('#publickey').val(resp.pubkey);
			}
		});
	});
});
//]]>
</script>

<?php
include('wireguard/includes/wg_foot.inc');
include('foot.inc');
?>
