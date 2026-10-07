<?php
/*
 * vpn_wg_peers_edit.php
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
##|*MATCH=vpn_wg_peers_edit.php*
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
$is_new = true;

if (isset($_REQUEST['tun'])) {
	$tun_name = $_REQUEST['tun'];
}

if (isset($_REQUEST['peer']) && is_numericint($_REQUEST['peer'])) {
	$peer_idx = $_REQUEST['peer'];
}

// All form save logic is in wireguard/wg.inc
if ($_POST) {
	switch ($_POST['act']) {
		case 'save':
			$res = wg_do_peer_post($_POST);
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
				header('Location: /wg/vpn_wg_peers.php');
			}
			
			break;

		case 'genpsk':
			// Process ajax call requesting new pre-shared key
			print(wg_gen_psk());
			exit;
			break;

		default:
			// Shouldn't be here, so bail out.
			header('Location: /wg/vpn_wg_peers.php');
			break;
	}
}

if (is_numericint($peer_idx) && is_array(config_get_path("installedpackages/wireguard/peers/item/{$peer_idx}"))) {
	// Looks like we are editing an existing peer
	$pconfig = config_get_path("installedpackages/wireguard/peers/item/{$peer_idx}");
	$is_new = false;
} else {
	// Default to enabled
	$pconfig['enabled'] = 'yes';

	// Automatically choose a tunnel based on the request 
	$pconfig['tun'] = $tun_name;

	// Default to a dynamic tunnel, so hide the endpoint form group
	$is_dynamic = true;
}

$shortcut_section = "wireguard";

$saved_peer = $is_new ? null : config_get_path("installedpackages/wireguard/peers/item/{$peer_idx}");

$pgtitle = array(gettext("VPN"), gettext("WireGuard"), gettext("Peers"));
$pglinks = array("", "/wg/vpn_wg_tunnels.php", "/wg/vpn_wg_peers.php");
if ($is_new) {
	$pgtitle[] = gettext('Add peer');
	$pglinks[] = '@self';
} else {
	$pgtitle[] = htmlspecialchars(!empty($saved_peer['descr']) ? $saved_peer['descr'] : wg_truncate_pretty($saved_peer['publickey'], 12));
	$pgtitle[] = gettext('Edit peer');
	$pglinks[] = '';
	$pglinks[] = '@self';
}

include("head.inc");

wg_print_service_warning();

if (!empty($input_errors)) {
	print_input_errors($input_errors);
}

wg_display_tabs('peers');

wg_ui_styles();

/* Header summary: the saved peer (or the defaults of a new one) */
$summary = $saved_peer ?? array('enabled' => 'yes', 'tun' => $tun_name ?? '', 'descr' => '');
$sum_tun_ok = !empty($summary['tun']) && ($summary['tun'] != 'unassigned') && wg_tunnel_get_config_by_name($summary['tun']);
$sum_keepalive = intval($summary['persistentkeepalive'] ?? 0);
if (empty($summary['endpoint'])) {
	$endpoint_fact = array(gettext('Endpoint'), gettext('Dynamic'));
} else {
	$endpoint_fact = array(gettext('Endpoint'), "{$summary['endpoint']}:" . (!empty($summary['port']) ? $summary['port'] : $wgg['default_port']), 'mono' => true);
}
fs_summary_card([
	'icon' => 'fa-user-shield',
	'title' => $summary['descr'] ?? '',
	'placeholder' => $is_new ? gettext('New peer') : wg_truncate_pretty($summary['publickey'] ?? '', 16),
	'subtitle' => gettext('WireGuard peer'),
	'badges' => [$is_new ? fs_badge('info', gettext('Not saved yet')) : (($summary['enabled'] == 'yes') ? fs_badge('enabled') : fs_badge('disabled'))],
	'label' => gettext('Peer summary'),
	'facts' => [
		$sum_tun_ok ? [gettext('Tunnel'), $summary['tun'], 'mono' => true, 'href' => '/wg/vpn_wg_tunnels_edit.php?tun=' . rawurlencode($summary['tun'])]
		    : [gettext('Tunnel'), '', 'empty' => gettext('Unassigned')],
		$endpoint_fact,
		[gettext('Allowed IPs'), '', 'chips' => wg_ui_address_strings($summary['allowedips']['row'] ?? array()), 'empty' => gettext('None')],
		[gettext('Keep alive'), ($sum_keepalive > 0) ? sprintf(gettext('%d s'), $sum_keepalive) : '', 'empty' => gettext('Off')],
	],
]);

$form = new Form(false);

$form->addGlobal(new Form_Input(
	'index',
	'',
	'hidden',
	$peer_idx
));

/* ---- General */
$section = new Form_Section(gettext('General'));

$section->addInput(new Form_Checkbox(
	'enabled',
	'Enable',
	gettext('Enable peer'),
	$pconfig['enabled'] == 'yes'
))->setHelp('Uncheck to disable the peer without removing it.');

$section->addInput($input = new Form_Select(
	'tun',
	'Tunnel',
	$pconfig['tun'],
	wg_get_tun_list()
))->setHelp("WireGuard tunnel of this peer. <a href='vpn_wg_tunnels_edit.php'>Create a tunnel</a>");

$section->addInput(new Form_Input(
	'descr',
	'Description',
	'text',
	$pconfig['descr'],
	['placeholder' => 'Description']
))->setHelp("For administrative reference (not parsed).");

$form->add($section);

/* ---- Connection */
$section = new Form_Section(gettext('Connection'));

$section->addInput(new Form_Checkbox(
	'dynamic',
	'Dynamic Endpoint',
	gettext('Dynamic'),
	empty($pconfig['endpoint']) || $is_dynamic
))->setHelp('The peer connects to this firewall from an unknown address. Uncheck to set its endpoint address and port.');

$group = new Form_Group('Endpoint');

// Used for hiding/showing the group via JS
$group->addClass("endpoint");

$group->add(new Form_Input(
	'endpoint',
	'Endpoint',
	'text',
	$pconfig['endpoint']
))->addClass('trim')
  ->setHelp('Hostname, IPv4 or IPv6 address of the peer.')
  ->setWidth(5);

$group->add(new Form_Input(
	'port',
	'Endpoint Port',
	'text',
	$pconfig['port']
))->addClass('trim')
  ->setHelp("Port. Empty: {$wgg['default_port']}.")
  ->setWidth(3);

$section->add($group);

$section->addInput(new Form_Input(
	'persistentkeepalive',
	'Keep Alive',
	'text',
	$pconfig['persistentkeepalive'],
	['placeholder' => 'Keep Alive']
))->addClass('trim')
  ->setHelp('Interval in seconds for keep alive packets to this peer. Empty: off.');

$form->add($section);

/* ---- Keys */
$section = new Form_Section(gettext('Keys'));

$section->addInput(new Form_Input(
	'publickey',
	'*Public Key',
	'text',
	$pconfig['publickey'],
	['placeholder' => 'Public Key', 'autocomplete' => 'new-password']
))->addClass('trim fs-mono')
  ->setHelp('WireGuard public key of the peer.');

$group = new Form_Group('Pre-shared Key');

$group->add(new Form_Input(
	'presharedkey',
	'Pre-shared Key',
	wg_secret_input_type(),
	$pconfig['presharedkey'],
	['autocomplete' => 'new-password']
))->addClass('trim fs-mono')
  ->setHelp('Optional extra symmetric key. <a id="copypsk" href="#" role="button" data-success-text="Copied" data-timeout="3000">Copy</a>');

$group->add(new Form_Button(
	'genpsk',
	'Generate',
	null,
	'fa-solid fa-key'
))->addClass('btn-outline-secondary btn-sm')
  ->setHelp('New pre-shared key');

$section->add($group);

$form->add($section);

/* ---- Allowed IPs */
$section = new Form_Section(gettext('Allowed IPs'));

$section->addInput(new Form_StaticText(
	gettext('Hint'),
	htmlspecialchars(gettext('Entries are rounded to their subnet start before they are saved. They must be unique between the peers of a tunnel; ' .
	        'otherwise traffic to an overlapping network goes only to the last peer in the list.'))
));

// Init the addresses array if necessary
if (!is_array($pconfig['allowedips'])
    || !is_array($pconfig['allowedips']['row'])
    || empty($pconfig['allowedips']['row'])) {
		array_init_path($pconfig, 'allowedips/row/0');

		// Hack to ensure empty lists default to /128 mask
		$pconfig['allowedips']['row'][0]['mask'] = '128';
		if (!$is_new) {
			config_set_path("installedpackages/wireguard/peers/item/{$peer_idx}/allowedips/row/0/mask", $pconfig['allowedips']['row'][0]['mask']);
		}
}

$last = count($pconfig['allowedips']['row']) - 1;

foreach ($pconfig['allowedips']['row'] as $counter => $item) {
	$group = new Form_Group($counter == 0 ? 'Allowed IPs' : null);

	$group->addClass('repeatable');

	$group->add(new Form_IpAddress(
		"address{$counter}",
		'Allowed Subnet or Host',
		$item['address'],
		'BOTH'
	))->addClass('trim')
	  ->setHelp($counter == $last ? 'Subnet or host<br />IPv4 or IPv6 subnet or host reachable through this peer.' : '')
	  ->addMask("address_subnet{$counter}", $item['mask'], 128, 0)
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
	'Add Allowed IP',
	null,
	'fa-solid fa-plus'
))->addClass('btn-success btn-sm addbtn');

$form->add($section);

$form->addGlobal(new Form_Input(
	'act',
	'',
	'hidden',
	'save'
));

$save = new Form_Button(
	'saveform',
	gettext('Save peer'),
	null,
	'fa-solid fa-floppy-disk'
);
$save->addClass('btn-primary');
$form->addGlobal($save);

fs_form_cancel($form, '/wg/vpn_wg_peers.php');

print($form);

?>

<?php $genkeywarning = gettext("Overwrite pre-shared key? Click 'ok' to overwrite key."); ?>

<script type="text/javascript">
//<![CDATA[
events.push(function() {
	// Supress "Delete" button if there are fewer than two rows
	checkLastRow();

	wgRegTrimHandler();

	$('#copypsk').click(function () {
		var $this = $(this);
		var originalText = $this.text();

		// The 'modern' way...
		navigator.clipboard.writeText($('#presharedkey').val());

		$this.text($this.attr('data-success-text'));

		setTimeout(function() {
			$this.text(originalText);
		}, $this.attr('data-timeout'));

		// Prevents the browser from scrolling
		return false;
	});

	// These are action buttons, not submit buttons
	$('#genpsk').prop('type','button');

	// Request a new pre-shared key
	$('#genpsk').click(function(event) {
		if ($('#presharedkey').val().length == 0 || confirm(<?=json_encode($genkeywarning)?>)) {
			ajaxRequest = $.ajax({
				url: "/wg/vpn_wg_peers_edit.php",
				type: "post",
				data: {
					act: "genpsk"
				},
				success: function(response, textStatus, jqXHR) {
					$('#presharedkey').val(response);
				}
			});
		}
	});

	$('#dynamic').click(function () {
		updateDynamicSection(this.checked);
	});

	function updateDynamicSection(hide) {
		hideClass('endpoint', hide);
	}

	updateDynamicSection($('#dynamic').prop('checked'));
});
//]]>
</script>

<?php
include('wireguard/includes/wg_foot.inc');
include('foot.inc');
?>
