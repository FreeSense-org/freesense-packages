<?php
/*
 * vpn_wg_settings.php
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
##|*NAME=VPN: WireGuard: Settings
##|*DESCR=Allow access to the 'VPN: WireGuard' page.
##|*MATCH=vpn_wg_settings.php*
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

$save_success = false;

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
				$res = wg_do_settings_post($_POST);
				$input_errors = $res['input_errors'];
				$pconfig = $res['pconfig'];

				if (empty($input_errors) && $res['changes']) {
					wg_toggle_wireguard();
					mark_subsystem_dirty($wgg['subsystems']['wg']);
					$save_success = true;
				}

				break;

			default:
				// Shouldn't be here, so bail out.
				header('Location: /wg/vpn_wg_settings.php');
				break;
		}
	}
}

// A dirty string hack
$s = fn($x) => $x;

// Just to make sure defaults are properly assigned if anything is missing
wg_defaults_install();

// Grab current configuration from the XML
$pconfig = config_get_path('installedpackages/wireguard/config/0');

$shortcut_section = 'wireguard';

$pgtitle = array(gettext('VPN'), gettext('WireGuard'), gettext('Settings'));
$pglinks = array('', '/wg/vpn_wg_tunnels.php', '@self');

include('head.inc');

wg_print_service_warning();

if (isset($_POST['apply'])) {
	print_apply_result_box($ret_code);
}

wg_print_config_apply_box();

if (!empty($input_errors)) {
	print_input_errors($input_errors);
}

wg_display_tabs('settings');

$interface_group_list = array('all' => gettext('All Tunnels'), 'unassigned' => gettext('Only Unassigned Tunnels'), 'none' => gettext('None'));

/* Header summary: the saved settings */
$svc_running = wg_is_service_running();
$sum_interval = wg_get_endpoint_resolve_interval();
fs_summary_card([
	'icon' => 'fa-shield-halved',
	'title' => gettext('WireGuard'),
	'subtitle' => gettext('Package settings'),
	'badges' => [
		wg_is_service_enabled() ? fs_badge('enabled') : fs_badge('disabled'),
		$svc_running ? fs_badge('up', gettext('Running')) : fs_badge('down', gettext('Stopped')),
	],
	'label' => gettext('WireGuard summary'),
	'facts' => [
		[gettext('Tunnels'), (string)count(config_get_path('installedpackages/wireguard/tunnels/item', [])), 'href' => '/wg/vpn_wg_tunnels.php'],
		[gettext('Peers'), (string)count(config_get_path('installedpackages/wireguard/peers/item', [])), 'href' => '/wg/vpn_wg_peers.php'],
		[gettext('Interface group'), $interface_group_list[$pconfig['interface_group']] ?? ($pconfig['interface_group'] ?? '')],
		[gettext('Endpoint re-resolve'), (intval($sum_interval) > 0) ? sprintf(gettext('Every %d s'), $sum_interval) : '', 'empty' => gettext('Off'),
		    'note' => ($pconfig['resolve_interval_track'] == 'yes') ? gettext('Follows the system setting') : null],
	],
	'actions' => [[gettext('Status'), '/wg/status_wireguard.php', 'fa-chart-line']],
]);

$form = new Form(false);

/* ---- General */
$section = new Form_Section(gettext('General'));

$wg_enable = new Form_Checkbox(
	'enable',
	gettext('Enable'),
	gettext('Enable WireGuard'),
	wg_is_service_enabled()
);

$wg_enable->setHelp(gettext('WireGuard cannot be disabled while a tunnel is assigned to an interface.'));

if (wg_is_wg_assigned()) {
	$wg_enable->setDisabled();

	// We still want to POST this field, make it a hidden field now
	$form->addGlobal(new Form_Input(
		'enable',
		'',
		'hidden',
		(wg_is_service_enabled() ? 'yes' : 'no')
	));
}

$section->addInput($wg_enable);

$section->addInput(new Form_Checkbox(
	'keep_conf',
	gettext('Keep Configuration'),
	gettext('Enable'),
	$pconfig['keep_conf'] == 'yes'
))->setHelp(gettext('Keep all tunnels and package settings when the package is removed or reinstalled (default).'));

$section->addInput($input = new Form_Select(
	'interface_group',
	gettext('Interface Group Membership'),
	$pconfig['interface_group'],
	$interface_group_list
))->setHelp("{$s(htmlspecialchars(gettext('Which tunnels are members of the WireGuard interface group. Group firewall rules are evaluated before interface rules.')))}<br />
	     {$s(htmlspecialchars(sprintf(gettext("Default: '%s'."), $interface_group_list['all'])))}");

$form->add($section);

/* ---- Endpoint resolving */
$section = new Form_Section(gettext('Endpoint hostnames'));

$group = new Form_Group(gettext('Endpoint Hostname Resolve Interval'));

$group->add(new Form_Input(
	'resolve_interval',
	gettext('Endpoint Hostname Resolve Interval'),
	'text',
	wg_get_endpoint_resolve_interval(),
	['placeholder' => wg_get_endpoint_resolve_interval()]
))->addClass('trim')
  ->setHelp("{$s(htmlspecialchars(gettext('Seconds between re-resolving endpoint hostnames.')))}<br />
	     {$s(htmlspecialchars(sprintf(gettext('Default %s seconds; 0 disables.'), $wgg['default_resolve_interval'])))}");

$group->add(new Form_Checkbox(
	'resolve_interval_track',
	null,
	gettext('Track System Resolve Interval'),
	($pconfig['resolve_interval_track'] == 'yes')
))->setHelp("{$s(htmlspecialchars(gettext("Use the system 'Aliases Hostnames Resolve Interval'")))} (<a href=\"/system_advanced_firewall.php\">{$s(htmlspecialchars(gettext('Firewall & NAT')))}</a>).");

$section->add($group);

$form->add($section);

/* ---- User interface (rarely changed) */
$ui_state = COLLAPSIBLE | (!empty($input_errors) ? SEC_OPEN : SEC_CLOSED);
$section = new Form_Section(gettext('User interface'), 'wg-ui', $ui_state);

$section->addInput(new Form_Checkbox(
	'hide_secrets',
	gettext('Hide Secrets'),
	gettext('Enable'),
	$pconfig['hide_secrets'] == 'yes'
))->setHelp(gettext('Show private and pre-shared keys as password fields.'));

$section->addInput(new Form_Checkbox(
	'hide_peers',
	gettext('Hide Peers'),
	gettext('Enable'),
	$pconfig['hide_peers'] == 'yes'
))->setHelp(gettext('Fold the peers of every tunnel away when the status page opens (default).'));

$form->add($section);

$form->addGlobal(new Form_Input(
	'act',
	'',
	'hidden',
	'save'
));

$save = new Form_Button(
	'saveform',
	gettext('Save'),
	null,
	'fa-solid fa-floppy-disk'
);
$save->addClass('btn-primary');
$form->addGlobal($save);

print($form);

?>

<script type="text/javascript">
//<![CDATA[
events.push(function() {
	wgRegTrimHandler();

	$('#resolve_interval_track').click(function () {
		updateResolveInterval(this.checked);
	});

	function updateResolveInterval(state) {
		$('#resolve_interval').prop( "disabled", state);
	}

	updateResolveInterval($('#resolve_interval_track').prop('checked'));
});
//]]>
</script>

<?php
include('wireguard/includes/wg_foot.inc');
include('foot.inc');
?>
