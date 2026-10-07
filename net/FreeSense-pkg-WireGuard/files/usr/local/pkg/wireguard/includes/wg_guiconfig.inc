<?php
/*
 * wg_guiconfig.inc
 *
 * part of FreeSense (https://www.freesense.org)
 * Copyright (c) 2021 R. Christian McDonald (https://github.com/rcmcdonald91)
 * All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the 'License');
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an 'AS IS' BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// FreeSense includes
require_once('util.inc');

// WireGuard includes
require_once('wireguard/includes/wg.inc');
require_once('wireguard/includes/wg_globals.inc');

function wg_print_service_warning($only_with_tunnels = true) {
	if (!wg_is_service_running() 
	    && (!$only_with_tunnels || count(config_get_path('installedpackages/wireguard/tunnels/item', [])) > 0)) {
		print_info_box(gettext('The WireGuard service is not running.'), 'danger', null);
	}
}

function wg_print_config_apply_box() {
	global $wgg;

	$s = fn($x) => $x;

	if (is_subsystem_dirty($wgg['subsystems']['wg'])) {
		print_apply_box("{$s(gettext('The WireGuard configuration has been changed.'))}<br />
					{$s(gettext('The changes must be applied for them to take effect.'))}<br />
					{$s(gettext('Notice: This action may momentarily suspend active WireGuard peer connections on any changed tunnels.'))}");
	}
}

// Formats peer endpoint address and port for the UI
function wg_format_endpoint($header = true, $peer = null, $endpoint_key = 'endpoint', $port_key = 'port') {
	$s = fn($x) => $x;

	if ($header) {
		return "{$s(gettext('Endpoint'))} : {$s(gettext('Port'))}";
	}

	if (!is_null($peer)) {
		if (!empty($peer[$endpoint_key])) {
			return "{$peer[$endpoint_key]}:{$peer[$port_key]}";
		} else {
			return gettext('Dynamic');
		}
	}
}

// Gets a list of available tunnels in a format suitable for input selection boxes
function wg_get_tun_list() {
	// Format tunnel description if one is configured
	$tunDescr = fn($tunnel) => !empty($tunnel['descr']) ? " ({$tunnel['descr']})" : null;

	$a_ret = array();

	// Always include the unassigned option first
	$a_ret['unassigned'] = 'Unassigned';

	foreach (config_get_path('installedpackages/wireguard/tunnels/item', []) as $tunnel) {
		$a_ret[$tunnel['name']] = "{$tunnel['name']}{$tunDescr($tunnel)}";	
	}

	// Consumers of this function always expect an array type
	return $a_ret;
}

// Truncates a given string if necessary and formats it to make it look good
function wg_truncate_pretty($text, $max_length) {
	$s_truncated = substr($text, 0, $max_length);

	$s_pretty_dots = (strlen($text) > $max_length) ? '...' : null;

	return "{$s_truncated}{$s_pretty_dots}";
}

function wg_interface_status_icon($status = 'up', $enabled_class = "fa-solid fa-arrow-up text-success", $disabled_class = "fa-solid fa-arrow-down text-danger") {
	global $wgg;

	$s = fn($x) => $x;

	$ret_class = ($status === 'up') ? $enabled_class : $disabled_class;

	$ret_html = "<i class=\"{$s(htmlspecialchars($ret_class))}\" style=\"vertical-align: middle;\" title=\"{$s(htmlspecialchars($status))}\"></i>";

	return $ret_html;
}

/* 
 * Returns the appropriate icon for peer handshake status based on latest handshake time
 * 
 * $latest_handshake should be format compatible with DateTime
 */
function wg_handshake_status_icon($latest_handshake = '@0', $tunnel_status = 'up', $fa_icon = "fa-solid fa-handshake") {
	global $wgg;

	$s = fn($x) => $x;

	try {
		$end_time = new DateTimeImmutable;

		$start_time = new DateTime($latest_handshake);
	} catch (Exception $e) {
		return null;
	}

	$diff_time = $end_time->diff($start_time);

	$diff_time_seconds = abs($end_time->getTimestamp() - $start_time->getTimestamp());

	$a_thresholds = $wgg['handshake_thresholds'];

	foreach ($a_thresholds as $threshold => $value) {
		if ($diff_time_seconds >= $threshold) {
			$ret_class = $value['class'];
			$ret_title = $value['title'];
			break;
		}
	}

	$ret_html = "<i class=\"fa-solid {$s(htmlspecialchars($fa_icon))} {$s(htmlspecialchars($ret_class))}\" style=\"vertical-align: middle;\" title=\"{$s(htmlspecialchars($ret_title))}\"></i>";

	return $ret_html;
}

/* 
 * Formats a given time difference in a human-friendly way
 * 
 * $start and $end should be format compatible with DateTime
 */
function wg_human_time_diff($start, $end = null, $num_units = 2, $from_epoch = false) {
	if (is_null($end)) {
		$end = new DateTime('now');
	}

	// If these fail for any reason, just bail out...
	try {
		if (!($start instanceof DateTime)) {
			$start = new DateTime($start);
		}

		if (!($end instanceof DateTime)) {
			$end = new DateTime($end);
		}
	} catch (Exception $e) {
		return gettext('never');
	}

	$interval = $end->diff($start);

	$doPlural = fn($nb, $str) => ($nb <= 1) ? $str[0] : $str[1];

	$doTense = fn($interval) => ($interval->invert) ? gettext('ago') : gettext('from now');

	$a_format = array();

	$a_interval = get_object_vars($interval);

	$tokens	= array(
			'y' => array(gettext('year'), gettext('years')),
			'm' => array(gettext('month'), gettext('months')),
			'd' => array(gettext('day'), gettext('days')),
			'h' => array(gettext('hour'), gettext('hours')),
			'i' => array(gettext('minute'), gettext('minutes')),
			's' => array(gettext('second'), gettext('seconds')));

	foreach ($tokens as $key => $value) {
		if ($a_interval[$key] != 0) {
			$a_format[] = "%{$key} {$doPlural($a_interval[$key], $value)}";
		}
	}

	if ((count($a_format) == 0) || (($start->getTimestamp() == 0) && !$from_epoch)) {
		return gettext('never');
	}

	$s_format = implode(', ', array_slice($a_format, 0, $num_units));

	return "{$interval->format($s_format)} {$doTense($interval)}";
}

// Returns the appropriate text input field type for secrets
function wg_secret_input_type() {
	wg_globals();

	$type = 'text';

	if ((config_get_path('installedpackages/wireguard/config/0/hide_secrets') !== null)
	    && config_get_path('installedpackages/wireguard/config/0/hide_secrets') == 'yes') {
		$type = 'password';
	}

	return $type;
}

// Returns bool indicating if peers should be hidden on status page on load
function wg_status_peers_hidden() {
	wg_globals();

	return (config_get_path('installedpackages/wireguard/config/0/hide_peers') === 'yes');
}

function wg_tunnel_status_class($tunnel = null) {
	global $wgg;

	if (isset($tunnel) && is_array($tunnel)) {
		if (wg_is_service_running() && ($tunnel['enabled'] == 'yes')) {
			return 'enabled';
		}
	}

	return 'disabled';
}

function wg_peer_status_class($peer = null) {
	global $wgg;

	if (isset($peer) && is_array($peer)) {
		$tunnel_state = true;

		// We want to visually disable peers if the tunnel is disabled...
		if ([$tun_idx, $tunnel, $is_new] = wg_tunnel_get_config_by_name($peer['tun'])) {
			$tunnel_state = ($tunnel['enabled'] == 'yes');
		}

		if (wg_is_service_running() && ($peer['enabled'] == 'yes') && $tunnel_state) {
			return 'enabled';
		}
	}

	return 'disabled';
}

// Generates a toggle icon link based on the status of the target
function wg_generate_toggle_icon_link($enabled = true, $type = null, $href = '#', $post = true, $icon_enabled = 'fa-ban', $icon_disabled = 'fa-regular fa-square-check') {
	$s = fn($x) => $x;
	
	$icon = $enabled ? $icon_enabled : $icon_disabled;

	$action = $enabled ? gettext('Disable') : gettext('Enable');

	$title = "{$action} {$type}";

	$usepost = $post ? ' usepost' : null;

	return "<a class=\"fa-solid {$s(htmlspecialchars($icon))}\" title=\"{$s(htmlspecialchars($title))}\" href=\"{$s(htmlspecialchars($href))}\"{$s(htmlspecialchars($usepost))}></a>";
}

function wg_compose_address_popover_link($addresses, $title, $href) {
	global $wgg;

	$s = fn($x) => $x;

	$getDescr = fn($x) => !empty($x) ? htmlspecialchars($x) : "<i>({$s(gettext('none'))})</i>";

	$ret_html = null;

	if (is_array($addresses) && count($addresses) > 0) {
		$extras = count($addresses) - 1;

		if ($extras > 0) {
			$data_html = 	<<<"START"
					<table>
						<thead>
							<th>{$s(gettext('Address'))}</th>
							<th style='padding-left: 10px;'>{$s(gettext('Description'))}</th>
						</thead>
						<tbody>

					START;

			foreach ($addresses as $address) {
				$address['address'] = "{$address['address']}/{$address['mask']}";

				$data_html .= 	<<<"ROW"
								<tr>
									<td>{$s(htmlspecialchars($address['address']))}</td>
									<td style='padding-left: 10px;'>{$getDescr($address['descr'])}</td>
								</tr>

						ROW;
			}

			$data_html .= 	<<<"END"
						</tbody>
					</table>
					END;

			$hint = "{$addresses[0]['address']}/{$addresses[0]['mask']} (+{$extras})";

			$popover_params = " data-bs-toggle=\"popover\" data-bs-trigger=\"hover focus\" data-bs-content=\"{$data_html}\" data-bs-html=\"true\"";
		} else {
			$title = $addresses[0]['descr'];

			$hint = "{$addresses[0]['address']}/{$addresses[0]['mask']}";

			$popover_params = null;
		}

		$ret_html = "<a href=\"{$s(htmlspecialchars($href))}\" title=\"{$s(htmlspecialchars($title))}\"{$popover_params}>{$s(htmlspecialchars($hint))}</a>";
	} else {
		$ret_html = "({$s(gettext('none'))})";
	}

	return $ret_html;
}

function wg_generate_tunnel_address_popover_link($tunnel_name) {
	global $wgg;

	$s = fn($x) => $x;

	if ([$tun_idx, $tunnel, $is_new] = wg_tunnel_get_config_by_name($tunnel_name, false)) {
		if (!is_wg_tunnel_assigned($tunnel['name'])) {
			return wg_compose_address_popover_link($tunnel['addresses']['row'], gettext('Interface Addresses'), "vpn_wg_tunnels_edit.php?tun={$tunnel_name}");
		} else {
			$wg_pfsense_if = wg_get_pfsense_interface_info($tunnel['name']);

			$ret_html = 	<<<"RET"
					<i class="fa-solid fa-sitemap" style="vertical-align: middle;"></i>
					<a style="padding-left: 3px" href="../../interfaces.php?if={$s(htmlspecialchars($wg_pfsense_if['name']))}">{$s(htmlspecialchars($wg_pfsense_if['descr']))} ({$s(htmlspecialchars($wg_pfsense_if['name']))})</a>
					
					RET;

			return $ret_html;
		}
	}

	return null;
}

function wg_generate_peer_allowedips_popup_link($peer_idx) {
	global $wgg;

	$s = fn($x) => $x;

	if ([$peer_idx, $peer, $is_new] = wg_peer_get_config($peer_idx, false)) {
		return wg_compose_address_popover_link($peer['allowedips']['row'], gettext('Allowed IPs'), "vpn_wg_peers_edit.php?peer={$peer_idx}");
	}

	return null;
}

/* ------------------------------------------------------------------
 * FreeSense page style helpers (1.1 WebUI)
 * ------------------------------------------------------------------ */

// Renders the WireGuard tab bar; $active is 'tunnels', 'peers', 'settings' or 'status'
function wg_display_tabs($active) {
	$tabs = array(
		'tunnels'	=> array(gettext('Tunnels'), '/wg/vpn_wg_tunnels.php'),
		'peers'		=> array(gettext('Peers'), '/wg/vpn_wg_peers.php'),
		'settings'	=> array(gettext('Settings'), '/wg/vpn_wg_settings.php'),
		'status'	=> array(gettext('Status'), '/wg/status_wireguard.php'),
	);

	$tab_array = array();

	foreach ($tabs as $key => [$label, $url]) {
		$tab_array[] = array($label, ($key === $active), $url);
	}

	display_top_tabs($tab_array);
}

// Returns 'address/mask' strings from a config 'row' list
function wg_ui_address_strings($rows) {
	$ret = array();

	if (is_array($rows)) {
		foreach ($rows as $row) {
			if (is_array($row) && !empty($row['address'])) {
				$ret[] = "{$row['address']}/{$row['mask']}";
			}
		}
	}

	return $ret;
}

/*
 * Mono list of addresses: the first $max are shown, the rest as a "+n" chip
 * with the full list in its tooltip. Returns escaped HTML.
 */
function wg_ui_address_list($addresses, $max = 2, $empty = null) {
	if (empty($addresses)) {
		return '<span class="fs-muted">' . htmlspecialchars($empty ?? gettext('None')) . '</span>';
	}

	$html = '';

	foreach (array_slice($addresses, 0, $max) as $address) {
		$html .= '<span class="wg-line fs-mono">' . htmlspecialchars($address) . '</span>';
	}

	$more = array_slice($addresses, $max);

	if (!empty($more)) {
		$html .= '<span class="fs-chip fs-chip--mono fs-chip--muted" title="' . htmlspecialchars(implode(', ', $more)) . '">+' . count($more) . '</span>';
	}

	return $html;
}

// Truncated mono key with a copy button. Returns escaped HTML.
function wg_ui_key($key, $what = null, $length = 12) {
	if (empty($key)) {
		return '<span class="fs-muted">' . htmlspecialchars(gettext('Not set')) . '</span>';
	}

	$label = $what ? sprintf(gettext('Copy the public key of %s'), $what) : gettext('Copy public key');

	return '<span class="wg-key"><span class="fs-mono" title="' . htmlspecialchars($key) . '">' . htmlspecialchars(wg_truncate_pretty($key, $length)) . '</span>'
		. '<button type="button" class="wg-copy" data-wg-copy="' . htmlspecialchars($key) . '" title="' . htmlspecialchars($label) . '" aria-label="' . htmlspecialchars($label) . '">'
		. '<i class="fa-regular fa-copy" aria-hidden="true"></i></button></span>';
}

// Endpoint as host:port, or a muted "Dynamic". Returns escaped HTML.
function wg_ui_endpoint($peer, $endpoint_key = 'endpoint', $port_key = 'port') {
	global $wgg;

	if (empty($peer[$endpoint_key])) {
		return '<span class="fs-muted">' . htmlspecialchars(gettext('Dynamic')) . '</span>';
	}

	$port = !empty($peer[$port_key]) ? $peer[$port_key] : $wgg['default_port'];

	$host = is_ipaddrv6($peer[$endpoint_key]) ? "[{$peer[$endpoint_key]}]" : $peer[$endpoint_key];

	return '<span class="fs-mono">' . htmlspecialchars("{$host}:{$port}") . '</span>';
}

/*
 * Assignment of a tunnel: [assigned (bool), interface name, interface description].
 */
function wg_ui_tunnel_assignment($tunnel_name) {
	if (is_wg_tunnel_assigned($tunnel_name)) {
		$info = wg_get_pfsense_interface_info($tunnel_name);

		return array(true, $info['name'] ?? '', $info['descr'] ?? '');
	}

	return array(false, '', '');
}

// Addresses cell of a tunnel: its assigned interface or its own addresses. Returns escaped HTML.
function wg_ui_tunnel_addresses($tunnel, $max = 2) {
	[$assigned, $ifname, $ifdescr] = wg_ui_tunnel_assignment($tunnel['name']);

	if ($assigned) {
		return '<a href="/interfaces.php?if=' . htmlspecialchars(rawurlencode($ifname)) . '" title="' . htmlspecialchars(gettext('Assigned interface')) . '">'
			. '<i class="fa-solid fa-sitemap icon-embed-btn" aria-hidden="true"></i>' . htmlspecialchars("{$ifdescr} ({$ifname})") . '</a>';
	}

	return wg_ui_address_list(wg_ui_address_strings($tunnel['addresses']['row'] ?? array()), $max);
}

/*
 * Handshake state of a running peer as an fs_badge().
 * $latest_handshake is a unix timestamp (0 = never).
 */
function wg_ui_handshake_badge($latest_handshake) {
	global $wgg;

	$ts = intval($latest_handshake);

	if ($ts <= 0) {
		return fs_badge('neutral', gettext('No handshake'), gettext('This peer has not completed a handshake yet'));
	}

	$age = abs(time() - $ts);

	$title = '';

	foreach ($wgg['handshake_thresholds'] as $threshold => $value) {
		if ($age >= $threshold) {
			$title = $value['title'];
			break;
		}
	}

	if ($age < 300) {
		return fs_badge('up', gettext('Active'), $title);
	} elseif ($age < 86400) {
		return fs_badge('warn', gettext('Idle'), $title);
	}

	return fs_badge('down', gettext('Stale'), $title);
}

// Page-local styles shared by the WireGuard pages
function wg_ui_styles() {
?>
<style>
.wg-sub { display: block; color: var(--fs-text-muted); font-size: var(--fs-fs-xs); }
.wg-line { display: block; }
.wg-key { display: inline-flex; align-items: center; gap: .25rem; white-space: nowrap; }
.wg-copy { display: inline-flex; align-items: center; justify-content: center; width: 1.75rem; height: 1.75rem; padding: 0; border: 0; border-radius: var(--fs-r-sm); background: transparent; color: var(--fs-text-muted); }
.wg-copy:hover, .wg-copy:focus-visible { color: var(--fs-text-strong); background: var(--fs-accent-tint); }
.wg-copy.is-done { color: var(--fs-pass); }
.wg-num { white-space: nowrap; font-variant-numeric: tabular-nums; }
.wg-tun-link { font-weight: 600; }
tr.wg-children > td { padding-top: 0; }
.fs-table .table > tbody > tr.wg-children:hover > * { background-color: transparent; }
.wg-children-box { margin: 0 0 .35rem .1rem; padding-left: .85rem; border-left: 2px solid var(--fs-border); }
.wg-children-head { display: flex; flex-wrap: wrap; align-items: center; gap: .25rem .75rem; min-height: 2rem; }
.wg-toggle { display: inline-flex; align-items: center; gap: .4rem; padding: .15rem .25rem; border: 0; border-radius: var(--fs-r-sm); background: transparent; color: var(--fs-text-muted); font-size: var(--fs-fs-sm); font-weight: 600; }
.wg-toggle:hover, .wg-toggle:focus-visible { color: var(--fs-text-strong); }
.wg-toggle > i { transition: transform var(--fs-t-fast) var(--fs-ease); }
.wg-toggle[aria-expanded="false"] > i { transform: rotate(-90deg); }
.wg-children-add { font-size: var(--fs-fs-sm); }
.wg-children-empty { color: var(--fs-text-muted); font-size: var(--fs-fs-sm); }
.wg-children-box .table { margin: 0; }
.wg-children-box .table > thead > tr > th { font-size: var(--fs-fs-xs); }
.wg-children-box .table > tbody > tr:last-child > td { border-bottom: 0; }
@media (max-width: 575.98px) {
	.wg-children-box { margin-left: 0; padding-left: .5rem; }
	.fs-table td.fs-col-actions { white-space: normal; }
	.fs-table td.fs-col-actions .fs-actions { display: flex; flex-wrap: wrap; justify-content: flex-end; width: calc(2 * var(--fs-hit) + 4px); }
}
</style>
<?php
}

?>
