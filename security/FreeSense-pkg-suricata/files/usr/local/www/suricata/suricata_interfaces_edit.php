<?php
/*
 * suricata_interfaces_edit.php
 *
 * part of FreeSense (https://www.freesense.org)
 * Copyright (c) 2004-2026 The FreeSense Project
 * Copyright (c) 2003-2004 Manuel Kasper
 * Copyright (c) 2005 Bill Marquette
 * Copyright (c) 2009 Robert Zelaya Sr. Developer
 * Copyright (c) 2024 Bill Meeks
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

// Define an array of native-mode netmap compatible NIC drivers
$netmapifs = array('cc', 'cxl', 'cxgbe', 'em', 'igb', 'lem', 'ix', 'ixgbe', 'ixl', 're', 'vtnet');
if (pfs_version_compare(false, 2.4, $g['product_version'])) {
	/* add FreeBSD 12 iflib(4) supported devices */
	$netmapifs = array_merge($netmapifs, array('ena', 'ice', 'igc', 'bnxt', 'vmx'));
	sort($netmapifs);
}

$a_rule = config_get_path('installedpackages/suricata/rule', []);

if (isset($_POST['id']) && is_numericint($_POST['id']))
	$id = $_POST['id'];
elseif (isset($_GET['id']) && is_numericint($_GET['id']));
	$id = htmlspecialchars($_GET['id'], ENT_QUOTES | ENT_HTML401);

if (!is_numericint($id)) {
		header("Location: /suricata/suricata_interfaces.php");
		exit;
}

if (isset($_POST['action']))
	$action = htmlspecialchars($_POST['action'], ENT_QUOTES | ENT_HTML401);
elseif (isset($_GET['action']))
	$action = htmlspecialchars($_GET['action'], ENT_QUOTES | ENT_HTML401);
else
	$action = "";

$pconfig = array();
if (!config_path_enabled('installedpackages/suricata/rule', $id)) {
	/* Adding a new interface, so generate new UUID and flag rules to rebuild. */
	$pconfig['uuid'] = suricata_generate_id();
	$rebuild_rules = true;
	$new_interface = true;
}
else {
	$pconfig['uuid'] = $a_rule[$id]['uuid'];
	$pconfig['descr'] = $a_rule[$id]['descr'];
	$rebuild_rules = false;
	$new_interface = false;
}
$suricata_uuid = $pconfig['uuid'];

// Get the physical configured interfaces on the firewall
$interfaces = get_configured_interface_with_descr();

// Footnote real interface associated with each configured interface
foreach ($interfaces as $if => $desc) {
	$interfaces[$if] = $interfaces[$if] . " (" . get_real_interface($if) . ")";
}

// Add a special "Unassigned" interface selection at end of list
$interfaces["Unassigned"] = gettext("Unassigned");

// See if interface is already configured, and use its $config values if set
if (isset($id) && isset($a_rule[$id])) {
	/* old options from config.xml */
	$if_friendly = convert_friendly_interface_to_friendly_descr($a_rule[$id]['interface']);
	$pconfig = $a_rule[$id];
	if (empty($pconfig['uuid']))
		$pconfig['uuid'] = $suricata_uuid;
	if (get_real_interface($pconfig['interface']) == "") {
		$pconfig['interface'] = gettext("Unassigned");
		$pconfig['enable'] = "off";
	}
}
elseif (isset($_POST['interface']) && !isset($a_rule[$id])) {
	// Saving first Suricata interface
	$pconfig['interface'] = $_POST['interface'];
	$if_friendly = convert_friendly_interface_to_friendly_descr($pconfig['interface']);
}
elseif (isset($id) && !isset($a_rule[$id])) {
    // Must be a new interface, so try to pick next available physical interface to use
	$ifaces = get_configured_interface_list();
	$ifrules = array();

	// Populate the $ifrules array with all existing configured Suricata interfaces
	foreach(config_get_path('installedpackages/suricata/rule', []) as $r)
		$ifrules[] = $r['interface'];

	// Walk FreeSense-configured interfaces, and take first one not already in our Suricata list
	foreach ($ifaces as $i) {
		if (!in_array($i, $ifrules)) {
			$pconfig['interface'] = $i;
			$if_friendly = convert_friendly_interface_to_friendly_descr($i);

			// If the interface is a VLAN, use the VLAN description
			// if set, otherwise default to the friendly description.
			if ($vlan = interface_is_vlan(get_real_interface($i))) {
				if (strlen($vlan['descr']) > 0) {
					$pconfig['descr'] = $vlan['descr'];
				}
				else {
					$pconfig['descr'] = convert_friendly_interface_to_friendly_descr($i);
				}
			}
			else {
				$pconfig['descr'] = convert_friendly_interface_to_friendly_descr($i);
			}

			$pconfig['enable'] = 'on';
			$pconfig['inspect_recursion_limit'] = '3000';
			break;
		}
	}
	if (count($ifrules) == count($ifaces)) {
		$input_errors[] = gettext("No more available interfaces to configure for Suricata!");
		$interfaces = array();
		$pconfig = array();
	}
}

// Get real interface where this Suricata instance runs
$if_real = get_real_interface($pconfig['interface']);

// Set defaults for any empty key parameters
if (empty($pconfig['blockoffendersip']))
	$pconfig['blockoffendersip'] = "both";
if (empty($pconfig['blockoffenderskill']))
	$pconfig['blockoffenderskill'] = "on";
if (empty($pconfig['ips_mode']))
	$pconfig['ips_mode'] = 'ips_mode_legacy';
if (empty($pconfig['ips_netmap_threads']))
	$pconfig['ips_netmap_threads'] = 'auto';
if (empty($pconfig['block_drops_only']))
	$pconfig['block_drops_only'] = "off";
if (empty($pconfig['passlist_debug_log']))
	$pconfig['passlist_debug_log'] = "off";
if (empty($pconfig['runmode']))
	$pconfig['runmode'] = "autofp";
if (empty($pconfig['autofp_scheduler']))
	$pconfig['autofp_scheduler'] = "hash";
if (empty($pconfig['max_pending_packets']))
	$pconfig['max_pending_packets'] = "1024";
if (empty($pconfig['detect_eng_profile']))
	$pconfig['detect_eng_profile'] = "medium";
if (empty($pconfig['mpm_algo']))
	$pconfig['mpm_algo'] = "auto";
if (empty($pconfig['spm_algo']))
	$pconfig['spm_algo'] = "auto";
if (empty($pconfig['sgh_mpm_context']))
	$pconfig['sgh_mpm_context'] = "auto";
if (empty($pconfig['enable_stats_collection']))
	$pconfig['enable_stats_collection'] = "off";
if (empty($pconfig['enable_http_log']))
	$pconfig['enable_http_log'] = "on";
if (empty($pconfig['http_log_filetype']))
	$pconfig['http_log_filetype'] = "regular";
if (empty($pconfig['append_http_log']))
	$pconfig['append_http_log'] = "on";
if (empty($pconfig['http_log_extended']))
	$pconfig['http_log_extended'] = "on";
if (empty($pconfig['tls_log_extended']))
	$pconfig['tls_log_extended'] = "on";
if (empty($pconfig['append_tls_log']))
	$pconfig['append_tls_log'] = "on";
if (empty($pconfig['tls_log_filetype']))
	$pconfig['tls_log_filetype'] = "regular";
if (empty($pconfig['stats_upd_interval']))
	$pconfig['stats_upd_interval'] = "10";
if (empty($pconfig['max_pcap_log_size']))
	$pconfig['max_pcap_log_size'] = "32";
if (empty($pconfig['max_pcap_log_files']))
	$pconfig['max_pcap_log_files'] = "100";
if (empty($pconfig['pcap_log_conditional']))
	$pconfig['pcap_log_conditional'] = "alerts";
if (empty($pconfig['alertsystemlog_facility']))
	$pconfig['alertsystemlog_facility'] = "local1";
if (empty($pconfig['alertsystemlog_priority']))
	$pconfig['alertsystemlog_priority'] = "notice";
if (empty($pconfig['eve_output_type']))
	$pconfig['eve_output_type'] = "regular";
if (empty($pconfig['eve_systemlog_facility']))
	$pconfig['eve_systemlog_facility'] = "local1";
if (empty($pconfig['eve_systemlog_priority']))
	$pconfig['eve_systemlog_priority'] = "notice";
if (empty($pconfig['eve_log_ethernet']))
	$pconfig['eve_log_ethernet'] = "no";
if (empty($pconfig['eve_log_drops']))
	$pconfig['eve_log_drops'] = "on";
if (empty($pconfig['eve_log_alert_drops']))
	$pconfig['eve_log_alert_drops'] = "on";
if (empty($pconfig['eve_log_alerts']))
	$pconfig['eve_log_alerts'] = "on";
if (empty($pconfig['eve_log_alerts_payload']))
	$pconfig['eve_log_alerts_payload'] = "on";
if (empty($pconfig['eve_log_alerts_packet']))
	$pconfig['eve_log_alerts_packet'] = "on";
if (empty($pconfig['eve_log_alerts_http']))
	$pconfig['eve_log_alerts_http'] = "on";
if (empty($pconfig['eve_log_alerts_metadata']))
	$pconfig['eve_log_alerts_metadata'] = "on";
if (empty($pconfig['eve_log_alerts_xff']))
	$pconfig['eve_log_alerts_xff'] = "off";
if (empty($pconfig['eve_log_alerts_xff_mode']))
	$pconfig['eve_log_alerts_xff_mode'] = "extra-data";
if (empty($pconfig['eve_log_alerts_xff_deployment']))
	$pconfig['eve_log_alerts_xff_deployment'] = "reverse";
if (empty($pconfig['eve_log_alerts_xff_header']))
	$pconfig['eve_log_alerts_xff_header'] = "X-Forwarded-For";
if (empty($pconfig['eve_log_http']))
	$pconfig['eve_log_http'] = "on";
if (empty($pconfig['eve_log_dns']))
	$pconfig['eve_log_dns'] = "on";
if (empty($pconfig['eve_log_tls']))
	$pconfig['eve_log_tls'] = "on";
if (empty($pconfig['eve_log_dhcp']))
	$pconfig['eve_log_dhcp'] = "on";
if (empty($pconfig['eve_log_nfs']))
	$pconfig['eve_log_nfs'] = "on";
if (empty($pconfig['eve_log_smb']))
	$pconfig['eve_log_smb'] = "on";
if (empty($pconfig['eve_log_krb5']))
	$pconfig['eve_log_krb5'] = "on";
if (empty($pconfig['eve_log_ikev2']))
	$pconfig['eve_log_ikev2'] = "on";
if (empty($pconfig['eve_log_quic']))
	$pconfig['eve_log_quic'] = "on";
if (empty($pconfig['eve_log_tftp']))
	$pconfig['eve_log_tftp'] = "on";
if (empty($pconfig['eve_log_rdp']))
	$pconfig['eve_log_rdp'] = "off";
if (empty($pconfig['eve_log_sip']))
	$pconfig['eve_log_sip'] = "off";
if (empty($pconfig['eve_log_files']))
	$pconfig['eve_log_files'] = "on";
if (empty($pconfig['eve_log_ssh']))
	$pconfig['eve_log_ssh'] = "on";
if (empty($pconfig['eve_log_smtp']))
	$pconfig['eve_log_smtp'] = "on";
if (empty($pconfig['eve_log_flow']))
	$pconfig['eve_log_flow'] = "off";
if (empty($pconfig['eve_log_netflow']))
	$pconfig['eve_log_netflow'] = "off";
if (empty($pconfig['eve_log_stats']))
	$pconfig['eve_log_stats'] = "off";
if (empty($pconfig['eve_log_stats_totals']))
	$pconfig['eve_log_stats_totals'] = "on";
if (empty($pconfig['eve_log_stats_deltas']))
	$pconfig['eve_log_stats_deltas'] = "off";
if (empty($pconfig['eve_log_stats_threads']))
	$pconfig['eve_log_stats_threads'] = "off";
if (empty($pconfig['eve_log_anomaly']))
	$pconfig['eve_log_anomaly'] = "off";
if (empty($pconfig['eve_log_anomaly_type_decode']))
	$pconfig['eve_log_anomaly_type_decode'] = "off";
if (empty($pconfig['eve_log_anomaly_type_stream']))
	$pconfig['eve_log_anomaly_type_stream'] = "off";
if (empty($pconfig['eve_log_anomaly_type_applayer']))
	$pconfig['eve_log_anomaly_type_applayer'] = "on";
if (empty($pconfig['eve_log_anomaly_packethdr']))
	$pconfig['eve_log_anomaly_packethdr'] = "off";
if (empty($pconfig['eve_log_drop'])) {
	$pconfig['eve_log_drop'] = "on";
}
if (empty($pconfig['eve_log_snmp'])) {
	$pconfig['eve_log_snmp'] = "on";
}
if (empty($pconfig['eve_log_mqtt'])) {
	$pconfig['eve_log_mqtt'] = "on";
}
if (empty($pconfig['eve_log_ftp'])) {
	$pconfig['eve_log_ftp'] = "on";
}
if (empty($pconfig['eve_log_http2'])) {
	$pconfig['eve_log_http2'] = "on";
}
if (empty($pconfig['eve_log_rfb'])) {
	$pconfig['eve_log_rfb'] = "on";
}
if (empty($pconfig['eve_log_http_extended']))
	$pconfig['eve_log_http_extended'] = $pconfig['http_log_extended'];
if (empty($pconfig['eve_log_tls_extended']))
	$pconfig['eve_log_tls_extended'] = $pconfig['tls_log_extended'];
if (empty($pconfig['eve_log_dhcp_extended']))
	$pconfig['eve_log_dhcp_extended'] = "off";
if (empty($pconfig['eve_log_smtp_extended']))
	$pconfig['eve_log_smtp_extended'] = $pconfig['smtp_log_extended'];
if (empty($pconfig['eve_log_http_extended_headers']))
	$pconfig['eve_log_http_extended_headers'] = "accept, accept-charset, accept-datetime, accept-encoding, accept-language, accept-range, age, allow, authorization, cache-control, connection, content-encoding, content-language, content-length, content-location, content-md5, content-range, content-type, cookie, date, dnt, etags, from, last-modified, link, location, max-forwards, origin, pragma, proxy-authenticate, proxy-authorization, range, referrer, refresh, retry-after, server, set-cookie, te, trailer, transfer-encoding, upgrade, vary, via, warning, www-authenticate, x-authenticated-user, x-flash-version, x-forwarded-proto, x-requested-with";
if (empty($pconfig['eve_log_smtp_extended_fields']))
	$pconfig['eve_log_smtp_extended_fields'] = "received, x-mailer, x-originating-ip, relays, reply-to, bcc";
if (empty($pconfig['eve_log_tls_extended_headers']))
	$pconfig['eve_log_tls_extended_headers'] = "subject, issuer, session_resumed, serial, fingerprint, sni, version, not_before, not_after, certificate, chain, ja3, ja3s";
if (empty($pconfig['eve_log_files_magic']))
	$pconfig['eve_log_files_magic'] = "off";
if (empty($pconfig['eve_log_files_hash']))
	$pconfig['eve_log_files_hash'] = "none";
if (empty($pconfig['eve_redis_server']))
	$pconfig['eve_redis_server'] = "127.0.0.1";
if (empty($pconfig['eve_redis_port']))
	$pconfig['eve_redis_port'] = "6379";
if (empty($pconfig['eve_redis_mode']))
	$pconfig['eve_redis_mode'] = "list";
if (empty($pconfig['eve_redis_key']))
	$pconfig['eve_redis_key'] = "suricata";
if (empty($pconfig['intf_promisc_mode']))
	$pconfig['intf_promisc_mode'] = "on";
if (empty($pconfig['intf_snaplen']))
	$pconfig['intf_snaplen'] = "1518";
if (empty($pconfig['file_store_logdir']))
	$pconfig['file_store_logdir'] = base64_encode("{$suricatalogdir}suricata_{$if_real}{$suricata_uuid}/filestore");

// See if creating a new interface by duplicating an existing one
if (strcasecmp($action, 'dup') == 0) {

	// Try to pick the next available physical interface to use
	$ifaces = get_configured_interface_list();
	$ifrules = array();
	foreach(config_get_path('installedpackages/suricata/rule', []) as $r)
		$ifrules[] = $r['interface'];
	foreach ($ifaces as $i) {
		if (!in_array($i, $ifrules)) {
			$pconfig['interface'] = $i;
			$pconfig['enable'] = 'on';
			$pconfig['descr'] = strtoupper($i);
			$pconfig['inspect_recursion_limit'] = '3000';
			break;
		}
	}

	if (count($ifrules) == count($ifaces)) {
		$input_errors[] = gettext("No more available interfaces to configure for Suricata!");
		$interfaces = array();
		$pconfig = array();
	}

	// Set Home Net, External Net, Suppress List and Pass List to defaults
	unset($pconfig['suppresslistname']);
	unset($pconfig['passlistname']);
	unset($pconfig['homelistname']);
	unset($pconfig['externallistname']);
}

if ($_REQUEST['ajax'] == 'ajax') {
	print("At least we got that straight!");
	exit;
}

if (isset($_POST["save"]) && !$input_errors) {
	if (!isset($_POST['interface']))
		$input_errors[] = gettext("Choosing an Interface is mandatory!");

	/* See if assigned interface is already in use */
	if (isset($_POST['interface'])) {
		foreach (config_get_path('installedpackages/suricata/rule', []) as $k => $v) {
			if (($v['interface'] == $_POST['interface']) && ($id != $k)) {
				$input_errors[] = gettext("The '{$_POST['interface']}' interface is already assigned to another Suricata instance.");
				break;
			}
		}
	}

	if ($_POST['ips_mode'] == 'ips_mode_inline') {
		$is_netmap = false;
		$realint = get_real_interface($_POST['interface']);
		foreach ($netmapifs as $if) {
			if (substr($realint, 0, strlen($if)) == $if) {
				$is_netmap = true;
				break;
			}
		}
		if (!$is_netmap) {
			$input_errors[] = gettext("The '{$_POST['interface']}' interface does not support Inline IPS Mode with native netmap.");
		}
	}

	// If Suricata is disabled on this interface, stop any running instance,
	// on an active interface, save the change, and exit.
	if ($_POST['enable'] != 'on' && config_path_enabled('installedpackages/suricata/rule', $id)) {
		$a_rule[$id]['enable'] = $_POST['enable'] ? 'on' : 'off';
		config_set_path('installedpackages/suricata/rule', $a_rule);
		suricata_stop($a_rule[$id], get_real_interface($a_rule[$id]['interface']));
		write_config("Suricata pkg: disabled Suricata on " . convert_friendly_interface_to_friendly_descr($a_rule[$id]['interface']));
		$rebuild_rules = false;
		sync_suricata_package_config();
		header( 'Expires: Sat, 26 Jul 1997 05:00:00 GMT' );
		header( 'Last-Modified: ' . gmdate( 'D, d M Y H:i:s' ) . ' GMT' );
		header( 'Cache-Control: no-store, no-cache, must-revalidate' );
		header( 'Cache-Control: post-check=0, pre-check=0', false );
		header( 'Pragma: no-cache' );
		header("Location: /suricata/suricata_interfaces.php");
		exit;
	}

	// Validate inputs
	if (isset($_POST['stats_upd_interval']) && !is_numericint($_POST['stats_upd_interval']))
		$input_errors[] = gettext("The value for Stats Update Interval must contain only digits and evaluate to an integer.");

	if ($_POST['max_pending_packets'] < 1 || $_POST['max_pending_packets'] > 65000)
		$input_errors[] = gettext("The value for Maximum-Pending-Packets must be between 1 and 65,000!");

	if (isset($_POST['max_pcap_log_size']) && !is_numeric($_POST['max_pcap_log_size']))
		$input_errors[] = gettext("The value for 'Max Packet Log Size' must be numbers only.  Do not include any alphabetic characters.");

	if (isset($_POST['max_pcap_log_files']) && !is_numeric($_POST['max_pcap_log_files']))
		$input_errors[] = gettext("The value for 'Max Packet Log Files' must be numbers only.");

	if (!empty($_POST['inspect_recursion_limit']) && !is_numeric($_POST['inspect_recursion_limit']))
		$input_errors[] = gettext("The value for Inspect Recursion Limit can either be blank or contain only digits evaluating to an integer greater than or equal to 0.");

	if ($_POST['intf_snaplen'] < 1 || !is_numeric($_POST['intf_snaplen']))
		$input_errors[] = gettext("The value for Interface Snaplen must contain only digits evaluating to an integer value greater than or equal to 1.");

	if (!empty($_POST['eve_redis_server']) && !is_ipaddr($_POST['eve_redis_server']))
		$input_errors[] = gettext("The value for 'EVE REDIS Server' must be an IP address.");

	if (!empty($_POST['eve_redis_port']) && !is_port($_POST['eve_redis_port']))
		$input_errors[] = gettext("The value for 'EVE REDIS Server' must have a valid TCP port.");

	if (!empty($_POST['eve_redis_key']) && !preg_match('/^[A-Za-z0-9]+$/',$_POST['eve_redis_key']))
		$input_errors[] = gettext("The value for 'EVE REDIS Key' must be alphanumeric.");

	if ($_POST['enable_telegraf_stats'] == "on" && empty($_POST['suricata_telegraf_unix_socket_name']))
		$input_errors[] = gettext("You must specify the Unix Socket name when enabling Telegraf stats output!");

	// if no errors, generate and save the interface configuration
	if (!$input_errors) {
		$natent = array();

		// Grab the existing configuration for modifications if it exists
		if (config_path_enabled('installedpackages/suricata/rule', $id)) {
			$natent = $a_rule[$id];
		}
		$natent['interface'] = $_POST['interface'];
		$natent['enable'] = $_POST['enable'] ? 'on' : 'off';
		$natent['uuid'] = $pconfig['uuid'];

		if ($_POST['descr']) $natent['descr'] =  htmlspecialchars($_POST['descr']); else $natent['descr'] = strtoupper($natent['interface']);
		if ($_POST['enable_verbose_logging'] == "on") { $natent['enable_verbose_logging'] = 'on'; }else{ $natent['enable_verbose_logging'] = 'off'; }
		if ($_POST['max_pcap_log_size']) $natent['max_pcap_log_size'] = $_POST['max_pcap_log_size']; else unset($natent['max_pcap_log_size']);
		if ($_POST['max_pcap_log_files']) $natent['max_pcap_log_files'] = $_POST['max_pcap_log_files']; else unset($natent['max_pcap_log_files']);
		if ($_POST['pcap_log_conditional']) $natent['pcap_log_conditional'] = $_POST['pcap_log_conditional'];
		if ($_POST['enable_stats_collection'] == "on") { $natent['enable_stats_collection'] = 'on'; }else{ $natent['enable_stats_collection'] = 'off'; }
		if ($_POST['enable_stats_log'] == "on") { $natent['enable_stats_log'] = 'on'; }else{ $natent['enable_stats_log'] = 'off'; }
		if ($_POST['append_stats_log'] == "on") { $natent['append_stats_log'] = 'on'; }else{ $natent['append_stats_log'] = 'off'; }
		if ($_POST['stats_upd_interval'] >= 1) $natent['stats_upd_interval'] = $_POST['stats_upd_interval']; else $natent['stats_upd_interval'] = "10";
		if ($_POST['enable_telegraf_stats'] == "on") $natent['enable_telegraf_stats'] = 'on'; else $natent['enable_telegraf_stats'] = 'off';
		if ($_POST['suricata_telegraf_unix_socket_name']) $natent['suricata_telegraf_unix_socket_name'] =  base64_encode($_POST['suricata_telegraf_unix_socket_name']);
		if ($_POST['enable_http_log'] == "on") { $natent['enable_http_log'] = 'on'; }else{ $natent['enable_http_log'] = 'off'; }
		if ($_POST['append_http_log'] == "on") { $natent['append_http_log'] = 'on'; }else{ $natent['append_http_log'] = 'off'; }
		if ($_POST['enable_tls_log'] == "on") { $natent['enable_tls_log'] = 'on'; }else{ $natent['enable_tls_log'] = 'off'; }
		if ($_POST['append_tls_log'] == "on") { $natent['append_tls_log'] = 'on'; }else{ $natent['append_tls_log'] = 'off'; }
		if ($_POST['enable_tls_store'] == "on") { $natent['enable_tls_store'] = 'on'; }else{ $natent['enable_tls_store'] = 'off'; }
		if ($_POST['http_log_extended'] == "on") { $natent['http_log_extended'] = 'on'; }else{ $natent['http_log_extended'] = 'off'; }
		if ($_POST['tls_log_extended'] == "on") { $natent['tls_log_extended'] = 'on'; }else{ $natent['tls_log_extended'] = 'off'; }
		if ($_POST['tls_session_resumption'] == "on") { $natent['tls_session_resumption'] = 'on'; }else{ $natent['tls_session_resumption'] = 'off'; }
		if ($_POST['enable_pcap_log'] == "on") { $natent['enable_pcap_log'] = 'on'; }else{ $natent['enable_pcap_log'] = 'off'; }
		if ($_POST['pcap_use_stream_depth'] == "on") { $natent['pcap_use_stream_depth'] = 'on'; }else{ $natent['pcap_use_stream_depth'] = 'off'; }
		if ($_POST['pcap_honor_pass_rules'] == "on") { $natent['pcap_honor_pass_rules'] = 'on'; }else{ $natent['pcap_honor_pass_rules'] = 'off'; }
		if ($_POST['enable_file_store'] == "on") { $natent['enable_file_store'] = 'on'; }else{ $natent['enable_file_store'] = 'off'; }
		if ($natent['enable_file_store'] == "on") {
			if ($_POST['file_store_logdir']) { $natent['file_store_logdir'] = base64_encode($_POST['file_store_logdir']); }else{ $natent['file_store_logdir'] = $pconfig['file_store_logdir']; }
		}
		if ($_POST['tls_log_filetype']) $natent['tls_log_filetype'] = $_POST['tls_log_filetype']; else unset($natent['tls_log_filetype']);
		if ($natent['tls_log_filetype'] == "unix_dgram" || $natent['tls_log_filetype'] == "unix_stream") {
			if ($_POST['tls_log_socket']) { $natent['tls_log_socket'] = base64_encode($_POST['tls_log_socket']); }else{ $natent['tls_log_socket'] = $pconfig['tls_log_socket']; }
		}
		if ($_POST['http_log_filetype']) $natent['http_log_filetype'] = $_POST['http_log_filetype']; else unset($natent['http_log_filetype']);
		if ($natent['http_log_filetype'] == "unix_dgram" || $natent['http_log_filetype'] == "unix_stream") {
			if ($_POST['http_log_socket']) { $natent['http_log_socket'] = base64_encode($_POST['http_log_socket']); }else{ $natent['http_log_socket'] = $pconfig['tls_log_socket']; }
		}
		if ($_POST['runmode']) $natent['runmode'] = $_POST['runmode']; else unset($natent['runmode']);
		if ($_POST['autofp_scheduler']) $natent['autofp_scheduler'] = $_POST['autofp_scheduler']; else unset($natent['autofp_scheduler']);
		if ($_POST['max_pending_packets']) $natent['max_pending_packets'] = $_POST['max_pending_packets']; else unset($natent['max_pending_packets']);
		if ($_POST['inspect_recursion_limit'] >= '0') $natent['inspect_recursion_limit'] = $_POST['inspect_recursion_limit']; else unset($natent['inspect_recursion_limit']);
		if ($_POST['intf_snaplen'] > '0') $natent['intf_snaplen'] = $_POST['intf_snaplen']; else $natent['inspect_recursion_limit'] = "1518";
		if ($_POST['detect_eng_profile']) $natent['detect_eng_profile'] = $_POST['detect_eng_profile']; else unset($natent['detect_eng_profile']);
		if ($_POST['mpm_algo']) $natent['mpm_algo'] = $_POST['mpm_algo']; else unset($natent['mpm_algo']);
		if ($_POST['spm_algo']) $natent['spm_algo'] = $_POST['spm_algo']; else unset($natent['spm_algo']);
		if ($_POST['sgh_mpm_context']) $natent['sgh_mpm_context'] = $_POST['sgh_mpm_context']; else unset($natent['sgh_mpm_context']);
		if ($_POST['blockoffenders'] == "on") $natent['blockoffenders'] = 'on'; else $natent['blockoffenders'] = 'off';
		if ($_POST['ips_mode']) $natent['ips_mode'] = $_POST['ips_mode']; else unset($natent['ips_mode']);
		if ($_POST['ips_netmap_threads']) $natent['ips_netmap_threads'] = $_POST['ips_netmap_threads']; else $natent['ips_netmap_threads'] = "auto";
		if ($_POST['blockoffenderskill'] == "on") $natent['blockoffenderskill'] = 'on'; else $natent['blockoffenderskill'] = 'off';
		if ($_POST['block_drops_only'] == "on") $natent['block_drops_only'] = 'on'; else $natent['block_drops_only'] = 'off';
		if ($_POST['passlist_debug_log'] == "on") $natent['passlist_debug_log'] = 'on'; else $natent['passlist_debug_log'] = 'off';
		if ($_POST['blockoffendersip']) $natent['blockoffendersip'] = $_POST['blockoffendersip']; else unset($natent['blockoffendersip']);
		if ($_POST['passlistname']) $natent['passlistname'] =  $_POST['passlistname']; else unset($natent['passlistname']);
		if ($_POST['homelistname']) $natent['homelistname'] =  $_POST['homelistname']; else unset($natent['homelistname']);
		if ($_POST['externallistname']) $natent['externallistname'] =  $_POST['externallistname']; else unset($natent['externallistname']);
		if ($_POST['suppresslistname']) $natent['suppresslistname'] =  $_POST['suppresslistname']; else unset($natent['suppresslistname']);
		if ($_POST['alertsystemlog'] == "on") { $natent['alertsystemlog'] = 'on'; }else{ $natent['alertsystemlog'] = 'off'; }
		if ($_POST['alertsystemlog_facility']) $natent['alertsystemlog_facility'] = $_POST['alertsystemlog_facility'];
		if ($_POST['alertsystemlog_priority']) $natent['alertsystemlog_priority'] = $_POST['alertsystemlog_priority'];
		if ($_POST['enable_eve_log'] == "on") { $natent['enable_eve_log'] = 'on'; }else{ $natent['enable_eve_log'] = 'off'; }
		if ($_POST['eve_output_type']) $natent['eve_output_type'] = $_POST['eve_output_type'];
		if ($natent['eve_output_type'] == "unix_dgram" || $natent['eve_output_type'] == "unix_stream") {
			if ($_POST['eve_output_socket']) { $natent['eve_output_socket'] = base64_encode($_POST['eve_output_socket']); }else{ $natent['eve_output_socket'] = $pconfig['eve_output_socket']; }
		}
		if ($_POST['eve_systemlog_facility']) $natent['eve_systemlog_facility'] = $_POST['eve_systemlog_facility'];
		if ($_POST['eve_systemlog_priority']) $natent['eve_systemlog_priority'] = $_POST['eve_systemlog_priority'];
		if ($_POST['eve_log_ethernet'] == "yes") { $natent['eve_log_ethernet'] = 'yes'; }else{ $natent['eve_log_ethernet'] = 'no'; }
		if ($_POST['eve_log_alerts'] == "on") { $natent['eve_log_alerts'] = 'on'; }else{ $natent['eve_log_alerts'] = 'off'; }
		if ($_POST['eve_log_alerts_payload']) { $natent['eve_log_alerts_payload'] = $_POST['eve_log_alerts_payload']; }else{ $natent['eve_log_alerts_payload'] = 'off'; }
		if ($_POST['eve_log_alerts_packet'] == "on") { $natent['eve_log_alerts_packet'] = 'on'; }else{ $natent['eve_log_alerts_packet'] = 'off'; }
		if ($_POST['eve_log_alerts_metadata'] == "on") { $natent['eve_log_alerts_metadata'] = 'on'; }else{ $natent['eve_log_alerts_metadata'] = 'off'; }
		if ($_POST['eve_log_alerts_http'] == "on") { $natent['eve_log_alerts_http'] = 'on'; }else{ $natent['eve_log_alerts_http'] = 'off'; }
		if ($_POST['eve_log_alerts_xff'] == "on") { $natent['eve_log_alerts_xff'] = 'on'; }else{ $natent['eve_log_alerts_xff'] = 'off'; }
		if ($_POST['eve_log_alerts_xff_mode']) { $natent['eve_log_alerts_xff_mode'] = $_POST['eve_log_alerts_xff_mode']; }else{ $natent['eve_log_alert_xff_mode'] = 'extra-data'; }
		if ($_POST['eve_log_alerts_xff_deployment']) { $natent['eve_log_alerts_xff_deployment'] = $_POST['eve_log_alerts_xff_deployment']; }else{ $natent['eve_log_alert_xff_deployment'] = 'reverse'; }
		if ($_POST['eve_log_alerts_xff_header']) { $natent['eve_log_alerts_xff_header'] = $_POST['eve_log_alerts_xff_header']; }else{ $natent['eve_log_alert_xff_mode'] = 'X-Forwarded-For'; }
		if ($_POST['eve_log_alerts_verdict'] == "on") { $natent['eve_log_alerts_verdict'] = 'on'; }else{ $natent['eve_log_alerts_verdict'] = 'off'; }
		if ($_POST['eve_log_alerts_tagged'] == "on") { $natent['eve_log_alerts_tagged'] = 'on'; }else{ $natent['eve_log_alerts_tagged'] = 'off'; }
		if ($_POST['eve_log_drops'] == "on") { $natent['eve_log_drops'] = 'on'; }else{ $natent['eve_log_drops'] = 'off'; }
		if ($_POST['eve_log_alert_drops'] == "on") { $natent['eve_log_alert_drops'] = 'on'; }else{ $natent['eve_log_alert_drops'] = 'off'; }
		if ($_POST['eve_log_drops_verdict'] == "on") { $natent['eve_log_drops_verdict'] = 'on'; }else{ $natent['eve_log_drops_verdict'] = 'off'; }
		if ($_POST['eve_log_drops_flows']) $natent['eve_log_drops_flows'] = $_POST['eve_log_drops_flows'];
		if ($_POST['eve_log_anomaly'] == "on") { $natent['eve_log_anomaly'] = 'on'; }else{ $natent['eve_log_anomaly'] = 'off'; }
		if ($_POST['eve_log_anomaly_type_decode'] == "on") { $natent['eve_log_anomaly_type_decode'] = 'on'; }else{ $natent['eve_log_anomaly_type_decode'] = 'off'; }
		if ($_POST['eve_log_anomaly_type_stream'] == "on") { $natent['eve_log_anomaly_type_stream'] = 'on'; }else{ $natent['eve_log_anomaly_type_stream'] = 'off'; }
		if ($_POST['eve_log_anomaly_type_applayer'] == "on") { $natent['eve_log_anomaly_type_applayer'] = 'on'; }else{ $natent['eve_log_anomaly_type_applayer'] = 'off'; }
		if ($_POST['eve_log_anomaly_packethdr'] == "on") { $natent['eve_log_anomaly_packethdr'] = 'on'; }else{ $natent['eve_log_anomaly_packethdr'] = 'off'; }
		if ($_POST['eve_log_http'] == "on") { $natent['eve_log_http'] = 'on'; }else{ $natent['eve_log_http'] = 'off'; }
		if ($_POST['eve_log_dns'] == "on") { $natent['eve_log_dns'] = 'on'; }else{ $natent['eve_log_dns'] = 'off'; }
		if ($_POST['eve_log_tls'] == "on") { $natent['eve_log_tls'] = 'on'; }else{ $natent['eve_log_tls'] = 'off'; }
		if ($_POST['eve_log_dhcp'] == "on") { $natent['eve_log_dhcp'] = 'on'; }else{ $natent['eve_log_dhcp'] = 'off'; }
		if ($_POST['eve_log_nfs'] == "on") { $natent['eve_log_nfs'] = 'on'; }else{ $natent['eve_log_nfs'] = 'off'; }
		if ($_POST['eve_log_smb'] == "on") { $natent['eve_log_smb'] = 'on'; }else{ $natent['eve_log_smb'] = 'off'; }
		if ($_POST['eve_log_krb5'] == "on") { $natent['eve_log_krb5'] = 'on'; }else{ $natent['eve_log_krb5'] = 'off'; }
		if ($_POST['eve_log_ikev2'] == "on") { $natent['eve_log_ikev2'] = 'on'; }else{ $natent['eve_log_ikev2'] = 'off'; }
		if ($_POST['eve_log_tftp'] == "on") { $natent['eve_log_tftp'] = 'on'; }else{ $natent['eve_log_tftp'] = 'off'; }
		if ($_POST['eve_log_bittorrent'] == "on") { $natent['eve_log_bittorrent'] = 'on'; }else{ $natent['eve_log_bittorrent'] = 'off'; }
		if ($_POST['eve_log_pgsql'] == "on") { $natent['eve_log_pgsql'] = 'on'; }else{ $natent['eve_log_pgsql'] = 'off'; }
		if ($_POST['eve_log_quic'] == "on") { $natent['eve_log_quic'] = 'on'; }else{ $natent['eve_log_quic'] = 'off'; }
		if ($_POST['eve_log_rdp'] == "on") { $natent['eve_log_rdp'] = 'on'; }else{ $natent['eve_log_rdp'] = 'off'; }
		if ($_POST['eve_log_sip'] == "on") { $natent['eve_log_sip'] = 'on'; }else{ $natent['eve_log_sip'] = 'off'; }
		if ($_POST['eve_log_files'] == "on") { $natent['eve_log_files'] = 'on'; }else{ $natent['eve_log_files'] = 'off'; }
		if ($_POST['eve_log_ssh'] == "on") { $natent['eve_log_ssh'] = 'on'; }else{ $natent['eve_log_ssh'] = 'off'; }
		if ($_POST['eve_log_smtp'] == "on") { $natent['eve_log_smtp'] = 'on'; }else{ $natent['eve_log_smtp'] = 'off'; }
		if ($_POST['eve_log_stats'] == "on") { $natent['eve_log_stats'] = 'on'; }else{ $natent['eve_log_stats'] = 'off'; }
		if ($_POST['eve_log_flow'] == "on") { $natent['eve_log_flow'] = 'on'; }else{ $natent['eve_log_flow'] = 'off'; }
		if ($_POST['eve_log_netflow'] == "on") { $natent['eve_log_netflow'] = 'on'; }else{ $natent['eve_log_netflow'] = 'off'; }
		if ($_POST['eve_log_snmp'] == "on") { $natent['eve_log_snmp'] = 'on'; }else{ $natent['eve_log_snmp'] = 'off'; }
		if ($_POST['eve_log_mqtt'] == "on") { $natent['eve_log_mqtt'] = 'on'; }else{ $natent['eve_log_mqtt'] = 'off'; }
		if ($_POST['eve_log_ftp'] == "on") { $natent['eve_log_ftp'] = 'on'; }else{ $natent['eve_log_ftp'] = 'off'; }
		if ($_POST['eve_log_http2'] == "on") { $natent['eve_log_http2'] = 'on'; }else{ $natent['eve_log_http2'] = 'off'; }
		if ($_POST['eve_log_rfb'] == "on") { $natent['eve_log_rfb'] = 'on'; }else{ $natent['eve_log_rfb'] = 'off'; }
		if ($_POST['eve_log_stats_totals'] == "on") { $natent['eve_log_stats_totals'] = 'on'; }else{ $natent['eve_log_stats_totals'] = 'off'; }
		if ($_POST['eve_log_stats_deltas'] == "on") { $natent['eve_log_stats_deltas'] = 'on'; }else{ $natent['eve_log_stats_deltas'] = 'off'; }
		if ($_POST['eve_log_stats_threads'] == "on") { $natent['eve_log_stats_threads'] = 'on'; }else{ $natent['eve_log_stats_threads'] = 'off'; }
		if ($_POST['eve_log_http_extended'] == "on") { $natent['eve_log_http_extended'] = 'on'; }else{ $natent['eve_log_http_extended'] = 'off'; }
		if ($_POST['eve_log_tls_extended'] == "on") { $natent['eve_log_tls_extended'] = 'on'; }else{ $natent['eve_log_tls_extended'] = 'off'; }
		if ($_POST['eve_log_dhcp_extended'] == "on") { $natent['eve_log_dhcp_extended'] = 'on'; }else{ $natent['eve_log_dhcp_extended'] = 'off'; }
		if ($_POST['eve_log_smtp_extended'] == "on") { $natent['eve_log_smtp_extended'] = 'on'; }else{ $natent['eve_log_smtp_extended'] = 'off'; }
		if ($_POST['eve_log_http_extended_headers']) { $natent['eve_log_http_extended_headers'] = implode(", ",$_POST['eve_log_http_extended_headers']); }else{ $natent['eve_log_http_extended_headers'] = ""; }
		if ($_POST['eve_log_smtp_extended_fields']) { $natent['eve_log_smtp_extended_fields'] = implode(", ",$_POST['eve_log_smtp_extended_fields']); }else{ $natent['eve_log_smtp_extended_fields'] = ""; }
		if ($_POST['eve_log_tls_extended_fields']) { $natent['eve_log_tls_extended_fields'] = implode(", ",$_POST['eve_log_tls_extended_fields']); }else{ $natent['eve_log_tls_extended_fields'] = ""; }

		if ($_POST['eve_log_files_magic'] == "on") { $natent['eve_log_files_magic'] = 'on'; }else{ $natent['eve_log_files_magic'] = 'off'; }
		if ($_POST['eve_log_files_hash']) { $natent['eve_log_files_hash'] = $_POST['eve_log_files_hash']; }else{ $natent['eve_log_files_hash'] = 'none'; }
		if ($_POST['eve_log_drop'] == "on") { $natent['eve_log_drop'] = 'on'; }else{ $natent['eve_log_drop'] = 'off'; }
		if ($_POST['delayed_detect'] == "on") { $natent['delayed_detect'] = 'on'; }else{ $natent['delayed_detect'] = 'off'; }
		if ($_POST['intf_promisc_mode'] == "on") { $natent['intf_promisc_mode'] = 'on'; }else{ $natent['intf_promisc_mode'] = 'off'; }
		if ($_POST['configpassthru']) $natent['configpassthru'] = base64_encode(str_replace("\r\n", "\n", $_POST['configpassthru'])); else unset($natent['configpassthru']);

		if ($_POST['eve_redis_server']) $natent['eve_redis_server'] = $_POST['eve_redis_server'];
		if ($_POST['eve_redis_port']) $natent['eve_redis_port'] = $_POST['eve_redis_port'];
		if ($_POST['eve_redis_mode']) $natent['eve_redis_mode'] = $_POST['eve_redis_mode'];
		if ($_POST['eve_redis_key']) $natent['eve_redis_key'] = $_POST['eve_redis_key'];

		// Check if EVE OUTPUT TYPE is 'syslog' and auto-enable Suricata syslog output if true.
		if ($natent['eve_output_type'] == "syslog" && $natent['alertsystemlog'] == "off") {
			$natent['alertsystemlog'] = "on";
			$savemsg1 = gettext("EVE Output to syslog requires Suricata alerts to be copied to the system log, so 'Send Alerts to System Log' has been auto-enabled.");
		}

		// Check if Inline IPS mode is enabled. Auto-enable 'Live Rule Swap' and display a message
		// about potential incompatibilities with Netmap and some NIC hardware drivers.
		if ($natent['ips_mode'] == "ips_mode_inline") {
			$savemsg2 = gettext("Inline IPS Mode is selected. Live Rule Swap will be automatically enabled to prevent netmap interfaces from cycling offline/online during future rules updates. " .
								"For better performance with Inline IPS Mode operation, consider changing the runmode setting to workers. " .
								"Please note that not all hardware NIC drivers support Netmap operation- which is required for Inline IPS Mode. If problems are experienced, switch to Legacy Mode instead.");
			config_set_path('installedpackages/suricata/config/0/live_swap_updates', "on");
		}

		$if_real = get_real_interface($natent['interface']);
		if (isset($id) && $a_rule[$id] && $action == '') {
			// See if moving an existing Suricata instance to another physical interface
			if ($natent['interface'] != $a_rule[$id]['interface']) {
				$oif_real = get_real_interface($a_rule[$id]['interface']);
				if (suricata_is_running($a_rule[$id]['uuid'], $oif_real)) {
					suricata_stop($a_rule[$id], $oif_real);
					$suricata_start = true;
				}
				else
					$suricata_start = false;
				@rename("{$suricatalogdir}suricata_{$oif_real}{$a_rule[$id]['uuid']}", "{$suricatalogdir}suricata_{$if_real}{$a_rule[$id]['uuid']}");
				@rename("{$suricatadir}suricata_{$a_rule[$id]['uuid']}_{$oif_real}", "{$suricatadir}suricata_{$a_rule[$id]['uuid']}_{$if_real}");
			}
			$a_rule[$id] = $natent;
		}
		elseif (strcasecmp($action, 'dup') == 0) {
			// Duplicating an existing interface to a new interface, so set flag to build new rules
			$rebuild_rules = true;

			// Duplicating an interface, so need to generate a new UUID for the cloned interface
			$natent['uuid'] = suricata_generate_id();

			// Add the new duplicated interface configuration to the [rule] array in config
			$a_rule[] = $natent;
		}
		else {
			// Adding new interface, so set interface configuration parameter defaults
			$natent['ip_max_frags'] = "65535";
			$natent['ip_frag_timeout'] = "60";
			$natent['frag_memcap'] = '33554432';
			$natent['defrag_memcap_policy'] = 'ignore';
			$natent['ip_max_trackers'] = '65535';
			$natent['frag_hash_size'] = '65536';

			$natent['flow_memcap'] = '134217728';
			$natent['flow_memcap_policy'] = 'ignore';
			$natent['flow_prealloc'] = '10000';
			$natent['flow_hash_size'] = '65536';
			$natent['flow_emerg_recovery'] = '30';
			$natent['flow_prune'] = '5';

			$natent['flow_tcp_new_timeout'] = '60';
			$natent['flow_tcp_established_timeout'] = '3600';
			$natent['flow_tcp_closed_timeout'] = '120';
			$natent['flow_tcp_emerg_new_timeout'] = '10';
			$natent['flow_tcp_emerg_established_timeout'] = '300';
			$natent['flow_tcp_emerg_closed_timeout'] = '20';

			$natent['flow_udp_new_timeout'] = '30';
			$natent['flow_udp_established_timeout'] = '300';
			$natent['flow_udp_emerg_new_timeout'] = '10';
			$natent['flow_udp_emerg_established_timeout'] = '100';

			$natent['flow_icmp_new_timeout'] = '30';
			$natent['flow_icmp_established_timeout'] = '300';
			$natent['flow_icmp_emerg_new_timeout'] = '10';
			$natent['flow_icmp_emerg_established_timeout'] = '100';

			$natent['stream_memcap'] = '268435456';
			$natent['stream_prealloc_sessions'] = '32768';
			$natent['reassembly_memcap'] = '131217728';
			$natent['reassembly_depth'] = '1048576';
			$natent['reassembly_to_server_chunk'] = '2560';
			$natent['reassembly_to_client_chunk'] = '2560';
			$natent['max_synack_queued'] = '5';
			$natent['enable_midstream_sessions'] = 'off';
			$natent['stream_memcap_policy'] = 'ignore';
			$natent['reassembly_memcap_policy'] = 'ignore';
			$natent['midstream_policy'] = 'ignore';
			$natent['stream_checksum_validation'] = "off";
			$natent['enable_async_sessions'] = 'off';
			$natent['stream_bypass'] = "off";
			$natent['stream_drop_invalid'] = "off";
			$natent['delayed_detect'] = 'off';
			$natent['intf_promisc_mode'] = 'on';
			$natent['intf_snaplen'] = '1518';
			$natent['mpm_algo'] = "auto";
			$natent['spm_algo'] = "auto";

			$natent['app_layer_error_policy'] = "ignore";
			$natent['asn1_max_frames'] = '256';
			$natent['bittorrent_parser'] = "yes";
			$natent['dcerpc_parser'] = "yes";
			$natent['dhcp_parser'] = "yes";
			$natent['dns_global_memcap'] = "16777216";
			$natent['dns_state_memcap'] = "524288";
			$natent['dns_request_flood_limit'] = "500";
			$natent['dns_parser_udp'] = "yes";
			$natent['dns_parser_tcp'] = "yes";
			$natent['dns_parser_udp_ports'] = "53";
			$natent['dns_parser_tcp_ports'] = "53";
			$natent['enip_parser'] = "yes";
			$natent['ftp_parser'] = "yes";
			$natent['ftp_data_parser'] = "on";
			$natent['http_parser'] = "yes";
			$natent['http_parser_memcap'] = "67108864";
			$natent['http2_parser'] = "yes";
			$natent['ikev2_parser'] = "yes";
			$natent['imap_parser'] = "detection-only";
			$natent['krb5_parser'] = "yes";
			$natent['mqtt_parser'] = "yes";
			$natent['msn_parser'] = "detection-only";
			$natent['nfs_parser'] = "yes";
			$natent['ntp_parser'] = "yes";
			$natent['pgsql_parser'] = "no";
			$natent['quic_parser'] = "yes";
			$natent['rdp_parser'] = "yes";
			$natent['rfb_parser'] = "yes";
			$natent['sip_parser'] = "yes";
			$natent['smb_parser'] = "yes";
			$natent['smtp_parser'] = "yes";
			$natent['smtp_parser_decode_mime'] = "off";
			$natent['smtp_parser_decode_base64'] = "on";
			$natent['smtp_parser_decode_quoted_printable'] = "on";
			$natent['smtp_parser_extract_urls'] = "on";
			$natent['smtp_parser_compute_body_md5'] = "off";
			$natent['snmp_parser'] = "yes";
			$natent['ssh_parser'] = "yes";
			$natent['telnet_parser'] = "yes";
			$natent['tftp_parser'] = "yes";
			$natent['tls_parser'] = "yes";
			$natent['tls_detect_ports'] = "443";
			$natent['tls_encrypt_handling'] = "default";
			$natent['tls_ja3_fingerprint'] = "off";

			$natent['enable_iprep'] = "off";
			$natent['host_memcap'] = "33554432";
			$natent['host_hash_size'] = "4096";
			$natent['host_prealloc'] = "1000";

			$default = array( "name" => "default", "bind_to" => "all", "policy" => "bsd" );
			array_init_path($natent, 'host_os_policy/item');
			$natent['host_os_policy']['item'][] = $default;

			$default = array( "name" => "default", "bind_to" => "all", "personality" => "IDS",
					  "request-body-limit" => 4096, "response-body-limit" => 4096,
					  "double-decode-path" => "no", "double-decode-query" => "no",
					  "uri-include-all" => "no", "meta-field-limit" => 18432 );
			array_init_path($natent, 'libhtp_policy/item');
			$natent['libhtp_policy']['item'][] = $default;

			// Enable the basic default rules for the interface
			$natent['rulesets'] = implode("||", SURICATA_DEFAULT_RULES);

			// Adding a new interface, so set flag to build new rules
			$rebuild_rules = true;

			// Add the new interface configuration to the [rule] array in config
			$a_rule[] = $natent;
		}

		// If Suricata is disabled on this interface, stop any running instance
		if ($natent['enable'] != 'on')
			suricata_stop($natent, $if_real);

		// Save configuration changes
		config_set_path('installedpackages/suricata/rule', $a_rule);
		write_config("Suricata pkg: modified interface configuration for " . convert_friendly_interface_to_friendly_descr($natent['interface']));

		// Update suricata.conf and suricata.sh files for this interface
		sync_suricata_package_config();

		// Refresh page fields with just-saved values
		$pconfig = $natent;
		$new_interface = false;
	} else {
		// Restore the existing parameters so the user can fix the detected error
		$pconfig = $_POST;
		if ($_POST['eve_log_http_extended_headers']) {
			$pconfig['eve_log_http_extended_headers'] = implode(", ",$_POST['eve_log_http_extended_headers']);
		} else {
			$pconfig['eve_log_http_extended_headers'] = "";
		}
		if ($_POST['eve_log_smtp_extended_fields']) {
			$pconfig['eve_log_smtp_extended_fields'] = implode(", ",$_POST['eve_log_smtp_extended_fields']);
		} else {
			$pconfig['eve_log_smtp_extended_fields'] = "";
		}
		if ($_POST['eve_log_tls_extended_fields']) {
			$pconfig['eve_log_tls_extended_fields'] = implode(", ",$_POST['eve_log_tls_extended_fields']);
		} else {
			$pconfig['eve_log_tls_extended_fields'] = "";
		}
	}
}

/**************************************************************/
/* This function builds an array of lists based on the $lists */
/* parameter. Valid list types are 'suppress' and 'passlist'  */
/*                                                            */
/* Returns: array of list names matching specified type       */
/**************************************************************/
function suricata_get_config_lists($lists) {

	$list = array();

	foreach (config_get_path("installedpackages/suricata/{$lists}/item", []) as $value) {
		$ilistname = $value['name'];
		$list[$ilistname] = htmlspecialchars($ilistname);
	}

	return(['default' => 'default'] + $list);
}

$if_crumb = $if_friendly ? $if_friendly : gettext('Interface');
$pglinks = array("", "/suricata/suricata_overview.php", "/suricata/suricata_interfaces.php", "", "@self");
$pgtitle = array(gettext("Services"), gettext("Suricata"), gettext("Interfaces"), htmlspecialchars($if_crumb), $new_interface ? gettext("Add interface") : gettext("Edit interface"));
if ($new_interface) {
	$pglinks = array("", "/suricata/suricata_overview.php", "/suricata/suricata_interfaces.php", "@self");
	$pgtitle = array(gettext("Services"), gettext("Suricata"), gettext("Interfaces"), gettext("Add interface"));
}
include_once("head.inc");

/* Display Alert message */
if ($input_errors) {
	print_input_errors($input_errors);
}
if ($savemsg1) {
	print_info_box($savemsg1);
}
if ($savemsg2) {
	print_info_box($savemsg2);
}

suricata_display_primary_navigation('interfaces');

// Check that CSO, TSO and LRO are all disabled for proper operation
$suricata_realif = get_real_interface($pconfig['interface'] ?? '');
if (!empty($suricata_realif) && function_exists('nic_settings_effective')) {
	$suricata_nic = nic_settings_effective($suricata_realif);
	$suricata_offload_active = ($suricata_nic['checksum'] !== 'off' || $suricata_nic['tso'] !== 'off' || $suricata_nic['lro'] !== 'off');
} else {
	$suricata_offload_active = (!config_path_enabled('system', 'disablechecksumoffloading') || !config_path_enabled('system', 'disablesegmentationoffloading') || !config_path_enabled('system', 'disablelargereceiveoffloading'));
}

if ($pconfig['enable'] == 'on' && $suricata_offload_active) {
	print_info_box(gettext('Suricata needs hardware checksum, TCP segmentation and large receive offloading disabled on this interface. One or more of them is still enabled.') .
		' <a href="/interfaces_nic_settings.php">' . gettext('Open NIC settings') . '</a>', 'warning');
}

suricata_display_interface_tabs($id, 'settings', $new_interface);

/* ------------------------------------------------------------ summary card */
$sum = (!$new_interface && isset($a_rule[$id])) ? $a_rule[$id] : $pconfig;
$sum_real = get_real_interface($sum['interface'] ?? '');
$sum_blocking = (($sum['blockoffenders'] ?? '') == 'on');
if ($sum_blocking && ($sum['ips_mode'] ?? '') == 'ips_mode_inline') {
	$sum_mode = gettext('IPS inline');
} elseif ($sum_blocking) {
	$sum_mode = gettext('IPS legacy');
} else {
	$sum_mode = gettext('IDS (alerts only)');
}
$sum_eve = gettext('Off');
if (($sum['enable_eve_log'] ?? '') == 'on') {
	$eve_types = array("regular" => gettext("File"), "syslog" => gettext("Syslog"), "redis" => gettext("Redis"), "unix_dgram" => gettext("UNIX datagram socket"), "unix_stream" => gettext("UNIX stream socket"));
	$sum_eve = $eve_types[$sum['eve_output_type'] ?? 'regular'] ?? gettext('File');
}
$sum_badges = [];
if ($new_interface) {
	$sum_badges[] = fs_badge('pending', gettext('Not saved yet'));
} elseif (($sum['enable'] ?? '') != 'on') {
	$sum_badges[] = fs_badge('disabled');
} else {
	$sum_badges[] = fs_badge('enabled');
	$sum_badges[] = ($sum_real != '' && suricata_is_running($sum['uuid'], $sum_real)) ? fs_badge('up', gettext('Running')) : fs_badge('down', gettext('Stopped'));
}
$sum_sources = suricata_ruleset_summary($sum);
$sum_facts = [
	[gettext('Interface'), ($sum_real != '') ? convert_friendly_interface_to_friendly_descr($sum['interface']) . " ({$sum_real})" : '', 'empty' => gettext('Not assigned')],
	[gettext('Mode'), $sum_mode],
	[gettext('Home net'), $sum['homelistname'] ?? '', 'empty' => 'default'],
	[gettext('EVE JSON log'), $sum_eve],
];
if (!$new_interface) {
	$sum_facts[] = [gettext('Rule sets'), '', 'chips' => array_keys($sum_sources), 'empty' => gettext('None selected')];
}
fs_summary_card([
	'icon' => 'fa-shield-halved',
	'title' => $new_interface ? '' : ($sum['descr'] ?? ''),
	'placeholder' => gettext('New Suricata interface'),
	'subtitle' => $new_interface ? gettext('Save the settings before starting Suricata on this interface.') : '',
	'badges' => $sum_badges,
	'meta' => $new_interface ? '' : $sum_real,
	'label' => gettext('Interface summary'),
	'facts' => $sum_facts,
	'actions' => $new_interface ? [] : [[gettext('Alerts'), "/suricata/suricata_alerts.php?instance={$id}", 'fa-bell'], [gettext('Rules'), "/suricata/suricata_rules.php?id={$id}", 'fa-list-check']],
]);

$sec_state = COLLAPSIBLE | (!empty($input_errors) ? SEC_OPEN : SEC_CLOSED);
$syslog_facilities = array("auth" => "AUTH", "authpriv" => "AUTHPRIV", "daemon" => "DAEMON", "kern" => "KERN", "security" => "SECURITY",
	"syslog" => "SYSLOG", "user" => "USER", "local0" => "LOCAL0", "local1" => "LOCAL1", "local2" => "LOCAL2",
	"local3" => "LOCAL3", "local4" => "LOCAL4", "local5" => "LOCAL5", "local6" => "LOCAL6", "local7" => "LOCAL7");
$log_filetypes = array("regular" => "Regular", "unix_dgram" => "UNIX Datagram Socket", "unix_stream" => "UNIX Stream Socket");

// Checkbox shorthand: every field keeps its name, value and checked state.
$cb = function ($name, $title, $text, $on = 'on') use (&$pconfig) {
	return new Form_Checkbox($name, $title, $text, $pconfig[$name] == $on ? true : false, $on);
};
$view_btn = function ($name, $target) {
	$btn = new Form_Button($name, ' ' . 'View List', '#', 'fa-regular fa-file-lines');
	$btn->removeClass('btn-primary')->removeClass('btn-secondary')->addClass('btn-outline-secondary')->addClass('btn-sm')
	    ->setAttribute('data-bs-toggle', 'modal')->setAttribute('data-bs-target', $target);
	return $btn;
};

$form = new Form;

/* ------------------------------------------------------------------ general */
$section = new Form_Section('General', 'suri-general');
$section->addInput($cb('enable', 'Enable', 'Inspect traffic on this interface with Suricata'));
$section->addInput(new Form_Select(
	'interface',
	'*Interface',
	$pconfig['interface'],
	$interfaces
))->setHelp('The firewall interface this Suricata instance inspects.');
$section->addInput(new Form_Input(
	'descr',
	'Description',
	'text',
	$pconfig['descr']
))->setHelp('Defaults to the interface name.');
$form->add($section);

/* ----------------------------------------------------------------- networks */
$section = new Form_Section('Networks and lists', 'suri-networks');

$group = new Form_Group('Home net');
$group->add(new Form_Select(
	'homelistname',
	'Home Net',
	$pconfig['homelistname'],
	suricata_get_config_lists('passlist')
))->setHelp('Networks Suricata protects.');
$group->add($view_btn('btnHomeNet', '#homenet'));
$group->setHelp('The default adds local networks, WAN addresses, gateways, VPNs and virtual IPs. Use a pass list with an alias for a custom set.');
$section->add($group);

$group = new Form_Group('External net');
$group->add(new Form_Select(
	'externallistname',
	'External Net',
	$pconfig['externallistname'],
	suricata_get_config_lists('passlist')
))->setHelp('Networks outside the home net.');
$group->add($view_btn('btnExternalNet', '#externalnet'));
$group->setHelp('Most installations keep the default (everything that is not home net).');
$section->add($group);

$group = new Form_Group('Suppress list');
$group->add(new Form_Select(
	'suppresslistname',
	'Alert Suppression and Filtering',
	$pconfig['suppresslistname'],
	suricata_get_config_lists('suppress')
))->setHelp('Suppression and event filtering applied to alerts. "default" turns it off.');
$group->add($view_btn('btnSuppressList', '#suppresslist'));
$section->add($group);
$form->add($section);

/* ----------------------------------------------------------------- blocking */
$section = new Form_Section('Blocking', 'suri-blocking');
$section->addInput($cb('blockoffenders', 'Block offenders', 'Block hosts that trigger a Suricata alert'));

$group = new Form_Group('IPS mode');
$group->add(new Form_Select(
	'ips_mode',
	'IPS Mode',
	$pconfig['ips_mode'],
	array( "ips_mode_legacy" => "Legacy Mode", "ips_mode_inline" => "Inline Mode" )
))->setHelp('Legacy inspects copies of packets; Inline sits between the NIC and the network stack.');
$group->setHelp('Legacy mode blocks the offending host after the first matching packets have passed. Inline mode drops matching packets before they reach the host, ' .
	'but only works with NIC drivers that support netmap (' . implode(', ', $netmapifs) . '). Switch back to Legacy if Inline causes problems.');
$section->add($group);

$section->addInput(new Form_Input(
	'ips_netmap_threads',
	'Netmap threads',
	'text',
	$pconfig['ips_netmap_threads']
))->setHelp('"auto" (recommended) uses one thread per netmap queue. This NIC reports ' . suricata_get_supported_netmap_queues($if_real) . ' queue(s).');

$section->addInput($cb('blockoffenderskill', 'Kill states', 'Kill firewall states of a blocked IP (default)'));
$section->addInput(new Form_Select(
	'blockoffendersip',
	'Which IP to block',
	$pconfig['blockoffendersip'],
	array( 'src' => 'SRC', 'dst' => 'DST', 'both' => 'BOTH' )
))->setHelp('Address taken from the packet to block. BOTH is recommended.');
$section->addInput($cb('block_drops_only', 'Block on DROP only', 'Only block for rules with the DROP action (otherwise ALERT rules block too)'));

$group = new Form_Group('Pass list');
$group->addClass('passlist');
$list = suricata_get_config_lists('passlist');
$list['none'] = 'none';
$group->add(new Form_Select(
	'passlistname',
	'Pass List',
	$pconfig['passlistname'],
	$list
))->setHelp('Addresses on the pass list are never blocked. "none" disables it.');
$group->add($view_btn('btnPasslist', '#passlist'));
$group->setHelp('The default pass list adds gateways, DNS servers, local networks, the WAN address, VPNs and virtual IPs.');
$section->add($group);

$section->addInput($cb('passlist_debug_log', 'Pass list debug log', 'Log pass list processing to ' .
	$suricatalogdir . 'suricata_' . $if_real . $suricata_uuid . '/passlist_debug.log'));
$form->add($section);

// Inline IPS rule action warning, shown when Inline mode is selected
$modal = new Modal('Important Information About IPS Inline Mode Blocking', 'ips_warn_dlg', 'large', 'Close');
$modal->addInput(new Form_StaticText (
	null,
	'<span class="help-block">' .
	gettext('In Inline IPS mode a rule only blocks traffic when its action is DROP. The default rule action is ALERT, which logs but does not block.') .
	'<br/><br/>' .
	gettext('Use dropsid.conf on the SID management page to change the action of the rules that should block. ') .
	gettext('With Snort rules and an IPS policy selected on the Categories tab, rules the policy marks as DROP are changed automatically when "IPS Policy Mode" is set to "Policy".') .
	'</span>'
));
$form->add($modal);

/* ------------------------------------------------------------------ logging */
$section = new Form_Section('Alert logging', 'suri-logging');
$section->addInput($cb('alertsystemlog', 'Send alerts to system log', 'Copy alerts from this interface to the firewall system log'))
	->setHelp('syslog truncates exported messages to 480 bytes.');
$section->addInput(new Form_Select(
	'alertsystemlog_facility',
	'Log facility',
	$pconfig['alertsystemlog_facility'],
	$syslog_facilities
))->setHelp('Default is LOCAL1.');
$section->addInput(new Form_Select(
	'alertsystemlog_priority',
	'Log priority',
	$pconfig['alertsystemlog_priority'],
	array( "emergency" => "EMERG", "critical" => "CRIT", "alert" => "ALERT", "error" => "ERR", "warning" => "WARNING", "notice" => "NOTICE", "info" => "INFO", "debug" => "DEBUG" )
))->setHelp('Default is NOTICE.');
$section->addInput($cb('enable_verbose_logging', 'Verbose logging', 'Write extra start-up and shutdown details to suricata.log'));
$form->add($section);

/* ---------------------------------------------------------------------- EVE */
$section = new Form_Section('EVE JSON output', 'suri-eve', $sec_state);
$section->addInput($cb('enable_eve_log', 'EVE JSON log', 'Write selected events as JSON to a file, syslog, Redis or a socket'));
$section->addInput(new Form_Select(
	'eve_output_type',
	'EVE output type',
	$pconfig['eve_output_type'],
	array("regular" => "FILE", "syslog" => "SYSLOG", "redis"=>"Redis", "unix_dgram" => "UNIX Datagram Socket", "unix_stream" => "UNIX Stream Socket")
))->setHelp('FILE is recommended. The UNIX socket must be created by its consumer.');
$section->addInput(new Form_Input(
	'eve_output_socket',
	'EVE output socket name',
	'text',
	base64_decode($pconfig['eve_output_socket'])
))->setHelp('Existing UNIX socket to write to. Suricata does not create it.');
$section->addInput(new Form_Select(
	'eve_systemlog_facility',
	'EVE syslog facility',
	$pconfig['eve_systemlog_facility'],
	$syslog_facilities
));
$section->addInput(new Form_Select(
	'eve_systemlog_priority',
	'EVE syslog priority',
	$pconfig['eve_systemlog_priority'],
	array( "emerg" => "EMERG", "crit" => "CRIT", "alert" => "ALERT", "err" => "ERR", "warning" => "WARNING", "notice" => "NOTICE", "info" => "INFO" )
));

$group = new Form_Group('EVE Redis server');
$group->add(new Form_Input(
	'eve_redis_server',
	'Redis Server',
	'text',
	$pconfig['eve_redis_server']
))->setHelp('Redis server IP');
$group->add(new Form_Input(
	'eve_redis_port',
	'Port',
	'text',
	$pconfig['eve_redis_port']
))->setHelp('Port');
$section->add($group)->addClass('eve_redis_connection');
$section->addInput(new Form_Select(
	'eve_redis_mode',
	'EVE Redis mode',
	$pconfig['eve_redis_mode'],
	array("list"=>"List (LPUSH)","rpush"=>"List (RPUSH)","channel"=>"Channel(PUBLISH)")
));
$section->addInput(new Form_Input(
	'eve_redis_key',
	'EVE Redis key',
	'text',
	$pconfig['eve_redis_key']
))->setHelp('Alphanumeric key name.');

$section->addInput($cb('eve_log_alerts_xff', 'HTTP X-Forwarded-For', 'Log X-Forwarded-For addresses'));
$section->addInput($cb('eve_log_ethernet', 'Ethernet header', 'Log the Ethernet header (MAC addresses) when available', 'yes'));
$section->addInput(new Form_Select(
	'eve_log_alerts_xff_mode',
	'XFF mode',
	$pconfig['eve_log_alerts_xff_mode'],
	array( "extra-data" => "extra-data", "overwrite" => "overwrite" )
))->setHelp('extra-data adds a field; overwrite replaces the source or destination IP. Default is extra-data.');
$section->addInput(new Form_Select(
	'eve_log_alerts_xff_deployment',
	'XFF deployment',
	$pconfig['eve_log_alerts_xff_deployment'],
	array( "reverse" => "reverse", "forward" => "forward" )
))->setHelp('reverse uses the last address in the header, forward the first. Default is reverse.');
$section->addInput(new Form_Input(
	'eve_log_alerts_xff_header',
	'XFF header',
	'text',
	$pconfig['eve_log_alerts_xff_header']
))->setHelp('Header that carries the client address. Default is X-Forwarded-For.');

$section->addInput($cb('eve_log_alerts', 'Log alerts', 'Write alerts to EVE'));
$section->addInput(new Form_Select(
	'eve_log_alerts_payload',
	'Alert payload format',
	$pconfig['eve_log_alerts_payload'],
	array("off"=>"NO","only-base64"=>"BASE64","only-printable"=>"PRINTABLE","on"=>"BOTH")
))->setHelp('Log the payload with alerts as Base64, printable text (lossy) or both.');

$group = new Form_Group('Alert details');
$group->add($cb('eve_log_alerts_packet', 'Alert Payloads', 'Packet dump'));
$group->add($cb('eve_log_alerts_http', 'Alert Payloads', 'HTTP data'));
$group->add($cb('eve_log_alerts_metadata', 'App Layer Metadata', 'App-layer metadata'));
$group->add($cb('eve_log_alerts_verdict', 'Engine Verdict', 'Engine verdict'));
$group->add($cb('eve_log_alerts_tagged', 'Tagged Packets', 'Tagged packets'));
$section->add($group)->addClass('eve_log_alerts_details');

$section->addInput($cb('eve_log_drops', 'Log drops', 'Write drops to EVE'));
$group = new Form_Group('Drop details');
$group->add($cb('eve_log_alert_drops', 'Alerts', 'Alerts that caused drops'));
$group->add($cb('eve_log_drops_verdict', 'Engine Verdicts', 'Engine verdict'));
$group->add(new Form_Select(
	'eve_log_drops_flows',
	'EVE Drop Log Flows',
	$pconfig['eve_log_drops_flows'],
	array("all"=>"All","start"=>"Start")
))->setHelp('"Start" logs one drop per flow direction, "All" every dropped packet.');
$section->add($group)->addClass('eve_log_drops_options');

$section->addInput($cb('eve_log_anomaly', 'Log anomalies', 'Log truncated or invalid packets (can slow processing on networks with many anomalies)'));
$group = new Form_Group('Anomaly details');
$group->add($cb('eve_log_anomaly_type_decode', 'Decode Anomaly', 'Decode'));
$group->add($cb('eve_log_anomaly_type_stream', 'Stream Anomaly', 'Stream'));
$group->add($cb('eve_log_anomaly_type_applayer', 'App Layer Anomaly', 'App layer'));
$group->add($cb('eve_log_anomaly_packethdr', 'Anomaly Packet Hdr', 'Packet header'));
$section->add($group)->addClass('eve_log_anomaly_details');

$group = new Form_Group('Logged traffic');
foreach (['eve_log_bittorrent' => 'BitTorrent', 'eve_log_dns' => 'DNS', 'eve_log_ftp' => 'FTP', 'eve_log_http' => 'HTTP',
    'eve_log_http2' => 'HTTP2', 'eve_log_ikev2' => 'IKE', 'eve_log_krb5' => 'Kerberos', 'eve_log_nfs' => 'NFS',
    'eve_log_pgsql' => 'PostgreSQL'] as $name => $text) {
	$group->add($cb($name, $text, $text));
}
$section->add($group)->addClass('eve_log_info');
$group = new Form_Group(false);
foreach (['eve_log_quic' => 'QUICv1', 'eve_log_rdp' => 'RDP', 'eve_log_rfb' => 'RFB', 'eve_log_sip' => 'SIP',
    'eve_log_smb' => 'SMB', 'eve_log_smtp' => 'SMTP', 'eve_log_tftp' => 'TFTP'] as $name => $text) {
	$group->add($cb($name, $text, $text));
}
$group->setHelp('Protocols to log.');
$section->add($group)->addClass('eve_log_info');

$group = new Form_Group('Logged info');
foreach (['eve_log_dhcp' => 'DHCP Messages', 'eve_log_drop' => 'Dropped Traffic', 'eve_log_flow' => 'Flows', 'eve_log_mqtt' => 'MQTT',
    'eve_log_netflow' => 'Net Flows', 'eve_log_stats' => 'Perf Stats', 'eve_log_snmp' => 'SNMP'] as $name => $text) {
	$group->add($cb($name, $text, $text));
}
$section->add($group)->addClass('eve_log_info');
$group = new Form_Group(false);
foreach (['eve_log_ssh' => 'SSH Handshakes', 'eve_log_tls' => 'TLS Handshakes', 'eve_log_files' => 'Tracked Files'] as $name => $text) {
	$group->add($cb($name, $text, $text));
}
$group->setHelp('Other information to log.');
$section->add($group)->addClass('eve_log_info');

$group = new Form_Group('Extended info');
$group->add($cb('eve_log_http_extended', 'Extended HTTP Info', 'HTTP'));
$group->add($cb('eve_log_tls_extended', 'Extended TLS Info', 'TLS'));
$group->add($cb('eve_log_dhcp_extended', 'Extended DHCP Info', 'DHCP'));
// The SMTP box has always shown the TLS setting's state; kept as is.
$group->add(new Form_Checkbox('eve_log_smtp_extended', 'Extended SMTP Info', 'SMTP', $pconfig['eve_log_tls_extended'] == 'on' ? true : false, 'on'));
$group->setHelp('Events that get extended information.');
$section->add($group)->addClass('eve_log_info');

$section->addInput(new Form_Select(
	'eve_log_http_extended_headers',
	'Extended HTTP headers',
	explode(", ",$pconfig['eve_log_http_extended_headers']),
	array("accept"=>"accept","accept-charset"=>"accept-charset","accept-datetime"=>"accept-datetime","accept-encoding"=>"accept-encoding","accept-language"=>"accept-language","accept-range"=>"accept-range","age"=>"age","allow"=>"allow","authorization"=>"authorization","cache-control"=>"cache-control","connection"=>"connection","content-encoding"=>"content-encoding","content-language"=>"content-language","content-length"=>"content-length","content-location"=>"content-location","content-md5"=>"content-md5","content-range"=>"content-range","content-type"=>"content-type","cookie"=>"cookie","date"=>"date","dnt"=>"dnt","etags"=>"etags","from"=>"from","last-modified"=>"last-modified","link"=>"link","location"=>"location","max-forwards"=>"max-forwards","origin"=>"origin","pragma"=>"pragma","proxy-authenticate"=>"proxy-authenticate","proxy-authorization"=>"proxy-authorization","range"=>"range","referrer"=>"referrer","refresh"=>"refresh","retry-after"=>"retry-after","server"=>"server","set-cookie"=>"set-cookie","te"=>"te","trailer"=>"trailer","transfer-encoding"=>"transfer-encoding","upgrade"=>"upgrade","vary"=>"vary","via"=>"via","warning"=>"warning","www-authenticate"=>"www-authenticate","x-authenticated-user"=>"x-authenticated-user","x-flash-version"=>"x-flash-version","x-forwarded-proto"=>"x-forwarded-proto","x-requested-with"=>"x-requested-with"),
	true
))->setHelp('Ctrl+click to select several.');
$section->addInput(new Form_Select(
	'eve_log_smtp_extended_fields',
	'Extended SMTP fields',
	explode(", ",$pconfig['eve_log_smtp_extended_fields']),
	array("bcc"=>"bcc","content-md5"=>"content-md5","date"=>"date","importance"=>"importance","in-reply-to"=>"in-reply-to","message-id"=>"message-id","organization"=>"organization","priority"=>"priority","received"=>"received","references"=>"references","reply-to"=>"reply-to","sensitivity"=>"sensitivity","subject"=>"subject","user-agent"=>"user-agent","x-mailer"=>"x-mailer","x-originating-ip"=>"x-originating-ip"),
	true
))->setHelp('Ctrl+click to select several.');
$section->addInput(new Form_Select(
	'eve_log_tls_extended_fields',
	'Extended TLS fields',
	explode(", ",$pconfig['eve_log_tls_extended_fields']),
	array("subject"=>"Subject","issuer"=>"Issuer","session_resumed"=>"Session Resumed","serial"=>"Serial","fingerprint"=>"Fingerprint","sni"=>"SNI (Server Name Indication)","version"=>"Version","not_before"=>"Not Before","not_after"=>"Not After","certifcate"=>"Certificate","chain"=>"Chain","ja3"=>"JA3","ja3s"=>"JA3S"),
	true
))->setHelp('Ctrl+click to select several.');

$section->addInput($cb('eve_log_files_magic', 'Tracked files magic', 'Log file magic for all tracked files'));
$section->addInput(new Form_Select(
	'eve_log_files_hash',
	'Tracked files checksum',
	$pconfig['eve_log_files_hash'],
	array("none" => "None", "md5" => "MD5", "sha1" => "SHA1", "sha256" => "SHA256")
))->setHelp('Checksum calculated for every tracked file. Default is None.');

$group = new Form_Group('Logged stats');
$group->add($cb('eve_log_stats_totals', 'Stats total', 'Totals'));
$group->add($cb('eve_log_stats_deltas', 'Stats deltas', 'Deltas'));
$group->add($cb('eve_log_stats_threads', 'Stats per thread', 'Per thread'));
$section->add($group)->addClass('eve_log_stats_details');
$form->add($section);

/* ------------------------------------------------------------ HTTP and TLS */
$section = new Form_Section('HTTP and TLS logs', 'suri-applogs', $sec_state);
$section->addInput($cb('enable_http_log', 'HTTP log', 'Log decoded HTTP traffic (default)'));
$section->addInput(new Form_Select(
	'http_log_filetype',
	'HTTP log file type',
	$pconfig['http_log_filetype'],
	$log_filetypes
))->setHelp('Regular file, or an existing UNIX socket.');
$section->addInput(new Form_Input(
	'http_log_socket',
	'HTTP log socket name',
	'text',
	base64_decode($pconfig['http_log_socket'])
))->setHelp('Existing UNIX socket to write to. Suricata does not create it.');
$section->addInput($cb('append_http_log', 'Append HTTP log', 'Append instead of clearing the log on restart (default)'));
$section->addInput($cb('http_log_extended', 'Extended HTTP info', 'Log extended HTTP information (default)'));

$section->addInput($cb('enable_tls_log', 'TLS log', 'Log TLS handshakes'));
$section->addInput(new Form_Select(
	'tls_log_filetype',
	'TLS log file type',
	$pconfig['tls_log_filetype'],
	$log_filetypes
))->setHelp('Regular file, or an existing UNIX socket.');
$section->addInput(new Form_Input(
	'tls_log_socket',
	'TLS log socket name',
	'text',
	base64_decode($pconfig['tls_log_socket'])
))->setHelp('Existing UNIX socket to write to. Suricata does not create it.');
$section->addInput($cb('append_tls_log', 'Append TLS log', 'Append instead of clearing the log on restart (default)'));
$section->addInput($cb('tls_session_resumption', 'TLS session resumption', 'Log transactions resumed with a session ID'));
$section->addInput($cb('enable_tls_store', 'TLS store', 'Store TLS certificates'));
$section->addInput($cb('tls_log_extended', 'Extended TLS info', 'Log extended TLS information such as the fingerprint (default)'));
$form->add($section);

/* --------------------------------------------------- file store and capture */
$section = new Form_Section('File store and packet capture', 'suri-capture', $sec_state);
$section->addInput($cb('enable_file_store', 'File store', 'Extract and store files from application-layer streams'))
	->setHelp('Uses a lot of disk space on a busy network.');
$section->addInput(new Form_Input(
	'file_store_logdir',
	'File store directory',
	'text',
	base64_decode($pconfig['file_store_logdir'])
))->setHelp('Blank uses a "filestore" folder in the interface log directory under ' . SURICATALOGDIR . '.');
$section->addInput($cb('enable_pcap_log', 'Packet log', 'Log packets in pcap format'))
	->setHelp('Can use a lot of disk space. Choose what to capture below.');
$section->addInput(new Form_Select(
	'pcap_log_conditional',
	'Capture',
	$pconfig['pcap_log_conditional'],
	array("alerts" => "ALERTS", "all" => "ALL", "tag"=>"TAG")
))->setHelp('ALERTS: alerted packets and flows (default). ALL: every packet. TAG: flows tagged with the "tag" keyword.');
$section->addInput($cb('pcap_use_stream_depth', 'Use stream depth', 'Ignore packets after the stream inspection depth is reached'));
$section->addInput($cb('pcap_honor_pass_rules', 'Honor pass rules', 'Stop capturing flows matched by a pass rule'));
$section->addInput(new Form_Input(
	'max_pcap_log_size',
	'Max packet log file size',
	'text',
	$pconfig['max_pcap_log_size']
))->setHelp('MB per file before it rotates. Default is 32.');
$section->addInput(new Form_Input(
	'max_pcap_log_files',
	'Max packet log files',
	'text',
	$pconfig['max_pcap_log_files']
))->setHelp('Files kept before the oldest is overwritten. Default is 100.');
$form->add($section);

/* --------------------------------------------------------------- statistics */
$section = new Form_Section('Statistics', 'suri-stats', $sec_state);
$section->addInput($cb('enable_stats_collection', 'Stats collection', 'Collect performance statistics for this interface'));
$section->addInput(new Form_Input(
	'stats_upd_interval',
	'Update interval',
	'text',
	$pconfig['stats_upd_interval']
))->setHelp('Seconds. Default is 10.');
$section->addInput($cb('enable_stats_log', 'Stats log', 'Write statistics to a CSV log file'));
$section->addInput($cb('append_stats_log', 'Append stats log', 'Append instead of clearing the log on restart'));
$section->addInput($cb('enable_telegraf_stats', 'Telegraf stats', 'Send statistics to Telegraf over a UNIX socket'));
$section->addInput(new Form_Input(
	'suricata_telegraf_unix_socket_name',
	'Telegraf UNIX socket',
	'text',
	base64_decode($pconfig['suricata_telegraf_unix_socket_name'])
))->setHelp('Full socket path as configured in the Telegraf inputs.suricata plugin. Telegraf creates the socket.');
$form->add($section);

/* -------------------------------------------------------------- performance */
$section = new Form_Section('Performance and detection engine', 'suri-performance', $sec_state);
$section->addInput(new Form_Select(
	'runmode',
	'Run mode',
	$pconfig['runmode'],
	array('autofp' => 'AutoFP', 'workers' => 'Workers', 'single' => 'Single')
))->setHelp('AutoFP (default) suits IDS and Legacy blocking. Workers performs best with Inline IPS. Single is for testing only.');
$section->addInput(new Form_Select(
	'autofp_scheduler',
	'AutoFP scheduler',
	$pconfig['autofp_scheduler'],
	array('hash' => 'Hash', 'ippair' => 'IP Pair')
))->setHelp('Flow load balancing: Hash uses the 5–7 tuple, IP Pair only the addresses.');
$section->addInput(new Form_Input(
	'max_pending_packets',
	'Max pending packets',
	'text',
	$pconfig['max_pending_packets']
))->setHelp('Packets processed at the same time, 1–65,000. Default is 1024. Too high a value can exhaust memory.');
$section->addInput(new Form_Select(
	'detect_eng_profile',
	'Detect-engine profile',
	$pconfig['detect_eng_profile'],
	array('low' => 'Low', 'medium' => 'Medium', 'high' => 'High')
))->setHelp('Medium (default) balances memory and speed. High is fastest and uses the most memory.');
$section->addInput(new Form_Select(
	'mpm_algo',
	'Multi-pattern matcher',
	$pconfig['mpm_algo'],
	array('auto' => 'Auto', 'ac' => 'AC', 'ac-bs' => 'AC-BS', 'ac-ks' => 'AC-KS', 'hs' => 'Hyperscan')
))->setHelp('Auto (default) uses Hyperscan when available.');
$section->addInput(new Form_Select(
	'spm_algo',
	'Single-pattern matcher',
	$pconfig['spm_algo'],
	array('auto' => 'Auto', 'bm' => 'BM', 'hs' => 'Hyperscan')
))->setHelp('Auto (default) uses Hyperscan when available.');
$section->addInput(new Form_Select(
	'sgh_mpm_context',
	'Signature group MPM context',
	$pconfig['sgh_mpm_context'],
	array('auto' => 'Auto', 'full' => 'Full', 'single' => 'Single')
))->setHelp('Auto (default) picks Full or Single from the matcher. Full can be faster but uses much more memory.');
$section->addInput(new Form_Input(
	'inspect_recursion_limit',
	'Inspection recursion limit',
	'text',
	$pconfig['inspect_recursion_limit']
))->setHelp('Default is 3000. 0 uses the internal default; blank means no limit.');
$section->addInput($cb('delayed_detect', 'Delayed detect', 'Build the signature list after capture threads have started'));
$section->addInput($cb('intf_promisc_mode', 'Promiscuous mode', 'Put the interface in promiscuous mode (default)'));
$section->addInput(new Form_Input(
	'intf_snaplen',
	'PCAP snaplen',
	'text',
	$pconfig['intf_snaplen']
))->setHelp('Bytes, default 1518 (IDS and Legacy mode only). Increase it if the interface carries VLAN traffic and expected alerts are missing.');
$form->add($section);

/* ---------------------------------------------------------------- advanced */
$section = new Form_Section('Advanced configuration pass-through', 'suri-advanced',
	COLLAPSIBLE | ((!empty($input_errors) || !empty($pconfig['configpassthru'])) ? SEC_OPEN : SEC_CLOSED));
$section->addInput(new Form_Textarea (
	'configpassthru',
	'Pass-through',
	base64_decode($pconfig['configpassthru'])
))->setHelp('Extra suricata.yaml parameters, one per line. They are inserted into the generated configuration.');
$form->add($section);

// List viewer pop-ups for the View list buttons
foreach ([['View HOME_NET', 'homenet', 'homenet_text'], ['View EXTERNAL_NET', 'externalnet', 'externalnet_text'],
    ['View PASS LIST', 'passlist', 'passlist_text'], ['View Suppress List', 'suppresslist', 'suppresslist_text']] as [$mtitle, $mid, $mfield]) {
	$modal = new Modal($mtitle, $mid, 'large', 'Close');
	$modal->addInput(new Form_Textarea (
		$mfield,
		'',
		'...Loading...'
	))->addClass('fs-mono')->setAttribute('rows', '12')->setAttribute('wrap', 'off');
	$form->add($modal);
}

if (isset($id)) {
	$form->addGlobal(new Form_Input(
		'id',
		'id',
		'hidden',
		$id
	));
}
if (isset($action)) {
	$form->addGlobal(new Form_Input(
		'action',
		'action',
		'hidden',
		$action
	));
}
fs_form_cancel($form, '/suricata/suricata_interfaces.php');
print($form);
?>

<script type="text/javascript">
//<![CDATA[

var ifacearray = <?= json_encode(get_configured_interface_with_descr()) ?>;
var ifacemap = new Map(Object.entries(ifacearray));
ifacemap.set("Unassigned", "Unassigned");

events.push(function(){

	function enable_blockoffenders() {
		var hide = ! $('#blockoffenders').prop('checked');
		hideCheckbox('blockoffenderskill', hide);
		hideCheckbox('block_drops_only', hide);
		hideCheckbox('passlist_debug_log', hide);
		hideSelect('blockoffendersip', hide);
		hideSelect('ips_mode', hide);
		hideClass('passlist', hide);
		if ($('#ips_mode').val() == 'ips_mode_inline') {
			hideInput('ips_netmap_threads', hide);
			hideCheckbox('blockoffenderskill', true);
			hideCheckbox('block_drops_only', true);
			hideCheckbox('passlist_debug_log', true);
			hideSelect('blockoffendersip', true);
			hideClass('passlist', true);
			hideInput('intf_snaplen', true);
			if (hide) {
				$('#eve_log_drop').parent().hide();
			}
			else {
				$('#eve_log_drop').parent().show();
			}
		}
		else {
			$('#eve_log_drop').parent().hide();
			hideInput('intf_snaplen', false);
			hideInput('ips_netmap_threads', true);
		}
	}

	function enable_autofp_scheduler() {
		if ($('#runmode').val() == 'autofp') {
			hideSelect('autofp_scheduler', false);
		}
		else {
			hideSelect('autofp_scheduler', true);
		}
	}

	function toggle_system_log() {
		var hide = ! $('#alertsystemlog').prop('checked');
		hideSelect('alertsystemlog_facility', hide);
		hideSelect('alertsystemlog_priority', hide);
	}

	function toggle_enable_stats() {
		var hide = ! $('#enable_stats_collection').prop('checked');
		hideInput('stats_upd_interval', hide);
		toggle_stats_log();
		toggle_telegraf_stats();
		toggle_eve_log_stats();
		hideCheckbox('enable_telegraf_stats', hide);
		hideCheckbox('enable_stats_log', hide);
		disableInput('eve_log_stats', hide);
	}

	function toggle_stats_log() {
		if ($('#enable_stats_collection').prop('checked')) {
			var hide = ! $('#enable_stats_log').prop('checked');
			hideCheckbox('append_stats_log', hide);
		}
		else {
			hideCheckbox('append_stats_log', true);
		}
	}

	function toggle_telegraf_stats() {
		if ($('#enable_stats_collection').prop('checked')) {
			var hide = ! $('#enable_telegraf_stats').prop('checked');
			hideInput('suricata_telegraf_unix_socket_name', hide);
		}
		else {
			hideInput('suricata_telegraf_unix_socket_name', true);
		}
	}

	function toggle_http_log() {
		var hide = ! $('#enable_http_log').prop('checked');
		hideInput('http_log_socket', hide);
		hideCheckbox('append_http_log', hide);
		hideCheckbox('http_log_extended', hide);
		if ($('#http_log_filetype').val() == 'regular') {
			hideSelect('http_log_socket', true);
		}
		else {
			hideSelect('http_log_socket', false);
		}
		hideSelect('http_log_filetype', hide);
	}

	function toggle_tls_log() {
		var hide = ! $('#enable_tls_log').prop('checked');
		hideInput('tls_log_socket', hide);
		hideCheckbox('enable_tls_store', hide);
		hideCheckbox('tls_log_extended', hide);
		hideCheckbox('append_tls_log', hide);
		hideCheckbox('tls_session_resumption', hide);
		if ($('#tls_log_filetype').val() == 'regular') {
			hideSelect('tls_log_socket', true);
		}
		else {
			hideSelect('tls_log_socket', false);
		}
		hideSelect('tls_log_filetype', hide);
	}

	function toggle_enable_file_store() {
		var hide = ! $('#enable_file_store').prop('checked');
		hideInput('file_store_logdir', hide);
	}

	function toggle_pcap_log() {
		var hide = ! $('#enable_pcap_log').prop('checked');
		hideCheckbox('pcap_use_stream_depth',hide);
		hideCheckbox('pcap_honor_pass_rules',hide);
		hideInput('max_pcap_log_size', hide);
		hideInput('max_pcap_log_files', hide);
		hideSelect('pcap_log_conditional', hide);
	}

	function toggle_eve_log() {
		var hide = ! $('#enable_eve_log').prop('checked');
		if ($('#eve_output_type').val().indexOf("unix") != -1) {
			hideSelect('eve_output_socket', false);
		}
		else {
			hideSelect('eve_output_socket', true);
		}
		hideSelect('eve_output_type', hide);
		hideCheckbox('eve_log_alerts',hide);
		hideCheckbox('eve_log_anomaly',hide);
		hideCheckbox('eve_log_alerts_xff',hide);
		hideCheckbox('eve_log_ethernet',hide);
		hideCheckbox('eve_log_drops',hide);
		hideClass('eve_log_info', hide);
		hideClass('eve_log_drops_options', hide);
		toggle_eve_log_files();
	}

	function toggle_eve_syslog() {
		var hide = ! ($('#enable_eve_log').prop('checked') && $('#eve_output_type').val() == "syslog");
		hideSelect('eve_systemlog_facility',hide);
		hideSelect('eve_systemlog_priority',hide);
	}

	function toggle_eve_redis() {
		var hide = ! ($('#enable_eve_log').prop('checked') && $('#eve_output_type').val() == "redis");
		hideClass('eve_redis_connection',hide);
		hideSelect('eve_redis_mode',hide);
		hideInput('eve_redis_key',hide);
	}

	function toggle_eve_log_alerts() {
		var hide = ! ($('#eve_log_alerts').prop('checked') && $('#enable_eve_log').prop('checked'));
		hideSelect('eve_log_alerts_payload',hide);
		hideClass('eve_log_alerts_details',hide);
	}

	function toggle_eve_log_drops() {
		var hide = ! ($('#eve_log_drops').prop('checked') && $('#enable_eve_log').prop('checked'));
		hideClass('eve_log_drops_options',hide);
	}

	function toggle_eve_log_anomaly() {
		var hide = ! ($('#eve_log_anomaly').prop('checked') && $('#enable_eve_log').prop('checked'));
		hideClass('eve_log_anomaly_details',hide);
	}

	function toggle_eve_log_alerts_xff() {
		var hide = ! ($('#eve_log_alerts_xff').prop('checked') && $('#eve_log_alerts').prop('checked') && $('#enable_eve_log').prop('checked'));
		hideSelect('eve_log_alerts_xff_mode',hide);
		hideSelect('eve_log_alerts_xff_deployment',hide);
		hideInput('eve_log_alerts_xff_header', hide);
	}

	function toggle_eve_log_stats() {
		var hide = ! ($('#eve_log_stats').prop('checked') && $('#enable_eve_log').prop('checked') && $('#enable_stats_collection').prop('checked'));
		hideClass('eve_log_stats_details',hide);
	}

	function toggle_eve_log_http() {
		var disable = ! $('#eve_log_http').prop('checked');
		disableInput('eve_log_http_extended',disable);
		toggle_eve_log_http_extended();
	}

	function toggle_eve_log_tls() {
		var disable = ! $('#eve_log_tls').prop('checked');
		disableInput('eve_log_tls_extended',disable);
		toggle_eve_log_tls_extended();
	}

	function toggle_eve_log_dhcp() {
		var disable = ! $('#eve_log_dhcp').prop('checked');
		disableInput('eve_log_dhcp_extended',disable);
	}

	function toggle_eve_log_smtp() {
		var disable = ! $('#eve_log_smtp').prop('checked');
		disableInput('eve_log_smtp_extended',disable);
		toggle_eve_log_smtp_extended();
	}

	function toggle_eve_log_files() {
		var hide = ! ($('#eve_log_files').prop('checked') && $('#enable_eve_log').prop('checked'));
		hideCheckbox('eve_log_files_magic',hide);
		hideSelect('eve_log_files_hash',hide);
	}

	function toggle_eve_log_http_extended() {
		var hide = ! ($('#eve_log_http_extended').prop('checked') && $('#enable_eve_log').prop('checked') && $('#eve_log_http').prop('checked'));
		hideSelect('eve_log_http_extended_headers\\[\\]',hide);
	}

	function toggle_eve_log_smtp_extended() {
		var hide = ! ($('#eve_log_smtp_extended').prop('checked') && $('#enable_eve_log').prop('checked') && $('#eve_log_smtp').prop('checked'));
		hideSelect('eve_log_smtp_extended_fields\\[\\]',hide);
	}

	function toggle_eve_log_tls_extended() {
		var hide = ! ($('#eve_log_tls_extended').prop('checked') && $('#enable_eve_log').prop('checked') && $('#eve_log_tls').prop('checked'));
		hideSelect('eve_log_tls_extended_fields\\[\\]',hide);
	}

	function enable_change() {
		var disable = ! $('#enable').prop('checked');

		disableInput('alertsystemlog', disable);
		disableInput('alertsystemlog_facility', disable);
		disableInput('alertsystemlog_priority', disable);
		disableInput('enable_verbose_logging', disable);
		disableInput('blockoffenders', disable);
		disableInput('ips_mode', disable);
		disableInput('blockoffenderskill', disable);
		disableInput('block_drops_only', disable);
		disableInput('passlist_debug_log', disable);
		disableInput('blockoffendersip', disable);
		disableInput('ips_netmap_threads', disable);
		disableInput('performance', disable);
		disableInput('runmode', disable);
		disableInput('autofp_scheduler', disable);
		disableInput('max_pending_packets', disable);
		disableInput('detect_eng_profile', disable);
		disableInput('inspect_recursion_limit', disable);
		disableInput('mpm_algo', disable);
		disableInput('spm_algo', disable);
		disableInput('sgh_mpm_context', disable);
		disableInput('delayed_detect', disable);
		disableInput('intf_promisc_mode', disable);
		disableInput('intf_snaplen', disable);
		disableInput('fpm_split_any_any', disable);
		disableInput('fpm_search_optimize', disable);
		disableInput('fpm_no_stream_inserts', disable);
		disableInput('cksumcheck', disable);
		disableInput('externallistname', disable);
		disableInput('homelistname', disable);
		disableInput('suppresslistname', disable);
		disableInput('btnHomeNet', disable);
		disableInput('btnExternalNet', disable);
		disableInput('btnSuppressList', disable);
		disableInput('passlistname', disable);
		disableInput('btnPasslist', disable);
		disableInput('configpassthru', disable);
		disableInput('enable_stats_collection', disable);
		disableInput('enable_stats_log', disable);
		disableInput('stats_upd_interval', disable);
		disableInput('append_stats_log', disable);
		disableInput('enable_telegraf_stats', disable);
		disableInput('suricata_telegraf_unix_socket_name', disable);
		disableInput('enable_http_log', disable);
		disableInput('append_http_log', disable);
		disableInput('http_log_extended', disable);
		disableInput('http_log_filetype', disable);
		disableInput('http_log_socket', disable);
		disableInput('enable_tls_log', disable);
		disableInput('enable_tls_store', disable);
		disableInput('append_tls_log', disable);
		disableInput('tls_log_extended', disable);
		disableInput('tls_log_filetype', disable);
		disableInput('tls_log_socket', disable);
		disableInput('tls_session_resumption', disable);
		disableInput('enable_file_store', disable);
		disableInput('file_store_logdir', disable);
		disableInput('enable_pcap_log', disable);
		disableInput('max_pcap_log_size', disable);
		disableInput('max_pcap_log_files', disable);
		disableInput('pcap_log_conditional', disable);
		disableInput('pcap_honor_pass_rules', disable);
		disableInput('pcap_use_stream_depth', disable);
		disableInput('enable_eve_log', disable);
		disableInput('eve_output_type', disable);
		disableInput('eve_output_socket', disable);
		disableInput('eve_systemlog_facility', disable);
		disableInput('eve_systemlog_priority', disable);
		disableInput('eve_redis_mode', disable);
		disableInput('eve_redis_key', disable);
		disableInput('eve_redis_server', disable);
		disableInput('eve_redis_port', disable);
		disableInput('eve_log_info', disable);
		disableInput('eve_log_alerts', disable);
		disableInput('eve_log_alerts_payload', disable);
		disableInput('eve_log_alerts_metadata', disable);
		disableInput('eve_log_alerts_verdict', disable);
		disableInput('eve_log_alerts_tagged', disable);
		disableInput('eve_log_drops', disable);
		disableInput('eve_log_alert_drops', disable);
		disableInput('eve_log_drops_verdict', disable);
		disableInput('eve_log_drops_flows', disable);
		disableInput('eve_log_anomaly', disable);
		disableInput('eve_log_anomaly_type_decode', disable);
		disableInput('eve_log_anomaly_type_stream', disable);
		disableInput('eve_log_anomaly_type_applayer', disable);
		disableInput('eve_log_anomaly_packethdr', disable);
		disableInput('eve_log_http', disable);
		disableInput('eve_log_dns', disable);
		disableInput('eve_log_nfs', disable);
		disableInput('eve_log_smb', disable);
		disableInput('eve_log_krb5', disable);
		disableInput('eve_log_ikev2', disable);
		disableInput('eve_log_tftp', disable);
		disableInput('eve_log_rdp', disable);
		disableInput('eve_log_sip', disable);
		disableInput('eve_log_ftp', disable);
		disableInput('eve_log_http2', disable);
		disableInput('eve_log_rfb', disable);
		disableInput('eve_log_tls', disable);
		disableInput('eve_log_files', disable);
		disableInput('eve_log_dhcp', disable);
		disableInput('eve_log_ssh', disable);
		disableInput('eve_log_smtp', disable);
		disableInput('eve_log_snmp', disable);
		disableInput('eve_log_mqtt', disable);
		disableInput('eve_log_bittorrent', disable);
		disableInput('eve_log_pgsql', disable);
		disableInput('eve_log_quic', disable);
		disableInput('eve_log_flow', disable);
		disableInput('eve_log_netflow', disable);
		disableInput('eve_log_drop', disable);
		disableInput('eve_log_alerts_packet',disable)
		disableInput('eve_log_alerts_payload',disable);
		disableInput('eve_log_alerts_http',disable);
		disableInput('eve_log_ethernet',disable);
		disableInput('eve_log_alerts_xff',disable);
		disableInput('eve_log_alerts_xff_mode',disable);
		disableInput('eve_log_alerts_xff_deployment',disable);
		disableInput('eve_log_alerts_xff_header',disable);
		disableInput('eve_log_files_magic',disable);
		disableInput('eve_log_files_hash',disable);

		var disable_http = ! $('#eve_log_http').prop('checked');
		disableInput('eve_log_http_extended',disable||disable_http);

		var disable_tls = ! $('#eve_log_tls').prop('checked');
		disableInput('eve_log_tls_extended',disable||disable_tls);

		var disable_dhcp = ! $('#eve_log_dhcp').prop('checked');
		disableInput('eve_log_dhcp_extended',disable||disable_dhcp);

		var disable_smtp = ! $('#eve_log_smtp').prop('checked');
		disableInput('eve_log_smtp_extended',disable||disable_smtp);

		var disable_stats = ! $('#enable_stats_collection').prop('checked');
		disableInput('eve_log_stats',disable||disable_stats);

		disableInput('eve_log_stats_totals',disable);
		disableInput('eve_log_stats_deltas',disable);
		disableInput('eve_log_stats_threads',disable);

		disableInput('eve_log_http_extended_headers\\[\\]',disable);
		disableInput('eve_log_smtp_extended_fields\\[\\]',disable);
		disableInput('eve_log_tls_extended_fields\\[\\]',disable);

	}

	// Call the list viewing page and write what it returns to the modal text area
	function getListContents(listName, listType, ctrlID) {
		var ajaxRequest;

		ajaxRequest = $.ajax({
			url: "/suricata/suricata_list_view.php",
			type: "post",
			data: { ajax: 	"ajax",
			        wlist: 	listName,
					type: 	listType,
					id: 	"<?=$id?>"
			}
		});

		// Display the results of the above ajax call
		ajaxRequest.done(function (response, textStatus, jqXHR) {
			// Write the list contents to the text control
			$('#' + ctrlID).text(response);
			$('#' + ctrlID).attr('readonly', true);
		});
	}

	// ---------- Event triggers fired after the VIEW LIST modals are shown -----------------------
	$('#homenet').on('shown.bs.modal', function() {
		getListContents($('#homelistname option:selected' ).text(), 'homenet', 'homenet_text');
	});

	$('#externalnet').on('shown.bs.modal', function() {
		getListContents($('#externallistname option:selected' ).text(), 'externalnet', 'externalnet_text');
	});

	$('#passlist').on('shown.bs.modal', function() {
		getListContents($('#passlistname option:selected' ).text(), 'passlist', 'passlist_text');
	});

	$('#suppresslist').on('shown.bs.modal', function() {
		getListContents($('#suppresslistname option:selected').text(), 'suppress', 'suppresslist_text');
	});

	// ---------- Click checkbox handlers ---------------------------------------------------------

	/* When form control id is clicked, disable/enable it's associated form controls */

	$('#enable').click(function() {
		enable_change();
	});

	$('#alertsystemlog').click(function() {
		toggle_system_log();
	});

	$('#enable_stats_collection').click(function() {
		toggle_enable_stats();
	});

	$('#enable_stats_log').click(function() {
		toggle_stats_log();
	});

	$('#enable_telegraf_stats').click(function() {
		toggle_telegraf_stats();
	});

	$('#enable_http_log').click(function() {
		toggle_http_log();
	});

	$('#enable_tls_log').click(function() {
		toggle_tls_log();
	});

	$('#enable_file_store').click(function() {
		toggle_enable_file_store();
	});

	$('#enable_pcap_log').click(function() {
		toggle_pcap_log();
	});

	$('#enable_eve_log').click(function() {
		toggle_eve_log();
		toggle_eve_redis();
		toggle_eve_syslog();
		toggle_eve_log_alerts();
		toggle_eve_log_anomaly();
		toggle_eve_log_alerts_xff();
		toggle_eve_log_stats();
		toggle_eve_log_http_extended();
		toggle_eve_log_smtp_extended();
		toggle_eve_log_tls_extended();
	});

	$('#eve_output_type').change(function() {
		toggle_eve_redis();
		toggle_eve_syslog();
	});

	$('#eve_log_alerts').click(function() {
		toggle_eve_log_alerts();
	});

	$('#eve_log_drops').click(function() {
		toggle_eve_log_drops();
	});

	$('#eve_log_anomaly').click(function() {
		toggle_eve_log_anomaly();
	});

	$('#eve_log_alerts_xff').click(function() {
		toggle_eve_log_alerts_xff();
	});

	$('#eve_log_stats').click(function() {
		toggle_eve_log_stats();
	});

	$('#eve_log_http').click(function() {
		toggle_eve_log_http();
	});

	$('#eve_log_tls').click(function() {
		toggle_eve_log_tls();
	});

	$('#eve_log_dhcp').click(function() {
		toggle_eve_log_dhcp();
	});

	$('#eve_log_smtp').click(function() {
		toggle_eve_log_smtp();
	});

	$('#eve_log_files').click(function() {
		toggle_eve_log_files();
	});

	$('#blockoffenders').click(function() {
		enable_blockoffenders();
	});

	$('#eve_log_http_extended').click(function(){
		toggle_eve_log_http_extended();
	});

	$('#eve_log_smtp_extended').click(function(){
		toggle_eve_log_smtp_extended();
	});

	$('#eve_log_tls_extended').click(function(){
		toggle_eve_log_tls_extended();
	});

	$('#ips_mode').on('change', function() {
		if ($('#ips_mode').val() == 'ips_mode_inline') {
			hideCheckbox('blockoffenderskill', true);
			hideCheckbox('block_drops_only', true);
			hideCheckbox('passlist_debug_log', true);
			hideSelect('blockoffendersip', true);
			hideClass('passlist', true);
			hideInput('intf_snaplen', true);
			hideInput('ips_netmap_threads', false);
			$('#eve_log_drop').parent().show();
			$('#ips_warn_dlg').modal('show');
		}
		else {
			hideCheckbox('blockoffenderskill', false);
			hideCheckbox('block_drops_only', false);
			hideCheckbox('passlist_debug_log', false);
			hideSelect('blockoffendersip', false);
			hideInput('intf_snaplen', false);
			hideClass('passlist', false);
			$('#eve_log_drop').parent().hide();
			$('#ips_warn_dlg').modal('hide');
			hideInput('ips_netmap_threads', true);
		}
	});

	$('#http_log_filetype').on('change', function() {
		if ($('#http_log_filetype').val() == 'regular') {
			hideSelect('http_log_socket', true);
		}
		else {
			hideSelect('http_log_socket', false);
		}
	});

	$('#tls_log_filetype').on('change', function() {
		if ($('#tls_log_filetype').val() == 'regular') {
			hideSelect('tls_log_socket', true);
		}
		else {
			hideSelect('tls_log_socket', false);
		}
	});

	$('#eve_output_type').on('change', function() {
		if ($('#eve_output_type').val().indexOf("unix") != -1) {
			hideSelect('eve_output_socket', false);
		}
		else {
			hideSelect('eve_output_socket', true);
		}
	});

	$('#runmode').on('change', function() {
		if ($('#runmode').val() == 'autofp') {
			hideSelect('autofp_scheduler', false);
		}
		else {
			hideSelect('autofp_scheduler', true);
		}
	});

	$('#interface').on('change', function() {
		$('#descr').val(ifacemap.get($('#interface').val()));
		$('#file_store_logdir').val('');
	});

	// ---------- On initial page load ------------------------------------------------------------
	enable_blockoffenders();
	enable_autofp_scheduler();
	toggle_system_log();
	toggle_enable_stats();
	toggle_http_log();
	toggle_tls_log();
	toggle_enable_file_store();
	toggle_pcap_log();
	toggle_eve_log();
	toggle_eve_redis();
	toggle_eve_syslog();
	toggle_eve_log_alerts();
	toggle_eve_log_drops();
	toggle_eve_log_anomaly();
	toggle_eve_log_alerts_xff();
	toggle_eve_log_http();
	toggle_eve_log_smtp();
	toggle_eve_log_tls();
	toggle_eve_log_dhcp();
	toggle_eve_log_files();
	toggle_eve_log_tls_extended();
	toggle_eve_log_http_extended();
	toggle_eve_log_smtp_extended();
	enable_change();

});
//]]>
</script>

<?php include("foot.inc"); ?>
