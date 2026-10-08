<?php
/*
 * suricata_app_parsers.php
 *
 * part of FreeSense (https://www.freesense.org)
 * Copyright (c) 2006-2026 Rubicon Communications, LLC (Netgate)
 * Copyright (c) 2025-2026 The FreeSense Project
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

if (isset($_POST['id']) && is_numericint($_POST['id']))
	$id = $_POST['id'];
elseif (isset($_GET['id']) && is_numericint($_GET['id']))
	$id = htmlspecialchars($_GET['id']);

if (!is_numericint($id))
	$id = 0;

// Initialize Suricata interface and HTTP libhtp engine arrays if necessary
config_init_path("installedpackages/suricata/rule/{$id}/libhtp_policy/item");

// Initialize required array variables as necessary
$a_aliases = config_get_path('aliases/alias', []);

$a_nat = config_get_path("installedpackages/suricata/rule/{$id}", []);

$libhtp_engine_next_id = count(array_get_path($a_nat, 'libhtp_policy/item', []));

// Build a lookup array of currently used engine 'bind_to' Aliases
// so we can screen matching Alias names from the list.
$used = array();
foreach (array_get_path($a_nat, 'libhtp_policy/item', []) as $v)
	$used[$v['bind_to']] = true;

$pconfig = array();
if (isset($id) && !empty($a_nat)) {
	/* Get current values from config for page form fields */
	$pconfig = $a_nat;
	if (empty($pconfig['app_layer_error_policy']))
		$pconfig['app_layer_error_policy'] = "ignore";

	// See if Host-OS policy engine array is configured and use
	// it; otherwise create a default engine configuration.
	if (!array_get_path($pconfig, 'libhtp_policy/item')) {
		$default = array( "name" => "default", "bind_to" => "all", "personality" => "IDS",
				  "request-body-limit" => 4096, "response-body-limit" => 4096,
				  "double-decode-path" => "no", "double-decode-query" => "no",
				  "uri-include-all" => "no", "meta-field-limit" => 18432 );
		array_init_path($pconfig, 'libhtp_policy/item');
		$pconfig['libhtp_policy']['item'][] = $default;
		array_init_path($a_nat, 'libhtp_policy/item');
		$a_nat['libhtp_policy']['item'][] = $default;
		config_set_path("installedpackages/suricata/rule/{$id}", $a_nat);
		write_config("Suricata pkg: created a new default HTTP server configuration for " . convert_friendly_interface_to_friendly_descr($a_nat['interface']));
		$libhtp_engine_next_id++;
	}
	else
		$pconfig['libhtp_policy'] = $a_nat['libhtp_policy'];
}

// Check for "import or select alias mode" and set flags if TRUE.
// "selectalias", when true, displays radio buttons to limit
// multiple selections.
if ($_POST['import_alias']) {
	$eng_id = $libhtp_engine_next_id;
	$importalias = true;
	$selectalias = false;
	$title = "HTTP Server Policy";
}
elseif ($_POST['select_alias']) {
	$importalias = true;
	$selectalias = true;
	$title = "HTTP Server Policy";

	// Preserve current Libhtp Policy Engine settings
	$eng_id = $_POST['eng_id'];
	$eng_name = $_POST['policy_name'];
	$eng_bind = $_POST['policy_bind_to'];
	$eng_personality = $_POST['personality'];
	$eng_req_body_limit = $_POST['req_body_limit'];
	$eng_resp_body_limit = $_POST['resp_body_limit'];
	$eng_meta_field_limit = $_POST['meta_field_limit'];
	$eng_enable_double_decode_path = $_POST['enable_double_decode_path'];
	$eng_enable_double_decode_query = $_POST['enable_double_decode_query'];
	$eng_enable_uri_include_all = $_POST['enable_uri_include_all'];
	$mode = "add_edit_libhtp_policy";
}

if ($_POST['save_libhtp_policy']) {
	if ($_POST['eng_id'] != "") {
		$eng_id = $_POST['eng_id'];

		// Grab all the POST values and save in new temp array
		$engine = array();
		$policy_name = trim($_POST['policy_name']);
		if ($policy_name) {
			$engine['name'] = $policy_name;
		}
		else
			$input_errors[] = gettext("The 'Policy Name' value cannot be blank.");

		if ($_POST['policy_bind_to']) {
			if (is_alias($_POST['policy_bind_to']))
				$engine['bind_to'] = $_POST['policy_bind_to'];
			elseif (strtolower(trim($_POST['policy_bind_to'])) == "all")
				$engine['bind_to'] = "all";
			else
				$input_errors[] = gettext("You must provide a valid Alias or the reserved keyword 'all' for the 'Bind-To IP Address' value.");
		}
		else
			$input_errors[] = gettext("The 'Bind-To IP Address' value cannot be blank.  Provide a valid Alias or the reserved keyword 'all'.");

		if ($_POST['personality']) { $engine['personality'] = $_POST['personality']; } else { $engine['personality'] = "bsd"; }

		if (is_numeric($_POST['req_body_limit']) && $_POST['req_body_limit'] >= 0)
			$engine['request-body-limit'] = $_POST['req_body_limit'];
		else
			$input_errors[] = gettext("The value for 'Request Body Limit' must be all numbers and greater than or equal to zero.");

		if (is_numeric($_POST['resp_body_limit']) && $_POST['resp_body_limit'] >= 0)
			$engine['response-body-limit'] = $_POST['resp_body_limit'];
		else
			$input_errors[] = gettext("The value for 'Response Body Limit' must be all numbers and greater than or equal to zero.");

		if (is_numeric($_POST['meta_field_limit']) && $_POST['meta_field_limit'] >= 0)
			$engine['meta-field-limit'] = $_POST['meta_field_limit'];
		else
			$input_errors[] = gettext("The value for 'Meta-Field Limit' must be all numbers and greater than or equal to zero.");

		if ($_POST['enable_double_decode_path']) { $engine['double-decode-path'] = 'yes'; }else{ $engine['double-decode-path'] = 'no'; }
		if ($_POST['enable_double_decode_query']) { $engine['double-decode-query'] = 'yes'; }else{ $engine['double-decode-query'] = 'no'; }
		if ($_POST['enable_uri_include_all']) { $engine['uri-include-all'] = 'yes'; }else{ $engine['uri-include-all'] = 'no'; }

		// Can only have one "all" Bind_To address
		if ($engine['bind_to'] == "all" && $engine['name'] != "default")
			$input_errors[] = gettext("Only one default OS-Policy Engine can be bound to all addresses.");

		// if no errors, write new entry to conf
		if (!$input_errors) {
			if (isset($eng_id) && isset($a_nat['libhtp_policy']['item'][$eng_id])) {
				$a_nat['libhtp_policy']['item'][$eng_id] = $engine;
			}
			else
				$a_nat['libhtp_policy']['item'][] = $engine;

			/* Reorder the engine array to ensure the */
			/* 'bind_to=all' entry is at the bottom   */
			/* if it contains more than one entry.	  */
			if (count($a_nat['libhtp_policy']['item']) > 1) {
				$i = -1;
				foreach ($a_nat['libhtp_policy']['item'] as $f => $v) {
					if ($v['bind_to'] == "all") {
						$i = $f;
						break;
					}
				}
				/* Only relocate the entry if we  */
				/* found it, and it's not already */
				/* at the end.					  */
				if ($i > -1 && ($i < (count($a_nat['libhtp_policy']['item']) - 1))) {
					$tmp = $a_nat['libhtp_policy']['item'][$i];
					unset($a_nat['libhtp_policy']['item'][$i]);
					$a_nat['libhtp_policy']['item'][] = $tmp;
				}
			}

			// Now write the new engine array to conf
			config_set_path("installedpackages/suricata/rule/{$id}", $a_nat);
			write_config("Suricata pkg: saved updated HTTP server configuration for " . convert_friendly_interface_to_friendly_descr($a_nat['interface']));
			$add_edit_libhtp_policy = false;
			header( 'Expires: Sat, 26 Jul 1997 05:00:00 GMT' );
			header( 'Last-Modified: ' . gmdate( 'D, d M Y H:i:s' ) . ' GMT' );
			header( 'Cache-Control: no-store, no-cache, must-revalidate' );
			header( 'Cache-Control: post-check=0, pre-check=0', false );
			header( 'Pragma: no-cache' );
			header("Location: suricata_app_parsers.php?id=$id");
			exit;
		}
		else {
			$add_edit_libhtp_policy = true;
			$pengcfg = $engine;
		}
	}
}
elseif ($_POST['add_libhtp_policy']) {
	$add_edit_libhtp_policy = true;
	$pengcfg = array( "name" => "engine_{$libhtp_engine_next_id}", "bind_to" => "", "personality" => "IDS",
			  "request-body-limit" => "4096", "response-body-limit" => "4096", "meta-field-limit" => 18432, 
			  "double-decode-path" => "no", "double-decode-query" => "no", "uri-include-all" => "no" );
	$eng_id = $libhtp_engine_next_id;
}
elseif ($_POST['edit_libhtp_policy']) {
	if ($_POST['eng_id'] != "") {
		$add_edit_libhtp_policy = true;
		$eng_id = $_POST['eng_id'];
		$pengcfg = $a_nat['libhtp_policy']['item'][$eng_id];
	}
}
elseif ($_POST['del_libhtp_policy']) {
	$natent = array();
	$natent = $pconfig;

	if ($_POST['eng_id'] != "") {
		unset($natent['libhtp_policy']['item'][$_POST['eng_id']]);
		$pconfig = $natent;
	}
	if (isset($id) && isset($a_nat)) {
		$a_nat = $natent;
		config_set_path("installedpackages/suricata/rule/{$id}", $a_nat);
		write_config("Suricata pkg: deleted a HTTP server configuration for " . convert_friendly_interface_to_friendly_descr($a_nat['interface']));
	}
	$add_edit_libhtp_policy = false;
	header( 'Expires: Sat, 26 Jul 1997 05:00:00 GMT' );
	header( 'Last-Modified: ' . gmdate( 'D, d M Y H:i:s' ) . ' GMT' );
	header( 'Cache-Control: no-store, no-cache, must-revalidate' );
	header( 'Cache-Control: post-check=0, pre-check=0', false );
	header( 'Pragma: no-cache' );
	header("Location: suricata_app_parsers.php?id=$id");
	exit;
}
elseif ($_POST['cancel_libhtp_policy']) {
	$add_edit_libhtp_policy = false;
}
elseif ($_POST['ResetAll']) {

	/* Reset all the settings to defaults */
	$pconfig['app_layer_error_policy'] = "ignore";
	$pconfig['asn1_max_frames'] = "256";
	$pconfig['bittorrent_parser'] = "yes";
	$pconfig['dcerpc_parser'] = "yes";
	$pconfig['dhcp_parser'] = "yes";
	$pconfig['dns_global_memcap'] = "16777216";
	$pconfig['dns_state_memcap'] = "524288";
	$pconfig['dns_request_flood_limit'] = "500";
	$pconfig['dns_parser_udp'] = "yes";
	$pconfig['dns_parser_udp_ports'] = "53";
	$pconfig['dns_parser_tcp'] = "yes";
	$pconfig['dns_parser_tcp_ports'] = "53";
	$pconfig['enip_parser'] = "yes";
	$pconfig['ftp_parser'] = "yes";
	$pconfig['ftp_data_parser'] = "on";
	$pconfig['http_parser'] = "yes";
	$pconfig['http_parser_memcap'] = "67108864";
	$pconfig['http2_parser'] = "yes";
	$pconfig['ikev2_parser'] = "yes";
	$pconfig['imap_parser'] = "detection-only";
	$pconfig['krb5_parser'] = "yes";
	$pconfig['mqtt_parser'] = "yes";
	$pconfig['msn_parser'] = "detection-only";
	$pconfig['nfs_parser'] = "yes";
	$pconfig['ntp_parser'] = "yes";
	$pconfig['pgsql_parser'] = "no";
	$pconfig['quic_parser'] = "yes";
	$pconfig['rfb_parser'] = "yes";
	$pconfig['rdp_parser'] = "yes";
	$pconfig['sip_parser'] = "yes";
	$pconfig['smb_parser'] = "yes";
	$pconfig['smtp_parser'] = "yes";
	$pconfig['smtp_parser_decode_mime'] = "off";
	$pconfig['smtp_parser_decode_base64'] = "on";
	$pconfig['smtp_parser_decode_quoted_printable'] = "on";
	$pconfig['smtp_parser_extract_urls'] = "on";
	$pconfig['smtp_parser_compute_body_md5'] = "off";
	$pconfig['snmp_parser'] = "yes";
	$pconfig['ssh_parser'] = "yes";
	$pconfig['tftp_parser'] = "yes";
	$pconfig['tls_parser'] = "yes";
	$pconfig['tls_detect_ports'] = "443";
	$pconfig['tls_encrypt_handling'] = "default";
	$pconfig['tls_ja3_fingerprint'] = "auto";
	$pconfig['telnet_parser'] = "yes";

	/* Log a message at the top of the page to inform the user */
	$savemsg = gettext("All flow and stream settings on this page have been reset to their defaults.  Click APPLY if you wish to keep these new settings.");
}
elseif ($_POST['save_import_alias']) {
	// If saving out of "select alias" mode,
	// then return to Libhtp Policy Engine edit
	// page.
	if ($_POST['mode'] == 'add_edit_libhtp_policy') {
		$pengcfg = array();
		$eng_id = $_POST['eng_id'];
		$pengcfg['name'] = $_POST['eng_name'];
		$pengcfg['bind_to'] = $_POST['eng_bind'];
		$pengcfg['personality'] = $_POST['eng_personality'];
		$pengcfg['request-body-limit'] = $_POST['eng_req_body_limit'];
		$pengcfg['response-body-limit'] = $_POST['eng_resp_body_limit'];
		$pengcfg['meta-field-limit'] = $_POST['eng_meta_field_limit'];
		$pengcfg['double-decode-path'] = $_POST['eng_enable_double_decode_path'];
		$pengcfg['double-decode-query'] = $_POST['eng_enable_double_decode_query'];
		$pengcfg['uri-include-all'] = $_POST['eng_enable_uri_include_all'];
		$add_edit_libhtp_policy = true;
		$mode = "add_edit_libhtp_policy";

		if (is_array($_POST['aliastoimport']) && count($_POST['aliastoimport']) == 1) {
			$pengcfg['bind_to'] = $_POST['aliastoimport'][0];
			$importalias = false;
			$selectalias = false;
		}
		else {
			$input_errors[] = gettext("No Alias is selected for import.  Nothing to SAVE.");
			$importalias = true;
			$selectalias = true;
			$eng_id = $_POST['eng_id'];
			$eng_name = $_POST['eng_name'];
			$eng_bind = $_POST['eng_bind'];
			$eng_personality = $_POST['eng_personality'];
			$eng_req_body_limit = $_POST['eng_req_body_limit'];
			$eng_resp_body_limit = $_POST['eng_resp_body_limit'];
			$eng_meta_field_limit = $_POST['eng_meta_field_limit'];
			$eng_enable_double_decode_path = $_POST['eng_enable_double_decode_path'];
			$eng_enable_double_decode_query = $_POST['eng_enable_double_decode_query'];
			$eng_enable_uri_include_all = $_POST['eng_enable_uri_include_all'];
		}
	}
	else {
		$engine = array( "name" => "", "bind_to" => "", "personality" => "IDS",
				 "request-body-limit" => "4096", "response-body-limit" => "4096", "meta-field-limit" => 18432, 
				 "double-decode-path" => "no", "double-decode-query" => "no", "uri-include-all" => "no" );

		// See if anything was checked to import
		if (is_array($_POST['aliastoimport']) && count($_POST['aliastoimport']) > 0) {
			foreach ($_POST['aliastoimport'] as $item) {
				$engine['name'] = strtolower($item);
				$engine['bind_to'] = $item;
				$a_nat['libhtp_policy']['item'][] = $engine;
			}
		}
		else {
			$input_errors[] = gettext("No entries were selected for import. Please select one or more Aliases for import and click SAVE.");
			$importalias = true;
		}

		// if no errors, write new entry to conf
		if (!$input_errors) {
			// Reorder the engine array to ensure the
			// 'bind_to=all' entry is at the bottom if
			// the array contains more than one entry.
			if (count($a_nat['libhtp_policy']['item']) > 1) {
				$i = -1;
				foreach ($a_nat['libhtp_policy']['item'] as $f => $v) {
					if ($v['bind_to'] == "all") {
						$i = $f;
						break;
					}
				}
				// Only relocate the entry if we
				// found it, and it's not already
				// at the end.
				if ($i > -1 && ($i < (count($a_nat['libhtp_policy']['item']) - 1))) {
					$tmp = $a_nat['libhtp_policy']['item'][$i];
					unset($a_nat['libhtp_policy']['item'][$i]);
					$a_nat['libhtp_policy']['item'][] = $tmp;
				}
				$pconfig['libhtp_policy']['item'] = $a_nat['libhtp_policy']['item'];
			}

			// Write the new engine array to config file
			config_set_path("installedpackages/suricata/rule/{$id}", $a_nat);
			write_config("Suricata pkg: saved an updated HTTP server configuration for " . convert_friendly_interface_to_friendly_descr($a_nat['interface']));
			$importalias = false;
			header( 'Expires: Sat, 26 Jul 1997 05:00:00 GMT' );
			header( 'Last-Modified: ' . gmdate( 'D, d M Y H:i:s' ) . ' GMT' );
			header( 'Cache-Control: no-store, no-cache, must-revalidate' );
			header( 'Cache-Control: post-check=0, pre-check=0', false );
			header( 'Pragma: no-cache' );
			header("Location: suricata_app_parsers.php?id=$id");
			exit;
		}
	}
}
elseif ($_POST['cancel_import_alias']) {
	$importalias = false;
	$selectalias = false;
	$eng_id = $_POST['eng_id'];

	// If cancelling out of "select alias" mode,
	// then return to Libhtp Policy Engine edit
	// page.
	if ($_POST['mode'] == 'add_edit_libhtp_policy') {
		$pengcfg = array();
		$pengcfg['name'] = $_POST['eng_name'];
		$pengcfg['bind_to'] = $_POST['eng_bind'];
		$pengcfg['personality'] = $_POST['eng_personality'];
		$pengcfg['request-body-limit'] = $_POST['eng_req_body_limit'];
		$pengcfg['response-body-limit'] = $_POST['eng_resp_body_limit'];
		$pengcfg['meta-field-limit'] = $_POST['eng_meta_field_limit'];
		$pengcfg['double-decode-path'] = $_POST['eng_enable_double_decode_path'];
		$pengcfg['double-decode-query'] = $_POST['eng_enable_double_decode_query'];
		$pengcfg['uri-include-all'] = $_POST['eng_enable_uri_include_all'];
		$add_edit_libhtp_policy = true;
	}
}
elseif ($_POST['save'] || $_POST['apply']) {
	$natent = array();
	$natent = $pconfig;

	// TODO: validate input values
	if (!is_numeric($_POST['asn1_max_frames'] ) || $_POST['asn1_max_frames'] < 1)
		$input_errors[] = gettext("The value for 'ASN1 Max Frames' must be all numbers and greater than 0.");

	if (!is_numeric($_POST['dns_global_memcap'] ) || $_POST['dns_global_memcap'] < 1)
		$input_errors[] = gettext("The value for 'DNS Global Memcap' must be all numbers and greater than 0.");

	if (!is_numeric($_POST['dns_state_memcap'] ) || $_POST['dns_state_memcap'] < 1)
		$input_errors[] = gettext("The value for 'DNS Flow/State Memcap' must be all numbers and greater than 0.");

	if (!is_numeric($_POST['dns_request_flood_limit'] ) || $_POST['dns_request_flood_limit'] < 1)
		$input_errors[] = gettext("The value for 'DNS Request Flood Limit' must be all numbers and greater than 0.");

	if (!is_numeric($_POST['http_parser_memcap'] ) || $_POST['http_parser_memcap'] < 1)
		$input_errors[] = gettext("The value for 'HTTP Memcap' must be all numbers and greater than 0.");

	if (is_alias($_POST['tls_detect_ports']) && trim(filter_expand_alias($_POST['tls_detect_ports'])) == "") {
		$input_errors[] = gettext("An invalid Port alias was specified for TLS Detect Ports.");
	}

	if (is_alias($_POST['dns_parser_udp_ports']) && trim(filter_expand_alias($_POST['dns_parser_udp_ports'])) == "") {
		$input_errors[] = gettext("An invalid Port alias was specified for DNS Parser UDP Detect Ports.");
	}

	if (is_alias($_POST['dns_parser_tcp_ports']) && trim(filter_expand_alias($_POST['dns_parser_tcp_ports'])) == "") {
		$input_errors[] = gettext("An invalid Port alias was specified for DNS Parser TCP Detect Ports.");
	}

	/* if no errors write to conf */
	if (!$input_errors) {
		if ($_POST['app_layer_error_policy'] != "") { $natent['app_layer_error_policy'] = $_POST['app_layer_error_policy']; }
		if ($_POST['asn1_max_frames'] != "") { $natent['asn1_max_frames'] = $_POST['asn1_max_frames']; }else{ $natent['asn1_max_frames'] = "256"; }
		if ($_POST['dns_global_memcap'] != ""){ $natent['dns_global_memcap'] = $_POST['dns_global_memcap']; }else{ $natent['dns_global_memcap'] = "16777216"; }
		if ($_POST['dns_state_memcap'] != ""){ $natent['dns_state_memcap'] = $_POST['dns_state_memcap']; }else{ $natent['dns_state_memcap'] = "524288"; }
		if ($_POST['dns_request_flood_limit'] != ""){ $natent['dns_request_flood_limit'] = $_POST['dns_request_flood_limit']; }else{ $natent['dns_request_flood_limit'] = "500"; }
		if ($_POST['http_parser_memcap'] != ""){ $natent['http_parser_memcap'] = $_POST['http_parser_memcap']; }else{ $natent['http_parser_memcap'] = "67108864"; }

		$natent['dns_parser_udp'] = $_POST['dns_parser_udp'];
		$natent['dns_parser_tcp'] = $_POST['dns_parser_tcp'];
		$natent['dns_parser_udp_ports'] = $_POST['dns_parser_udp_ports'];
		$natent['dns_parser_tcp_ports'] = $_POST['dns_parser_tcp_ports'];
		$natent['http_parser'] = $_POST['http_parser'];
		$natent['tls_parser'] = $_POST['tls_parser'];
		$natent['tls_detect_ports'] = $_POST['tls_detect_ports'];
		$natent['tls_encrypt_handling'] = $_POST['tls_encrypt_handling'];
		$natent['tls_ja3_fingerprint'] = $_POST['tls_ja3_fingerprint'];
		$natent['smtp_parser'] = $_POST['smtp_parser'];
		$natent['smtp_parser_decode_mime'] = $_POST['smtp_parser_decode_mime'];
		$natent['smtp_parser_decode_base64'] = $_POST['smtp_parser_decode_base64'];
		$natent['smtp_parser_decode_quoted_printable'] = $_POST['smtp_parser_decode_quoted_printable'];
		$natent['smtp_parser_extract_urls'] = $_POST['smtp_parser_extract_urls'];
		$natent['smtp_parser_compute_body_md5'] = $_POST['smtp_parser_compute_body_md5'];
		$natent['imap_parser'] = $_POST['imap_parser'];
		$natent['ssh_parser'] = $_POST['ssh_parser'];
		$natent['ftp_parser'] = $_POST['ftp_parser'];
		$natent['ftp_data_parser'] = $_POST['ftp_data_parser'];
		$natent['dcerpc_parser'] = $_POST['dcerpc_parser'];
		$natent['smb_parser'] = $_POST['smb_parser'];
		$natent['msn_parser'] = $_POST['msn_parser'];
		$natent['krb5_parser'] = $_POST['krb5_parser'];
		$natent['ikev2_parser'] = $_POST['ikev2_parser'];
		$natent['nfs_parser'] = $_POST['nfs_parser'];
		$natent['tftp_parser'] = $_POST['tftp_parser'];
		$natent['ntp_parser'] = $_POST['ntp_parser'];
		$natent['dhcp_parser'] = $_POST['dhcp_parser'];
		$natent['rdp_parser'] = $_POST['rdp_parser'];
		$natent['sip_parser'] = $_POST['sip_parser'];
		$natent['snmp_parser'] = $_POST['snmp_parser'];
		$natent['http2_parser'] = $_POST['http2_parser'];
		$natent['rfb_parser'] = $_POST['rfb_parser'];
		$natent['enip_parser'] = $_POST['enip_parser'];
		$natent['mqtt_parser'] = $_POST['mqtt_parser'];
		$natent['bittorrent_parser'] = $_POST['bittorrent_parser'];
		$natent['pgsql_parser'] = $_POST['pgsql_parser'];
		$natent['quic_parser'] = $_POST['quic_parser'];

		/**************************************************/
		/* If we have a valid rule ID, save configuration */
		/* then update the suricata.conf file for this	  */
		/* interface.									  */
		/**************************************************/
		if (isset($id) && $a_nat) {
			$a_nat = $natent;
			config_set_path("installedpackages/suricata/rule/{$id}", $a_nat);
			write_config("Suricata pkg: saved updated app-layer parser configuration for " . convert_friendly_interface_to_friendly_descr($a_nat['interface']));
			$rebuild_rules = false;
			suricata_generate_yaml($natent);

			// Sync to configured CARP slaves if any are enabled
			suricata_sync_on_changes();
		}

		header( 'Expires: Sat, 26 Jul 1997 05:00:00 GMT' );
		header( 'Last-Modified: ' . gmdate( 'D, d M Y H:i:s' ) . ' GMT' );
		header( 'Cache-Control: no-store, no-cache, must-revalidate' );
		header( 'Cache-Control: post-check=0, pre-check=0', false );
		header( 'Pragma: no-cache' );
		header("Location: suricata_app_parsers.php?id=$id");
		exit;
	}
}

$if_friendly = convert_friendly_interface_to_friendly_descr($pconfig['interface']);
$pglinks = array("", "/suricata/suricata_overview.php", "/suricata/suricata_interfaces.php", "/suricata/suricata_interfaces_edit.php?id={$id}", "@self");
$pgtitle = array(gettext("Services"), gettext("Suricata"), gettext("Interfaces"), htmlspecialchars($pconfig['descr'] ?: $if_friendly), gettext("App-layer parsers"));
include_once("head.inc");
suricata_display_primary_navigation('interfaces');

/* Interface context (same block on every per-interface Suricata page): tab bar + summary */
$sf_tab = array('suricata_rulesets.php' => 'rulesets', 'suricata_rules.php' => 'rules', 'suricata_flow_stream.php' => 'flow_stream',
	'suricata_app_parsers.php' => 'app_parsers', 'suricata_define_vars.php' => 'define_vars', 'suricata_ip_reputation.php' => 'ip_reputation');
suricata_display_interface_tabs($id, $sf_tab[basename(__FILE__)] ?? '');
$sf_rule = config_get_path("installedpackages/suricata/rule/{$id}", []);
$sf_real = get_real_interface($sf_rule['interface'] ?? '');
if (($sf_rule['blockoffenders'] ?? '') != 'on') {
	$sf_mode = gettext('IDS (alerts only)');
} elseif (($sf_rule['ips_mode'] ?? '') == 'ips_mode_inline') {
	$sf_mode = gettext('IPS inline');
} else {
	$sf_mode = gettext('IPS legacy');
}
$sf_badges = array();
if (($sf_rule['enable'] ?? '') != 'on') {
	$sf_badges[] = fs_badge('disabled');
} else {
	$sf_badges[] = fs_badge('enabled');
	$sf_badges[] = ($sf_real != '' && !empty($sf_rule['uuid']) && suricata_is_running($sf_rule['uuid'], $sf_real)) ? fs_badge('up', gettext('Running')) : fs_badge('down', gettext('Stopped'));
}
fs_summary_card(array(
	'icon' => 'fa-shield-halved',
	'title' => $sf_rule['descr'] ?? '',
	'placeholder' => convert_friendly_interface_to_friendly_descr($sf_rule['interface'] ?? ''),
	'badges' => $sf_badges,
	'meta' => $sf_real,
	'label' => gettext('Interface summary'),
	'facts' => array(
		array(gettext('Interface'), ($sf_real != '') ? convert_friendly_interface_to_friendly_descr($sf_rule['interface']) . " ({$sf_real})" : '', 'empty' => gettext('Not assigned')),
		array(gettext('Mode'), $sf_mode),
		array(gettext('Home net'), $sf_rule['homelistname'] ?? '', 'empty' => 'default'),
		array(gettext('Rule sets'), '', 'chips' => array_keys(suricata_ruleset_summary($sf_rule)), 'empty' => gettext('None selected')),
	),
	'actions' => array(array(gettext('Alerts'), '/suricata/suricata_alerts.php?instance=' . (int)$id, 'fa-bell'), array(gettext('Edit interface'), '/suricata/suricata_interfaces_edit.php?id=' . (int)$id, 'fa-pencil')),
));

/* Display error message */
if ($input_errors) {
	print_input_errors($input_errors);
}

if ($savemsg) {
	/* Display save message */
	print_info_box($savemsg);
}
?>

<?php

if ($importalias) {

	print('<form action="suricata_app_parsers.php" method="post" name="iform" id="iform" class="">');
	print('<input name="id" type="hidden" value="' . $id . '"/>');
	print('<input type="hidden" name="eng_id" id="eng_id" value="' . $eng_id . '"/>');

	if ($selectalias) {
		print('<input type="hidden" name="eng_name" value="' . htmlspecialchars($eng_name) . '"/>');
		print('<input type="hidden" name="eng_bind" value="' . htmlspecialchars($eng_bind) . '"/>');
		print('<input type="hidden" name="eng_personality" value="' . htmlspecialchars($eng_personality) . '"/>');
		print('<input type="hidden" name="eng_req_body_limit" value="' . htmlspecialchars($eng_req_body_limit) . '"/>');
		print('<input type="hidden" name="eng_resp_body_limit" value="' . htmlspecialchars($eng_resp_body_limit) . '"/>');
		print('<input type="hidden" name="eng_meta_field_limit" value="' . htmlspecialchars($eng_meta_field_limit) . '"/>');
		print('<input type="hidden" name="eng_enable_double_decode_path" value="' . htmlspecialchars($eng_enable_double_decode_path) . '"/>');
		print('<input type="hidden" name="eng_enable_double_decode_query" value="' . htmlspecialchars($eng_enable_double_decode_query) . '"/>');
		print('<input type="hidden" name="eng_enable_uri_include_all" value="' . htmlspecialchars($eng_enable_uri_include_all) . '"/>');
	}

	include("/usr/local/www/suricata/suricata_import_aliases.php");
	print('</form>');

} elseif ($add_edit_libhtp_policy) {

	include("/usr/local/www/suricata/suricata_libhtp_policy_engine.php");

} else {

	$sec_state = COLLAPSIBLE | (!empty($input_errors) ? SEC_OPEN : SEC_CLOSED);
	$parser_opts = array(  "yes" => "yes", "no" => "no", "detection-only" => "detection-only" );

	print('<form action="suricata_app_parsers.php" method="post" name="iform" id="iform" class="">');
	print('<input name="id" type="hidden" value="' . (int)$id . '"/>');
	print('<input type="hidden" name="eng_id" id="eng_id" value=""/>');
?>
<style>
.sf-notes { display: flex; flex-wrap: wrap; gap: .4rem 1.5rem; margin: -.5rem 0 var(--fs-sp-5); color: var(--fs-text-muted); font-size: var(--fs-fs-sm); }
.sf-parser-legend { padding: var(--fs-sp-3) var(--fs-sp-4) 0; margin: 0; color: var(--fs-text-muted); font-size: var(--fs-fs-sm); }
</style>
<?php
	/* ---- HTTP: parser, memory and the per-server libhtp configurations */
	$section = new Form_Section('HTTP');
	$section->addInput(new Form_Select(
		'http_parser',
		'HTTP parser',
		$pconfig['http_parser'],
		$parser_opts
	))->setHelp('Default is yes.');
	$section->addInput(new Form_Input(
		'http_parser_memcap',
		'Memory cap',
		'text',
		$pconfig['http_parser_memcap']
	))->setHelp('Bytes. Default is 67,108,864 (64 MB).');
	print($section);
?>
<div class="panel panel-default fs-table">
<?php
	fs_table_toolbar(array(
		'title' => gettext('HTTP server configurations'),
		'search' => false,
		'noun' => gettext('configurations'),
		'noun_one' => gettext('configuration'),
		'actions' => '<button type="submit" name="import_alias" class="btn btn-sm btn-outline-secondary" title="' . fs_h(gettext("Import server configuration from existing Aliases")) . '" value="Import">'
		    . '<i class="fa-solid fa-upload icon-embed-btn" aria-hidden="true"></i>' . fs_h(gettext('Import')) . '</button>'
		    . '<button type="submit" name="add_libhtp_policy" class="btn btn-sm btn-primary" title="' . fs_h(gettext("Add a new server configuration")) . '" value="Add">'
		    . '<i class="fa-solid fa-plus icon-embed-btn" aria-hidden="true"></i>' . fs_h(gettext('Add server')) . '</button>',
	));
?>
	<div class="panel-body table-responsive">
		<table class="table table-hover">
			<thead>
				<tr>
					<th><?=gettext("Name")?></th>
					<th><?=gettext("Bind to")?></th>
					<th><?=gettext("Personality")?></th>
					<th class="fs-col-actions"><span class="visually-hidden"><?=gettext('Actions')?></span></th>
				</tr>
			</thead>
			<tbody>
<?php foreach ($pconfig['libhtp_policy']['item'] as $f => $v): ?>
				<tr>
					<td><?=htmlspecialchars(gettext($v['name']))?></td>
					<td><?=($v['bind_to'] == 'all') ? '<span class="fs-chip">' . gettext('All hosts') . '</span>' : '<span class="fs-chip fs-chip--mono">' . htmlspecialchars($v['bind_to']) . '</span>'?></td>
					<td><span class="fs-chip fs-chip--strong"><?=htmlspecialchars($v['personality'] ?? '')?></span></td>
					<td class="fs-col-actions"><div class="fs-actions">
						<button type="submit" name="edit_libhtp_policy" value="Edit" class="fs-action" data-sf-eng="<?=(int)$f?>" title="<?=fs_h(sprintf(gettext('Edit %s'), $v['name']))?>" aria-label="<?=fs_h(sprintf(gettext('Edit %s'), $v['name']))?>"><i class="fa-solid fa-pencil" aria-hidden="true"></i></button>
<?php if ($v['bind_to'] != "all") : ?>
						<button type="submit" name="del_libhtp_policy" value="Delete" class="fs-action fs-action--delete" data-sf-eng="<?=(int)$f?>" title="<?=fs_h(sprintf(gettext('Delete %s'), $v['name']))?>" aria-label="<?=fs_h(sprintf(gettext('Delete %s'), $v['name']))?>"
							data-fs-confirm="<?=fs_h(sprintf(gettext('Delete HTTP server configuration “%s”?'), $v['name']))?>" data-fs-confirm-action="<?=gettext('Delete')?>"><i class="fa-solid fa-trash-can" aria-hidden="true"></i></button>
<?php else : ?>
						<span class="fs-action" title="<?=gettext("The default configuration cannot be deleted")?>" aria-hidden="true"><i class="fa-solid fa-lock fs-muted"></i></span>
<?php endif ?>
					</div></td>
				</tr>
<?php endforeach; ?>
			</tbody>
		</table>
	</div>
</div>
<?php
	/* ---- DNS */
	$section = new Form_Section('DNS');
	$section->addInput(new Form_Select(
		'dns_parser_udp',
		'UDP parser',
		$pconfig['dns_parser_udp'],
		$parser_opts
	))->setHelp('Default is yes.');
	$section->addInput(new Form_Select(
		'dns_parser_tcp',
		'TCP parser',
		$pconfig['dns_parser_tcp'],
		$parser_opts
	))->setHelp('Default is yes.');
	$section->addInput(new Form_Input(
		'dns_parser_udp_ports',
		'UDP detection ports',
		'text',
		$pconfig['dns_parser_udp_ports']
	))->setHelp('Comma-separated ports or a port alias. Default is 53.');
	$section->addInput(new Form_Input(
		'dns_parser_tcp_ports',
		'TCP detection ports',
		'text',
		$pconfig['dns_parser_tcp_ports']
	))->setHelp('Comma-separated ports or a port alias. Default is 53.');
	$section->addInput(new Form_Input(
		'dns_global_memcap',
		'Global memory cap',
		'text',
		$pconfig['dns_global_memcap']
	))->setHelp('Bytes. Default is 16,777,216 (16 MB).');
	$section->addInput(new Form_Input(
		'dns_state_memcap',
		'Flow/state memory cap',
		'text',
		$pconfig['dns_state_memcap']
	))->setHelp('Bytes per flow. Default is 524,288 (512 KB).');
	$section->addInput(new Form_Input(
		'dns_request_flood_limit',
		'Request flood limit',
		'text',
		$pconfig['dns_request_flood_limit']
	))->setHelp('Unanswered requests that count as a flood (app-layer-event:dns.flooded). Default is 500.');
	print($section);

	/* ---- TLS */
	$section = new Form_Section('TLS');
	$section->addInput(new Form_Select(
		'tls_parser',
		'TLS parser',
		$pconfig['tls_parser'],
		$parser_opts
	))->setHelp('Default is yes.');
	$section->addInput(new Form_Input(
		'tls_detect_ports',
		'Detection ports',
		'text',
		$pconfig['tls_detect_ports']
	))->setHelp('Comma-separated ports or a port alias, e.g. 443, 8443. Default is 443.');
	$section->addInput(new Form_Select(
		'tls_encrypt_handling',
		'Encryption handling',
		$pconfig['tls_encrypt_handling'],
		array(  "default" => "Default", "bypass" => "Bypass", "full" => "Full" )
	))->setHelp('Once encryption starts: Default keeps checking the session for anomalies and tls_* keywords, Bypass stops processing the flow (fastest), Full keeps full inspection including content signatures.');
	$section->addInput(new Form_Checkbox(
		'tls_ja3_fingerprint',
		'JA3/JA3S fingerprint',
		'Generate JA3/JA3S fingerprints from the client hello. Default is off; rules that need it still turn it on.',
		$pconfig['tls_ja3_fingerprint'] == 'on' ? true:false,
		'on'
	));
	print($section);

	/* ---- SMTP */
	$section = new Form_Section('SMTP');
	$section->addInput(new Form_Select(
		'smtp_parser',
		'SMTP parser',
		$pconfig['smtp_parser'],
		$parser_opts
	))->setHelp('Default is yes.');
	$section->addInput(new Form_Checkbox(
		'smtp_parser_decode_mime',
		'MIME decoding',
		'Decode MIME messages of SMTP transactions. Can use a lot of resources. Default is off.',
		$pconfig['smtp_parser_decode_mime'] == 'on' ? true:false,
		'on'
	));
	$section->addInput(new Form_Checkbox(
		'smtp_parser_decode_base64',
		'Base64 decoding',
		'Decode Base64 MIME entity bodies. Default is on.',
		$pconfig['smtp_parser_decode_base64'] == 'on' ? true:false,
		'on'
	));
	$section->addInput(new Form_Checkbox(
		'smtp_parser_decode_quoted_printable',
		'Quoted-printable decoding',
		'Decode quoted-printable MIME entity bodies. Default is on.',
		$pconfig['smtp_parser_decode_quoted_printable'] == 'on' ? true:false,
		'on'
	));
	$section->addInput(new Form_Checkbox(
		'smtp_parser_extract_urls',
		'URL extraction',
		'Extract URLs and keep them in the state data. Default is on.',
		$pconfig['smtp_parser_extract_urls'] == 'on' ? true:false,
		'on'
	));
	$section->addInput(new Form_Checkbox(
		'smtp_parser_compute_body_md5',
		'Body MD5',
		'Compute the MD5 of the mail body so it can be journalized. Default is off.',
		$pconfig['smtp_parser_compute_body_md5'] == 'on' ? true:false,
		'on'
	));
	print($section);

	/* ---- FTP */
	$section = new Form_Section('FTP');
	$section->addInput(new Form_Select(
		'ftp_parser',
		'FTP parser',
		$pconfig['ftp_parser'],
		$parser_opts
	))->setHelp('Default is yes.');
	$section->addInput(new Form_Checkbox(
		'ftp_data_parser',
		'FTP-DATA parser',
		'Process FTP-DATA transfers. File-Store needs this to save FTP uploads and downloads.',
		$pconfig['ftp_data_parser'] == 'on' ? true:false,
		'on'
	));
	print($section);

	/* ---- Other protocols: one select each, collapsed */
	$section = new Form_Section('Other protocols', 'sf-other-parsers', $sec_state);
	foreach (array(
		array('bittorrent_parser', 'BitTorrent-DHT', 'yes'),
		array('dcerpc_parser', 'DCERPC', 'yes'),
		array('dhcp_parser', 'DHCP', 'yes'),
		array('enip_parser', 'ENIP', 'yes'),
		array('http2_parser', 'HTTP/2', 'yes'),
		array('ikev2_parser', 'IKE', 'yes'),
		array('imap_parser', 'IMAP', 'detection-only'),
		array('krb5_parser', 'Kerberos', 'yes'),
		array('mqtt_parser', 'MQTT', 'yes'),
		array('msn_parser', 'MSN', 'detection-only'),
		array('nfs_parser', 'NFS', 'yes'),
		array('ntp_parser', 'NTP', 'yes'),
		array('pgsql_parser', 'PostgreSQL', 'no'),
		array('quic_parser', 'QUICv1', 'yes'),
		array('rdp_parser', 'RDP', 'yes'),
		array('rfb_parser', 'RFB', 'yes'),
		array('ssh_parser', 'SSH', 'yes'),
		array('sip_parser', 'SIP', 'yes'),
		array('smb_parser', 'SMB', 'yes'),
		array('snmp_parser', 'SNMP', 'yes'),
		array('telnet_parser', 'Telnet', 'yes'),
		array('tftp_parser', 'TFTP', 'yes'),
	) as $p) {
		$section->addInput(new Form_Select(
			$p[0],
			$p[1],
			$pconfig[$p[0]],
			$parser_opts
		))->setHelp(sprintf(gettext('Default is %s.'), $p[2]));
	}
	print($section);

	/* ---- Error handling and limits */
	$section = new Form_Section('Error policy and limits', 'sf-parser-advanced', $sec_state);
	$section->addInput(new Form_Select(
		'app_layer_error_policy',
		'Parser exception policy',
		$pconfig['app_layer_error_policy'],
		array( "drop-flow" => "Drop Flow", "pass-flow" => "Pass Flow", "bypass" => "Bypass", "drop-packet" => "Drop Packet",
			   "pass-packet" => "Pass Packet", "reject" => "Reject", "ignore" => "Ignore" )
	))->setHelp('What to do when a parser reaches an error state. Default is Ignore. Drop Flow drops the flow; Drop Packet the packet; Reject also rejects it; Bypass stops inspecting the flow; Pass Flow and Pass Packet turn off detection but keep parsing and logging.');
	$section->addInput(new Form_Input(
		'asn1_max_frames',
		'ASN.1 max frames',
		'text',
		$pconfig['asn1_max_frames']
	))->setHelp('Most ASN.1 frames to decode (X.400, LDAP, H.323, SNMP …). Default is 256.');
	print($section);
?>
	<div class="sf-notes">
		<span><?=gettext('Parser values: yes enables detection and parsing, detection-only detects the protocol without parsing it, no turns both off.')?></span>
	</div>

	<div class="fs-actionbar">
		<button type="submit" id="save" name="save" value="Save" class="btn btn-primary" title="<?=gettext('Save App Parsers settings');?>"><i class="fa-solid fa-floppy-disk icon-embed-btn" aria-hidden="true"></i><?=gettext('Save');?></button>
	</div>

</form>

<?php } ?>

<script type="text/javascript">
//<![CDATA[
events.push(function(){

	// Edit / delete an HTTP server configuration: remember which one before the form posts
	document.addEventListener('click', function(e) {
		var btn = e.target.closest('button[data-sf-eng]');
		if (!btn || e.defaultPrevented) {
			return;
		}
		document.getElementById('eng_id').value = btn.getAttribute('data-sf-eng');
	});

	function toggle_smtp_mime_decoding() {
		if ($('#smtp_parser').val() == 'yes') {
			hideCheckbox('smtp_parser_decode_mime', false);
			var hide = ! ($('#smtp_parser_decode_mime').prop('checked'));
			hideCheckbox('smtp_parser_decode_base64',hide);
			hideCheckbox('smtp_parser_decode_quoted_printable',hide);
			hideCheckbox('smtp_parser_extract_urls',hide);
			hideCheckbox('smtp_parser_compute_body_md5',hide);
		}
		else {
			hideCheckbox('smtp_parser_decode_mime', true);
			hideCheckbox('smtp_parser_decode_base64',true);
			hideCheckbox('smtp_parser_decode_quoted_printable',true);
			hideCheckbox('smtp_parser_extract_urls',true);
			hideCheckbox('smtp_parser_compute_body_md5',true);
		}
	}

	function toggle_tls_parser() {
		if ($('#tls_parser').val() == 'yes') {
			hideInput('tls_detect_ports', false);
			hideSelect('tls_encrypt_handling', false);
			hideCheckbox('tls_ja3_fingerprint', false);
		}
		else {
			hideInput('tls_detect_ports', true);
			hideSelect('tls_encrypt_handling', true);
			hideCheckbox('tls_ja3_fingerprint', true);
		}
	}

	// ---------- Click checkbox handlers ---------------------------------------------------------
	// When form control id is clicked, disable/enable it's associated form controls

	$('#smtp_parser_decode_mime').click(function() {
		toggle_smtp_mime_decoding();
	});

	// ---------- Selection control handlers ---------------------------------------------------------
	// When form control selection changes, disable/enable it's associated form controls
	$('#smtp_parser').on('change', function() {
		toggle_smtp_mime_decoding();
	});

	$('#tls_parser').on('change', function() {
		toggle_tls_parser();
	});

	// ---------- On initial page load ------------------------------------------------------------
	var portsarray = <?= json_encode(get_alias_list(array("port"))) ?>;

	$('#tls_detect_ports').autocomplete({
		source: portsarray
	});
	$('#dns_parser_udp_ports').autocomplete({
		source: portsarray
	});
	$('#dns_parser_tcp_ports').autocomplete({
		source: portsarray
	});

	toggle_smtp_mime_decoding();
	toggle_tls_parser();

});
//]]>
</script>

<?php include("foot.inc"); ?>
