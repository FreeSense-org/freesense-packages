<?php
/*
 * suricata_flow_stream.php
 *
 * part of FreeSense (https://www.freesense.org)
 * Copyright (c) 2004-2026 The FreeSense Project
 * Copyright (c) 2003-2004 Manuel Kasper
 * Copyright (c) 2005 Bill Marquette
 * Copyright (c) 2009 Robert Zelaya Sr. Developer
 * Copyright (c) 2023 Bill Meeks
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
	$id=0;

$a_aliases = config_get_path('aliases/alias', []);
$a_nat = config_get_path("installedpackages/suricata/rule/{$id}", []);
$host_os_policy_engine_next_id = count(array_get_path($a_nat, 'host_os_policy/item', []));

// Build a lookup array of currently used engine 'bind_to' Aliases
// so we can screen matching Alias names from the list.
$used = array();
foreach (array_get_path($a_nat, 'host_os_policy/item', []) as $v)
	$used[$v['bind_to']] = true;

$pconfig = array();
if (isset($id) && !empty($a_nat)) {
	/* Get current values from config for page form fields */
	$pconfig = $a_nat;
	if (empty($pconfig['stream_memcap_policy']))
		$pconfig['stream_memcap_policy'] = "ignore";
	if (empty($pconfig['midstream_policy']))
		$pconfig['midstream_policy'] = "ignore";
	if (empty($pconfig['defrag_memcap_policy']))
		$pconfig['defrag_memcap_policy'] = "ignore";
	if (empty($pconfig['reassembly_memcap_policy']))
		$pconfig['reassembly_memcap_policy'] = "ignore";
	if (empty($pconfig['flow_memcap_policy']))
		$pconfig['flow_memcap_policy'] = "ignore";
	if (empty($pconfig['stream_checksum_validation']))
		$pconfig['stream_checksum_validation'] = "on";

	// See if Host-OS policy engine array is configured and use
	// it; otherwise create a default engine configuration.
	if (empty($pconfig['host_os_policy']['item'])) {
		$default = array( "name" => "default", "bind_to" => "all", "policy" => "bsd" );
		$pconfig['host_os_policy']['item'] = array();
		$pconfig['host_os_policy']['item'][] = $default;
		array_init_path($a_nat, 'host_os_policy/item');
		$a_nat['host_os_policy']['item'][] = $default;
		config_set_path("installedpackages/suricata/rule/{$id}", $a_nat);
		write_config("Suricata pkg: saved new default Host_OS_Policy engine.");
		$host_os_policy_engine_next_id++;
	}
	else
		$pconfig['host_os_policy'] = $a_nat['host_os_policy'];
}

// Check for "import or select alias mode" and set flags if TRUE.
// "selectalias", when true, displays radio buttons to limit
// multiple selections.
if ($_POST['import_alias']) {
	$eng_id = $host_os_policy_engine_next_id;
	$importalias = true;
	$selectalias = false;
	$title = "Host Operating System Policy";
}
elseif ($_POST['select_alias']) {
	$importalias = true;
	$selectalias = true;
	$title = "Host Operating System Policy";

	// Preserve current OS Policy Engine settings
	$eng_id = $_POST['eng_id'];
	$eng_name = $_POST['policy_name'];
	$eng_bind = $_POST['policy_bind_to'];
	$eng_policy = $_POST['policy'];
	$mode = "add_edit_os_policy";
}

if ($_POST['save_os_policy']) {
	if ($_POST['eng_id'] != "") {
		$eng_id = $_POST['eng_id'];

		// Grab all the POST values and save in new temp array
		$engine = array();
		$policy_name = trim($_POST['policy_name']);
		if ($policy_name) {
			$engine['name'] = $policy_name;
		}
		else {
			$input_errors[] = gettext("The 'Policy Name' value cannot be blank.");
			$add_edit_os_policy = true;
		}
		if ($_POST['policy_bind_to']) {
			if (is_alias($_POST['policy_bind_to']))
				$engine['bind_to'] = $_POST['policy_bind_to'];
			elseif (strtolower(trim($_POST['policy_bind_to'])) == "all")
				$engine['bind_to'] = "all";
			else {
				$input_errors[] = gettext("You must provide a valid Alias or the reserved keyword 'all' for the 'Bind-To IP Address' value.");
				$add_edit_os_policy = true;
			}
		}
		else {
			$input_errors[] = gettext("The 'Bind-To IP Address' value cannot be blank.  Provide a valid Alias or the reserved keyword 'all'.");
			$add_edit_os_policy = true;
		}

		if ($_POST['policy']) { $engine['policy'] = $_POST['policy']; } else { $engine['policy'] = "bsd"; }

		// Can only have one "all" Bind_To address
		if ($engine['bind_to'] == "all" && $engine['name'] != "default") {
			$input_errors[] = gettext("Only one default OS-Policy Engine can be bound to all addresses.");
			$add_edit_os_policy = true;
			$pengcfg = $engine;
		}

		// if no errors, write new entry to conf
		if (!$input_errors) {
			if (isset($eng_id) && array_get_path($a_nat, "host_os_policy/item/{$eng_id}")) {
				$a_nat['host_os_policy']['item'][$eng_id] = $engine;
			}
			else
				$a_nat['host_os_policy']['item'][] = $engine;

			/* Reorder the engine array to ensure the */
			/* 'bind_to=all' entry is at the bottom   */
			/* if it contains more than one entry.	*/
			if (count(array_get_path($a_nat, 'host_os_policy/item', [])) > 1) {
				$i = -1;
				foreach (array_get_path($a_nat, 'host_os_policy/item', []) as $f => $v) {
					if ($v['bind_to'] == "all") {
						$i = $f;
						break;
					}
				}
				/* Only relocate the entry if we  */
				/* found it, and it's not already */
				/* at the end.					*/
				if ($i > -1 && ($i < (count(array_get_path($a_nat, 'host_os_policy/item', [])) - 1))) {
					$tmp = array_get_path($a_nat, "host_os_policy/item/{$i}", []);
					array_del_path($a_nat, "host_os_policy/item/{$i}");
					$a_nat['host_os_policy']['item'][] = $tmp;
				}
			}

			// Now write the new engine array to conf
			config_set_path("installedpackages/suricata/rule/{$id}", $a_nat);
			write_config("Suricata pkg: saved new Host_OS_Policy engine.");
			header( 'Expires: Sat, 26 Jul 1997 05:00:00 GMT' );
			header( 'Last-Modified: ' . gmdate( 'D, d M Y H:i:s' ) . ' GMT' );
			header( 'Cache-Control: no-store, no-cache, must-revalidate' );
			header( 'Cache-Control: post-check=0, pre-check=0', false );
			header( 'Pragma: no-cache' );
			header("Location: suricata_flow_stream.php?id=$id");
			exit;
		}
	}
}
elseif ($_POST['add_os_policy']) {
	$add_edit_os_policy = true;
	$pengcfg = array( "name" => "engine_{$host_os_policy_engine_next_id}", "bind_to" => "", "policy" => "bsd" );
	$eng_id = $host_os_policy_engine_next_id;
}
elseif ($_POST['edit_os_policy']) {
	if ($_POST['eng_id'] != "") {
		$add_edit_os_policy = true;
		$eng_id = $_POST['eng_id'];
		$pengcfg = $a_nat['host_os_policy']['item'][$eng_id];
	}
}
elseif ($_POST['del_os_policy']) {
	$natent = array();
	$natent = $pconfig;

	if ($_POST['eng_id'] != "") {
		array_del_path($natent, "host_os_policy/item/{$_POST['eng_id']}");
		$pconfig = $natent;
	}
	if (isset($id) && !empty($a_nat)) {
		$a_nat = $natent;
		config_set_path("installedpackages/suricata/rule/{$id}", $a_nat);
		write_config("Suricata pkg: deleted a Host_OS_Policy engine.");
	}
	header( 'Expires: Sat, 26 Jul 1997 05:00:00 GMT' );
	header( 'Last-Modified: ' . gmdate( 'D, d M Y H:i:s' ) . ' GMT' );
	header( 'Cache-Control: no-store, no-cache, must-revalidate' );
	header( 'Cache-Control: post-check=0, pre-check=0', false );
	header( 'Pragma: no-cache' );
	header("Location: suricata_flow_stream.php?id=$id");
	exit;
}
elseif ($_POST['cancel_os_policy']) {
	$add_edit_os_policy = false;
}
elseif ($_POST['ResetAll']) {

	/* Reset all the settings to defaults */
	$pconfig['defrag_memcap_policy'] = "ignore";
	$pconfig['ip_max_frags'] = "65535";
	$pconfig['ip_frag_timeout'] = "60";
	$pconfig['frag_memcap'] = '33554432';
	$pconfig['ip_max_trackers'] = '65535';
	$pconfig['frag_hash_size'] = '65536';

	$pconfig['flow_memcap'] = '134217728';
	$pconfig['flow_memcap_policy'] = 'ignore';
	$pconfig['flow_prealloc'] = '10000';
	$pconfig['flow_hash_size'] = '65536';
	$pconfig['flow_emerg_recovery'] = '30';
	$pconfig['flow_prune'] = '5';

	$pconfig['flow_tcp_new_timeout'] = '60';
	$pconfig['flow_tcp_established_timeout'] = '3600';
	$pconfig['flow_tcp_closed_timeout'] = '120';
	$pconfig['flow_tcp_emerg_new_timeout'] = '10';
	$pconfig['flow_tcp_emerg_established_timeout'] = '300';
	$pconfig['flow_tcp_emerg_closed_timeout'] = '20';

	$pconfig['flow_udp_new_timeout'] = '30';
	$pconfig['flow_udp_established_timeout'] = '300';
	$pconfig['flow_udp_emerg_new_timeout'] = '10';
	$pconfig['flow_udp_emerg_established_timeout'] = '100';

	$pconfig['flow_icmp_new_timeout'] = '30';
	$pconfig['flow_icmp_established_timeout'] = '300';
	$pconfig['flow_icmp_emerg_new_timeout'] = '10';
	$pconfig['flow_icmp_emerg_established_timeout'] = '100';

	// The default 'stream_memcap' value must be calculated as follows:
	// 216 * prealloc_sessions * number of threads = memory use in bytes
	// 128 MB is a decent all-around default, but some setups need more.
	$pconfig['stream_prealloc_sessions'] = '32768';
	$pconfig['stream_memcap'] = '268435456';
	$pconfig['reassembly_memcap'] = '134217728';
	$pconfig['reassembly_depth'] = '1048576';
	$pconfig['reassembly_to_server_chunk'] = '2560';
	$pconfig['reassembly_to_client_chunk'] = '2560';
	$pconfig['enable_midstream_sessions'] = 'off';
	$pconfig['stream_memcap_policy'] = 'ignore';
	$pconfig['midstream_policy'] = 'ignore';
	$pconfig['reassembly_memcap_policy'] = 'ignore';
	$pconfig['enable_async_sessions'] = 'off';
	$pconfig['max_synack_queued'] = '5';
	$pconfig['stream_bypass'] = "no";
	$pconfig['stream_drop_invalid'] = "no";

	/* Log a message at the top of the page to inform the user */
	$savemsg = gettext("All flow and stream settings have been reset to their defaults.  Click APPLY to save the changes.");
}
elseif ($_POST['save'] || $_POST['apply']) {
	$natent = array();
	$natent = $pconfig;

	// TODO: validate input values

	/* if no errors write to conf */
	if (!$input_errors) {
		if ($_POST['ip_max_frags'] != "") { $natent['ip_max_frags'] = $_POST['ip_max_frags']; }else{ $natent['ip_max_frags'] = "65535"; }
		if ($_POST['ip_frag_timeout'] != "") { $natent['ip_frag_timeout'] = $_POST['ip_frag_timeout']; }else{ $natent['ip_frag_timeout'] = "60"; }
		if ($_POST['frag_memcap'] != "") { $natent['frag_memcap'] = $_POST['frag_memcap']; }else{ $natent['frag_memcap'] = "33554432"; }
		if ($_POST['defrag_memcap_policy']) { $natent['defrag_memcap_policy'] = $_POST['defrag_memcap_policy']; }
		if ($_POST['ip_max_trackers'] != "") { $natent['ip_max_trackers'] = $_POST['ip_max_trackers']; }else{ $natent['ip_max_trackers'] = "65535"; }
		if ($_POST['frag_hash_size'] != "") { $natent['frag_hash_size'] = $_POST['frag_hash_size']; }else{ $natent['frag_hash_size'] = "65536"; }
		if ($_POST['flow_memcap'] != "") { $natent['flow_memcap'] = $_POST['flow_memcap']; }else{ $natent['flow_memcap'] = "134217728"; }
		if ($_POST['flow_memcap_policy']) { $natent['flow_memcap_policy'] = $_POST['flow_memcap_policy']; }
		if ($_POST['flow_prealloc'] != "") { $natent['flow_prealloc'] = $_POST['flow_prealloc']; }else{ $natent['flow_prealloc'] = "10000"; }
		if ($_POST['flow_hash_size'] != "") { $natent['flow_hash_size'] = $_POST['flow_hash_size']; }else{ $natent['flow_hash_size'] = "65536"; }
		if ($_POST['flow_emerg_recovery'] != "") { $natent['flow_emerg_recovery'] = $_POST['flow_emerg_recovery']; }else{ $natent['flow_emerg_recovery'] = "30"; }
		if ($_POST['flow_prune'] != "") { $natent['flow_prune'] = $_POST['flow_prune']; }else{ $natent['flow_prune'] = "5"; }

		if ($_POST['flow_tcp_new_timeout'] != "") { $natent['flow_tcp_new_timeout'] = $_POST['flow_tcp_new_timeout']; }else{ $natent['flow_tcp_new_timeout'] = "60"; }
		if ($_POST['flow_tcp_established_timeout'] != "") { $natent['flow_tcp_established_timeout'] = $_POST['flow_tcp_established_timeout']; }else{ $natent['flow_tcp_established_timeout'] = "3600"; }
		if ($_POST['flow_tcp_closed_timeout'] != "") { $natent['flow_tcp_closed_timeout'] = $_POST['flow_tcp_closed_timeout']; }else{ $natent['flow_tcp_closed_timeout'] = "120"; }
		if ($_POST['flow_tcp_emerg_new_timeout'] != "") { $natent['flow_tcp_emerg_new_timeout'] = $_POST['flow_tcp_emerg_new_timeout']; }else{ $natent['flow_tcp_emerg_new_timeout'] = "10"; }
		if ($_POST['flow_tcp_emerg_established_timeout'] != "") { $natent['flow_tcp_emerg_established_timeout'] = $_POST['flow_tcp_emerg_established_timeout']; }else{ $natent['flow_tcp_emerg_established_timeout'] = "300"; }
		if ($_POST['flow_tcp_emerg_closed_timeout'] != "") { $natent['flow_tcp_emerg_closed_timeout'] = $_POST['flow_tcp_emerg_closed_timeout']; }else{ $natent['flow_tcp_emerg_closed_timeout'] = "20"; }

		if ($_POST['flow_udp_new_timeout'] != "") { $natent['flow_udp_new_timeout'] = $_POST['flow_udp_new_timeout']; }else{ $natent['flow_udp_new_timeout'] = "30"; }
		if ($_POST['flow_udp_established_timeout'] != "") { $natent['flow_udp_established_timeout'] = $_POST['flow_udp_established_timeout']; }else{ $natent['flow_udp_established_timeout'] = "300"; }
		if ($_POST['flow_udp_emerg_new_timeout'] != "") { $natent['flow_udp_emerg_new_timeout'] = $_POST['flow_udp_emerg_new_timeout']; }else{ $natent['flow_udp_emerg_new_timeout'] = "10"; }
		if ($_POST['flow_udp_emerg_established_timeout'] != "") { $natent['flow_udp_emerg_established_timeout'] = $_POST['flow_udp_emerg_established_timeout']; }else{ $natent['flow_udp_emerg_established_timeout'] = "100"; }

		if ($_POST['flow_icmp_new_timeout'] != "") { $natent['flow_icmp_new_timeout'] = $_POST['flow_icmp_new_timeout']; }else{ $natent['flow_icmp_new_timeout'] = "30"; }
		if ($_POST['flow_icmp_established_timeout'] != "") { $natent['flow_icmp_established_timeout'] = $_POST['flow_icmp_established_timeout']; }else{ $natent['flow_icmp_established_timeout'] = "300"; }
		if ($_POST['flow_icmp_emerg_new_timeout'] != "") { $natent['flow_icmp_emerg_new_timeout'] = $_POST['flow_icmp_emerg_new_timeout']; }else{ $natent['flow_icmp_emerg_new_timeout'] = "10"; }
		if ($_POST['flow_icmp_emerg_established_timeout'] != "") { $natent['flow_icmp_emerg_established_timeout'] = $_POST['flow_icmp_emerg_established_timeout']; }else{ $natent['flow_icmp_emerg_established_timeout'] = "100"; }

		if ($_POST['stream_memcap'] != "") { $natent['stream_memcap'] = $_POST['stream_memcap']; }else{ $natent['stream_memcap'] = "268435456"; }
		if ($_POST['stream_memcap_policy']) { $natent['stream_memcap_policy'] = $_POST['stream_memcap_policy']; }
		if ($_POST['stream_prealloc_sessions'] != "") { $natent['stream_prealloc_sessions'] = $_POST['stream_prealloc_sessions']; }else{ $natent['stream_prealloc_sessions'] = "32768"; }
		if ($_POST['enable_midstream_sessions'] == "on") { $natent['enable_midstream_sessions'] = 'on'; }else{ $natent['enable_midstream_sessions'] = 'off'; }
		if ($_POST['stream_checksum_validation'] == "on") { $natent['stream_checksum_validation'] = 'on'; }else{ $natent['stream_checksum_validation'] = 'off'; }
		if ($_POST['midstream_policy']) { $natent['midstream_policy'] = $_POST['midstream_policy']; }
		if ($_POST['enable_async_sessions'] == "on") { $natent['enable_async_sessions'] = 'on'; }else{ $natent['enable_async_sessions'] = 'off'; }
		if ($_POST['stream_bypass'] == "on") { $natent['stream_bypass'] = 'on'; }else{ $natent['stream_bypass'] = 'no'; }
		if ($_POST['stream_drop_invalid'] == "on") { $natent['stream_drop_invalid'] = 'on'; }else{ $natent['stream_drop_invalid'] = 'no'; }
		if ($_POST['reassembly_memcap'] != "") { $natent['reassembly_memcap'] = $_POST['reassembly_memcap']; }else{ $natent['reassembly_memcap'] = "134217728"; }
		if ($_POST['reassembly_memcap_policy']) { $natent['reassembly_memcap_policy'] = $_POST['reassembly_memcap_policy']; }
		if ($_POST['reassembly_depth'] != "") { $natent['reassembly_depth'] = $_POST['reassembly_depth']; }else{ $natent['reassembly_depth'] = "1048576"; }
		if ($_POST['reassembly_to_server_chunk'] != "") { $natent['reassembly_to_server_chunk'] = $_POST['reassembly_to_server_chunk']; }else{ $natent['reassembly_to_server_chunk'] = "2560"; }
		if ($_POST['reassembly_to_client_chunk'] != "") { $natent['reassembly_to_client_chunk'] = $_POST['reassembly_to_client_chunk']; }else{ $natent['reassembly_to_client_chunk'] = "2560"; }
		if ($_POST['max_synack_queued'] != "") { $natent['max_synack_queued'] = $_POST['max_synack_queued']; }else{ $natent['max_synack_queued'] = "5"; }

		/**************************************************/
		/* If we have a valid rule ID, save configuration */
		/* then update the suricata.conf file for this	*/
		/* interface.									 */
		/**************************************************/
		if (isset($id) && !empty($a_nat)) {
			$a_nat = $natent;
			config_set_path("installedpackages/suricata/rule/{$id}", $a_nat);
			write_config("Suricata pkg: saved flow or stream configuration changes.");
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
		header("Location: suricata_flow_stream.php?id=$id");
		exit;
	}
}
elseif ($_POST['save_import_alias']) {
	// If saving out of "select alias" mode,
	// then return to Host OS Policy Engine edit
	// page.
	if ($_POST['mode'] =='add_edit_os_policy') {
		$pengcfg = array();
		$eng_id = $_POST['eng_id'];
		$pengcfg['name'] = $_POST['eng_name'];
		$pengcfg['bind_to'] = $_POST['eng_bind'];
		$pengcfg['policy'] = $_POST['eng_policy'];
		$add_edit_os_policy = true;
		$mode = "add_edit_os_policy";

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
			$eng_policy = $_POST['eng_policy'];
		}
	}
	else {
		// Assume we are importing one or more aliases
		// for use in new Host OS Policy engines.
		$engine = array( "name" => "", "bind_to" => "", "policy" => "bsd" );

		// See if anything was checked to import
		if (is_array($_POST['aliastoimport']) && count($_POST['aliastoimport']) > 0) {
			foreach ($_POST['aliastoimport'] as $item) {
				$engine['name'] = strtolower($item);
				$engine['bind_to'] = $item;
				$a_nat['host_os_policy']['item'][] = $engine;
			}
		}
		else {
			$input_errors[] = gettext("No entries were selected for import.  Please select one or more Aliases for import and click SAVE.");
			$importalias = true;
		}

		// if no errors, write new entry to conf
		if (!$input_errors) {
			// Reorder the engine array to ensure the
			// 'bind_to=all' entry is at the bottom if
			// the array contains more than one entry.
			if (count($a_nat['host_os_policy']['item']) > 1) {
				$i = -1;
				foreach ($a_nat['host_os_policy']['item'] as $f => $v) {
					if ($v['bind_to'] == "all") {
						$i = $f;
						break;
					}
				}
				// Only relocate the entry if we
				// found it, and it's not already
				// at the end.
				if ($i > -1 && ($i < (count($a_nat['host_os_policy']['item']) - 1))) {
					$tmp = $a_nat['host_os_policy']['item'][$i];
					unset($a_nat['host_os_policy']['item'][$i]);
					$a_nat['host_os_policy']['item'][] = $tmp;
				}
				$pconfig['host_os_policy']['item'] = $a_nat['host_os_policy']['item'];
			}

			// Write the new engine array to config file
			config_set_path("installedpackages/suricata/rule/{$id}", $a_nat);
			write_config("Suricata pkg: saved Host_OS_Policy engine created from a defined firewall alias.");
			$importalias = false;
			$selectalias = false;
			header( 'Expires: Sat, 26 Jul 1997 05:00:00 GMT' );
			header( 'Last-Modified: ' . gmdate( 'D, d M Y H:i:s' ) . ' GMT' );
			header( 'Cache-Control: no-store, no-cache, must-revalidate' );
			header( 'Cache-Control: post-check=0, pre-check=0', false );
			header( 'Pragma: no-cache' );
			header("Location: suricata_flow_stream.php?id=$id");
			exit;
		}
	}
}
elseif ($_POST['cancel_import_alias']) {
	$importalias = false;
	$selectalias = false;
	$eng_id = $_POST['eng_id'];

	// If cancelling out of "select alias" mode,
	// then return to Host OS Policy Engine edit
	// page.
	if ($_POST['mode'] == 'add_edit_os_policy') {
		$pengcfg = array();
		$pengcfg['name'] = $_POST['eng_name'];
		$pengcfg['bind_to'] = $_POST['eng_bind'];
		$pengcfg['policy'] = $_POST['eng_policy'];
		$add_edit_os_policy = true;
	}
}

$if_friendly = convert_friendly_interface_to_friendly_descr($pconfig['interface']);
$pglinks = array("", "/suricata/suricata_overview.php", "/suricata/suricata_interfaces.php", "/suricata/suricata_interfaces_edit.php?id={$id}", "@self");
$pgtitle = array(gettext("Services"), gettext("Suricata"), gettext("Interfaces"), htmlspecialchars($pconfig['descr'] ?: $if_friendly), gettext("Flow and stream"));

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
	print_input_errors($input_errors); // TODO: add checks
}

if ($savemsg) {
	/* Display save message */
	print_info_box($savemsg);
}
?>

<?php
	if ($importalias) {

		print('<form action="suricata_flow_stream.php" method="post" name="iform" id="iform" class="">');
		print('<input type="hidden" name="eng_id" id="eng_id" value="' . htmlspecialchars($eng_id) . '"/>');
		print('<input type="hidden" name="id" id="id" value="' . htmlspecialchars($id) . '"/>');

		if ($selectalias) {
			print('<input type="hidden" name="eng_name" value="' . htmlspecialchars($eng_name) . '"/>');
			print('<input type="hidden" name="eng_bind" value="' . htmlspecialchars($eng_bind) . '"/>');
			print('<input type="hidden" name="eng_policy" value="' . htmlspecialchars($eng_policy) . '"/>');
		}

		include("/usr/local/www/suricata/suricata_import_aliases.php");
		print('</form>');

	} elseif ($add_edit_os_policy) {

		$form = new Form(false);
		include("/usr/local/www/suricata/suricata_os_policy_engine.php");

	} else {
		$sec_state = COLLAPSIBLE | (!empty($input_errors) ? SEC_OPEN : SEC_CLOSED);
		$exception_help = gettext('Default is Ignore. See the exception policy notes below.');
?>

<style>
.sf-notes { display: flex; flex-wrap: wrap; gap: .4rem 1.5rem; margin: -.5rem 0 var(--fs-sp-5); color: var(--fs-text-muted); font-size: var(--fs-fs-sm); }
.sf-policy-notes .panel-body { padding: var(--fs-sp-3) var(--fs-sp-4); }
.sf-policy-notes dl { display: grid; grid-template-columns: 9rem minmax(0, 1fr); gap: .35rem 1rem; margin: .5rem 0 0; }
.sf-policy-notes dt { font-weight: 600; }
.sf-policy-notes dd { margin: 0; }
@media (max-width: 575.98px) { .sf-policy-notes dl { grid-template-columns: 1fr; gap: .1rem; } .sf-policy-notes dd { margin-bottom: .4rem; } }
</style>

<form action="suricata_flow_stream.php" method="post" name="iform" id="iform" class="">
<input type="hidden" name="eng_id" id="eng_id" value="<?=fs_h($eng_id)?>"/>
<input type="hidden" name="id" id="id" value="<?=(int)$id?>"/>

<div class="panel panel-default fs-table">
<?php
	fs_table_toolbar(array(
		'title' => gettext('Host OS policies'),
		'search' => false,
		'noun' => gettext('policies'),
		'noun_one' => gettext('policy'),
		'actions' => '<button type="submit" name="import_alias[]" class="btn btn-sm btn-outline-secondary" title="' . fs_h(gettext("Import policy configuration from existing Aliases")) . '" value="Import">'
		    . '<i class="fa-solid fa-upload icon-embed-btn" aria-hidden="true"></i>' . fs_h(gettext('Import')) . '</button>'
		    . '<button type="submit" name="add_os_policy[]" class="btn btn-sm btn-primary" title="' . fs_h(gettext("Add a new policy configuration")) . '" value="Add">'
		    . '<i class="fa-solid fa-plus icon-embed-btn" aria-hidden="true"></i>' . fs_h(gettext('Add policy')) . '</button>',
	));
?>
	<div class="panel-body table-responsive">
		<table class="table table-hover">
			<thead>
				<tr>
					<th><?=gettext("Name")?></th>
					<th><?=gettext("Bind to")?></th>
					<th><?=gettext("Target OS")?></th>
					<th class="fs-col-actions"><span class="visually-hidden"><?=gettext('Actions')?></span></th>
				</tr>
			</thead>
			<tbody>
<?php foreach ($pconfig['host_os_policy']['item'] as $f => $v): ?>
				<tr>
					<td><?=htmlspecialchars(gettext($v['name']))?></td>
					<td><?=($v['bind_to'] == 'all') ? '<span class="fs-chip">' . gettext('All hosts') . '</span>' : '<span class="fs-chip fs-chip--mono">' . htmlspecialchars($v['bind_to']) . '</span>'?></td>
					<td><span class="fs-chip fs-chip--strong"><?=htmlspecialchars($v['policy'] ?? 'bsd')?></span></td>
					<td class="fs-col-actions"><div class="fs-actions">
						<button type="submit" name="edit_os_policy[]" value="Edit" class="fs-action" data-sf-eng="<?=(int)$f?>" title="<?=fs_h(sprintf(gettext('Edit %s'), $v['name']))?>" aria-label="<?=fs_h(sprintf(gettext('Edit %s'), $v['name']))?>"><i class="fa-solid fa-pencil" aria-hidden="true"></i></button>
<?php if ($v['bind_to'] != "all") : ?>
						<button type="submit" name="del_os_policy[]" value="Delete" class="fs-action fs-action--delete" data-sf-eng="<?=(int)$f?>" title="<?=fs_h(sprintf(gettext('Delete %s'), $v['name']))?>" aria-label="<?=fs_h(sprintf(gettext('Delete %s'), $v['name']))?>"
							data-fs-confirm="<?=fs_h(sprintf(gettext('Delete host OS policy “%s”?'), $v['name']))?>" data-fs-confirm-action="<?=gettext('Delete')?>"><i class="fa-solid fa-trash-can" aria-hidden="true"></i></button>
<?php else : ?>
						<span class="fs-action" title="<?=gettext("The default policy cannot be deleted")?>" aria-hidden="true"><i class="fa-solid fa-lock fs-muted"></i></span>
<?php endif ?>
					</div></td>
				</tr>
<?php endforeach; ?>
			</tbody>
		</table>
	</div>
</div>
</form>

<?php

$form = new Form();

$form->addGlobal(new Form_Input(
	'id',
	'id',
	'hidden',
	$id
));

$form->addGlobal(new Form_Input(
	'eng_id',
	'eng_id',
	'hidden',
	$eng_id
));

$stream_policies = array( "drop-flow" => "Drop Flow", "pass-flow" => "Pass Flow", "bypass" => "Bypass", "drop-packet" => "Drop Packet",
	"pass-packet" => "Pass Packet", "reject" => "Reject", "ignore" => "Ignore" );
$packet_policies = array( "bypass" => "Bypass", "drop-packet" => "Drop Packet", "pass-packet" => "Pass Packet",
	"reject" => "Reject", "ignore" => "Ignore" );

/* ---- Stream engine: the settings changed most often */
$section = new Form_Section('Stream engine');
$section->addInput(new Form_Input(
	'stream_memcap',
	'Memory cap',
	'text',
	$pconfig['stream_memcap']
))->setHelp('Bytes. Default is 268,435,456 (256 MB). Raise it in 4 MB steps if Suricata fails to start with a memory allocation error; systems with more than 4 cores usually need more.');
$section->addInput(new Form_Select(
	'stream_memcap_policy',
	'Memory cap exception policy',
	$pconfig['stream_memcap_policy'],
	$stream_policies
))->setHelp($exception_help);
$section->addInput(new Form_Input(
	'stream_prealloc_sessions',
	'Preallocated sessions',
	'text',
	$pconfig['stream_prealloc_sessions']
))->setHelp('Default is 32,768 sessions.');
$section->addInput(new Form_Checkbox(
	'enable_midstream_sessions',
	'Mid-stream sessions',
	'Pick up sessions that started before Suricata saw them. Default is off; such sessions are then subject to the Midstream exception policy.',
	$pconfig['enable_midstream_sessions'] == 'on' ? true:false,
	'on'
));
$section->addInput(new Form_Select(
	'midstream_policy',
	'Midstream exception policy',
	$pconfig['midstream_policy'],
	$stream_policies
))->setHelp($exception_help);
$section->addInput(new Form_Checkbox(
	'enable_async_sessions',
	'Async streams',
	'Track asynchronous one-sided streams. Default is off.',
	$pconfig['enable_async_sessions'] == 'on' ? true:false,
	'on'
));
$section->addInput(new Form_Checkbox(
	'stream_checksum_validation',
	'Checksum validation',
	'Packets with an invalid checksum are not processed by the stream and app layer. Default is on.',
	$pconfig['stream_checksum_validation'] == 'on' ? true:false,
	'on'
));
$section->addInput(new Form_Checkbox(
	'stream_bypass',
	'Bypass packets',
	'Bypass packets once the reassembly depth is reached. Default is off.',
	$pconfig['stream_bypass'] == 'on' ? true:false,
	'on'
));
$section->addInput(new Form_Checkbox(
	'stream_drop_invalid',
	'Drop invalid packets',
	'Inline mode: drop packets that are invalid for the stream engine. Default is off.',
	$pconfig['stream_drop_invalid'] == 'on' ? true:false,
	'on'
));
$form->add($section);

/* ---- Stream reassembly */
$section = new Form_Section('Stream reassembly', 'sf-reassembly', $sec_state);
$section->addInput(new Form_Input(
	'reassembly_memcap',
	'Memory cap',
	'text',
	$pconfig['reassembly_memcap']
))->setHelp('Bytes. Default is 134,217,728 (128 MB).');
$section->addInput(new Form_Select(
	'reassembly_memcap_policy',
	'Memory cap exception policy',
	$pconfig['reassembly_memcap_policy'],
	$stream_policies
))->setHelp($exception_help);
$section->addInput(new Form_Input(
	'reassembly_depth',
	'Depth',
	'text',
	$pconfig['reassembly_depth']
))->setHelp('Bytes of a stream to reassemble. Default is 1,048,576 (1 MB); 0 reassembles the whole stream, which file extraction needs.');
$section->addInput(new Form_Input(
	'reassembly_to_server_chunk',
	'To-server chunk size',
	'text',
	$pconfig['reassembly_to_server_chunk']
))->setHelp('Bytes per raw inspection chunk for to-server traffic. Default is 2,560.');
$section->addInput(new Form_Input(
	'reassembly_to_client_chunk',
	'To-client chunk size',
	'text',
	$pconfig['reassembly_to_client_chunk']
))->setHelp('Bytes per raw inspection chunk for to-client traffic. Default is 2,560.');
$section->addInput(new Form_Input(
	'max_synack_queued',
	'Queued SYN/ACKs',
	'number',
	$pconfig['max_synack_queued']
))->setHelp('Extra SYN/ACKs held while waiting for the ACK of the handshake. Default is 5.');
$form->add($section);

/* ---- Flow manager */
$section = new Form_Section('Flow manager', 'sf-flow', $sec_state);
$section->addInput(new Form_Input(
	'flow_memcap',
	'Memory cap',
	'text',
	$pconfig['flow_memcap']
))->setHelp('Bytes. Default is 134,217,728 (128 MB).');
$section->addInput(new Form_Select(
	'flow_memcap_policy',
	'Memory cap exception policy',
	$pconfig['flow_memcap_policy'],
	$packet_policies
))->setHelp($exception_help);
$section->addInput(new Form_Input(
	'flow_hash_size',
	'Hash table size',
	'text',
	$pconfig['flow_hash_size']
))->setHelp('Default is 65,536 entries.');
$section->addInput(new Form_Input(
	'flow_prealloc',
	'Preallocated flows',
	'text',
	$pconfig['flow_prealloc']
))->setHelp('Default is 10,000 flows.');
$section->addInput(new Form_Input(
	'flow_emerg_recovery',
	'Emergency recovery',
	'text',
	$pconfig['flow_emerg_recovery']
))->setHelp('Percent of preallocated flows to free before leaving emergency mode. Default is 30.');
$section->addInput(new Form_Input(
	'flow_prune',
	'Prune flows',
	'text',
	$pconfig['flow_prune']
))->setHelp('Flows to prune in emergency mode when a new flow is needed. Default is 5.');
$form->add($section);

/* ---- Flow timeouts (seconds) */
$section = new Form_Section('Flow timeouts', 'sf-timeouts', $sec_state);
$group = new Form_Group('TCP');
$group->add(new Form_Input('flow_tcp_new_timeout', 'New', 'text', $pconfig['flow_tcp_new_timeout']))->setHelp('New. Default 60');
$group->add(new Form_Input('flow_tcp_established_timeout', 'Established', 'text', $pconfig['flow_tcp_established_timeout']))->setHelp('Established. Default 3600');
$group->add(new Form_Input('flow_tcp_closed_timeout', 'Closed', 'text', $pconfig['flow_tcp_closed_timeout']))->setHelp('Closed. Default 120');
$section->add($group);
$group = new Form_Group('TCP in emergency');
$group->add(new Form_Input('flow_tcp_emerg_new_timeout', 'New', 'text', $pconfig['flow_tcp_emerg_new_timeout']))->setHelp('New. Default 10');
$group->add(new Form_Input('flow_tcp_emerg_established_timeout', 'Established', 'text', $pconfig['flow_tcp_emerg_established_timeout']))->setHelp('Established. Default 300');
$group->add(new Form_Input('flow_tcp_emerg_closed_timeout', 'Closed', 'text', $pconfig['flow_tcp_emerg_closed_timeout']))->setHelp('Closed. Default 20');
$section->add($group);
$group = new Form_Group('UDP');
$group->add(new Form_Input('flow_udp_new_timeout', 'New', 'text', $pconfig['flow_udp_new_timeout']))->setHelp('New. Default 30');
$group->add(new Form_Input('flow_udp_established_timeout', 'Established', 'text', $pconfig['flow_udp_established_timeout']))->setHelp('Established. Default 300');
$section->add($group);
$group = new Form_Group('UDP in emergency');
$group->add(new Form_Input('flow_udp_emerg_new_timeout', 'New', 'text', $pconfig['flow_udp_emerg_new_timeout']))->setHelp('New. Default 10');
$group->add(new Form_Input('flow_udp_emerg_established_timeout', 'Established', 'text', $pconfig['flow_udp_emerg_established_timeout']))->setHelp('Established. Default 100');
$section->add($group);
$group = new Form_Group('ICMP');
$group->add(new Form_Input('flow_icmp_new_timeout', 'New', 'text', $pconfig['flow_icmp_new_timeout']))->setHelp('New. Default 30');
$group->add(new Form_Input('flow_icmp_established_timeout', 'Established', 'text', $pconfig['flow_icmp_established_timeout']))->setHelp('Established. Default 300');
$section->add($group);
$group = new Form_Group('ICMP in emergency');
$group->add(new Form_Input('flow_icmp_emerg_new_timeout', 'New', 'text', $pconfig['flow_icmp_emerg_new_timeout']))->setHelp('New. Default 10');
$group->add(new Form_Input('flow_icmp_emerg_established_timeout', 'Established', 'text', $pconfig['flow_icmp_emerg_established_timeout']))->setHelp('Established. Default 100');
$section->add($group);
$section->addInput(new Form_StaticText(null, '<span class="fs-muted">' . gettext('All timeouts are in seconds.') . '</span>'));
$form->add($section);

/* ---- IP defragmentation */
$section = new Form_Section('IP defragmentation', 'sf-defrag', $sec_state);
$section->addInput(new Form_Input(
	'frag_memcap',
	'Memory cap',
	'text',
	$pconfig['frag_memcap']
))->setHelp('Bytes. Default is 33,554,432 (32 MB).');
$section->addInput(new Form_Select(
	'defrag_memcap_policy',
	'Memory cap exception policy',
	$pconfig['defrag_memcap_policy'],
	$packet_policies
))->setHelp($exception_help);
$section->addInput(new Form_Input(
	'ip_max_trackers',
	'Max trackers',
	'text',
	$pconfig['ip_max_trackers']
))->setHelp('Defragmented flows to follow. Default is 65,535.');
$section->addInput(new Form_Input(
	'ip_max_frags',
	'Max fragments',
	'text',
	$pconfig['ip_max_frags']
))->setHelp('Fragments held while waiting for reassembly. Default is 65,535; must be at least Max trackers.');
$section->addInput(new Form_Input(
	'frag_hash_size',
	'Hash table size',
	'text',
	$pconfig['frag_hash_size']
))->setHelp('Default is 65,536 entries.');
$section->addInput(new Form_Input(
	'ip_frag_timeout',
	'Timeout',
	'text',
	$pconfig['ip_frag_timeout']
))->setHelp('Seconds to hold a fragment while waiting for the rest of the packet. Default is 60.');
$form->add($section);

print($form);
?>

<div class="panel panel-default sf-policy-notes">
	<div class="panel-heading"><h2 class="panel-title"><?=gettext('Exception policies')?></h2></div>
	<div class="panel-body">
		<p class="fs-muted mb-0"><?=gettext('What Suricata does with a packet or flow when a memory cap is reached or a session is picked up mid-stream:')?></p>
		<dl>
			<dt><?=gettext('Drop Flow')?></dt><dd><?=gettext('Stops inspecting the whole flow and drops this and all later packets of it.')?></dd>
			<dt><?=gettext('Drop Packet')?></dt><dd><?=gettext('Drops the current packet.')?></dd>
			<dt><?=gettext('Reject')?></dt><dd><?=gettext('Like Drop Flow (or Drop Packet for packet policies), and also rejects the current packet.')?></dd>
			<dt><?=gettext('Bypass')?></dt><dd><?=gettext('Bypasses the flow; nothing more is inspected.')?></dd>
			<dt><?=gettext('Pass Flow')?></dt><dd><?=gettext('Turns off payload and packet detection; reassembly, app-layer parsing and logging continue.')?></dd>
			<dt><?=gettext('Pass Packet')?></dt><dd><?=gettext('Turns off detection, but stream updates and app-layer parsing continue.')?></dd>
			<dt><?=gettext('Ignore')?></dt><dd><?=gettext('Applies no exception policy (default).')?></dd>
		</dl>
	</div>
</div>

<div class="sf-notes">
	<span><?=gettext('Saving rebuilds the rules file, which can take several seconds. Restart Suricata on this interface to use the new values.')?></span>
</div>

<script type="text/javascript">
//<![CDATA[
events.push(function() {
	// Edit / delete a host OS policy: remember which one before the form posts
	document.addEventListener('click', function(e) {
		var btn = e.target.closest('button[data-sf-eng]');
		if (!btn || e.defaultPrevented) {
			return;
		}
		document.getElementById('eng_id').value = btn.getAttribute('data-sf-eng');
	});
});
//]]>
</script>

<?php } ?>

<?php include("foot.inc"); ?>
