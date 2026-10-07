<?php
/*
 * suricata_alerts.php
 *
 * part of FreeSense (https://www.freesense.org)
 * Copyright (c) 2004-2026 The FreeSense Project
 * Copyright (c) 2003-2004 Manuel Kasper
 * Copyright (c) 2005 Bill Marquette
 * Copyright (c) 2009 Robert Zelaya Sr. Developer
 * Copyright (c) 2025 Bill Meeks
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

global $g;
$supplist = array();
$suri_pf_table = SURICATA_PF_TABLE;

function suricata_is_alert_globally_suppressed($list, $gid, $sid) {

	/************************************************/
	/* Checks the passed $gid:$sid to see if it has */
	/* been globally suppressed.  If true, then any */
	/* "track by_src" or "track by_dst" options are */
	/* disabled since they are overridden by the    */
	/* global suppression of the $gid:$sid.         */
	/************************************************/

	/* If entry at array key [GID][SID] is set to the
	 * string "suppress", then the rule is globally
	 * suppressed, otherwise it will  have a child
	 * array for track "by_src" or "by_dst".
     */
	if (array_get_path($list, "{$gid}/{$sid}", "") == "suppress")
		return true;
	else
		return false;
}

function suricata_add_supplist_entry($suppress) {

	/************************************************/
	/* Adds the passed entry to the Suppress List   */
	/* for the active interface.  If a Suppress     */
	/* List is defined for the interface, it is     */
	/* used.  If no list is defined, a new default  */
	/* list is created using the interface name.    */
	/*                                              */
	/* On Entry:                                    */
	/*   $suppress --> suppression entry text       */
	/*                                              */
	/* Returns:                                     */
	/*   TRUE if successful or FALSE on failure     */
	/************************************************/

	global $instanceid;

	$a_suppress = config_get_path('installedpackages/suricata/suppress/item', []);
	$found_list = false;

	/* If no Suppress List is set for the interface, then create one with the interface name */
	if (empty(config_get_path("installedpackages/suricata/rule/{$instanceid}/suppresslistname", '')) || config_get_path("installedpackages/suricata/rule/{$instanceid}/suppresslistname", '') == 'default') {
		$s_list = array();
		$s_list['uuid'] = uniqid();
		$s_list['name'] = config_get_path("installedpackages/suricata/rule/{$instanceid}/interface") . "suppress" . "_" . $s_list['uuid'];
		$s_list['descr']  =  "Auto-generated list for Alert suppression";
		$s_list['suppresspassthru'] = base64_encode($suppress);
		$a_suppress[] = $s_list;
		config_set_path("installedpackages/suricata/rule/{$instanceid}/suppresslistname", $s_list['name']);
		$found_list = true;
	} else {
		/* If we get here, a Suppress List is defined for the interface so see if we can find it */
		foreach ($a_suppress as $a_id => $alist) {
			if ($alist['name'] == config_get_path("installedpackages/suricata/rule/{$instanceid}/suppresslistname", '')) {
				$found_list = true;
				if (!empty($alist['suppresspassthru'])) {
					$tmplist = base64_decode($alist['suppresspassthru']);
					$tmplist .= "\n{$suppress}";
					$alist['suppresspassthru'] = base64_encode($tmplist);
					$a_suppress[$a_id] = $alist;
				}
				else {
					$alist['suppresspassthru'] = base64_encode($suppress);
					$a_suppress[$a_id] = $alist;
				}
			}
		}
	}

	/* If we created a new list or updated an existing one, save the change */
	/* and return true; otherwise return false.                             */
	if ($found_list) {
		config_set_path('installedpackages/suricata/suppress/item', $a_suppress);
		write_config("Suricata pkg: saved change to Suppress List " . $s_list['name'] . " from ALERTS tab.");
		sync_suricata_package_config();
		return true;
	}
	else
		return false;
}

function suricata_escape_filter_regex($filtertext) {
	/* If the caller (user) has not already put a backslash before a slash, to escape it in the regex, */
	/* then this will do it. Take out any "\/" already there, then turn all ordinary "/" into "\/".  */
	return str_replace('/', '\/', str_replace('\/', '/', $filtertext));
}

function suricata_match_filter_field($flent, $fields, $exact_match = FALSE) {
	foreach ($fields as $key => $field) {
		if ($field == null)
			continue;

		// Only match whole field string when
		// performing an exact match.
		if ($exact_match) {
			if ($flent[$key] == $field) {
				return true;
			}
			else {
				return false;
			}
		}

		if ((strpos($field, '!') === 0)) {
			$field = substr($field, 1);
			$field_regex = suricata_escape_filter_regex($field);
			if (@preg_match("/{$field_regex}/i", $flent[$key]))
				return false;
		}
		else {
			$field_regex = suricata_escape_filter_regex($field);
			if (!@preg_match("/{$field_regex}/i", $flent[$key]))
				return false;
		}
	}
	return true;
}

if (isset($_POST['instance']) && is_numericint($_POST['instance']))
	$instanceid = $_POST['instance'];
// This is for the auto-refresh so we can  stay on the same interface
elseif (isset($_GET['instance']) && is_numericint($_GET['instance']))
	$instanceid = $_GET['instance'];

if (!is_numericint($instanceid))
	$instanceid = 0;

$a_instance = config_get_path("installedpackages/suricata/rule/{$instanceid}", []);
$suricata_uuid = $a_instance['uuid'];
$if_real = get_real_interface($a_instance['interface']);
$suricatalogdir = SURICATALOGDIR;
$suricatadir = SURICATADIR;

// Load up the arrays of force-enabled and force-disabled SIDs
$enablesid = suricata_load_sid_mods($a_instance['rule_sid_on']);
$disablesid = suricata_load_sid_mods($a_instance['rule_sid_off']);

// Load up the arrays of forced-alert, forced-drop or forced-reject
// rules as applicable to the current IPS mode.
if ($a_instance['blockoffenders'] == 'on' && ($a_instance['ips_mode'] == 'ips_mode_inline' || $a_instance['block_drops_only'] == 'on')) {
	$alertsid = suricata_load_sid_mods($a_instance['rule_sid_force_alert']);
	$dropsid = suricata_load_sid_mods($a_instance['rule_sid_force_drop']);

	// REJECT forcing is only applicable to Inline IPS Mode
	if ($a_instance['ips_mode'] == 'ips_mode_inline' ) {
		$rejectsid = suricata_load_sid_mods($a_instance['rule_sid_force_reject']);
	}
	else {
		$rejectsid = array();
	}
}

$pconfig = array();
$pconfig['arefresh'] = config_get_path('installedpackages/suricata/alertsblocks/arefresh', 'on');
$pconfig['alertnumber'] = config_get_path('installedpackages/suricata/alertsblocks/alertnumber', '250');
$anentries = (int)$pconfig['alertnumber'];

# --- AJAX REVERSE DNS RESOLVE Start ---
if (isset($_POST['resolve'])) {
	$ip = strtolower($_POST['resolve']);
	$res = (is_ipaddr($ip) ? gethostbyaddr($ip) : '');
	if (strpos($res, 'xn--') !== false) {
		$res = idn_to_utf8($res);
	}

	if ($res && $res != $ip)
		$response = array('resolve_ip' => $ip, 'resolve_text' => $res);
	else
		$response = array('resolve_ip' => $ip, 'resolve_text' => gettext("Cannot resolve"));

	echo json_encode(str_replace("\\","\\\\", $response)); // single escape chars can break JSON decode
	exit;
}
# --- AJAX REVERSE DNS RESOLVE End ---

# --- AJAX GEOIP CHECK Start ---
if (isset($_POST['geoip'])) {
	$ip = strtolower($_POST['geoip']);
	if (is_ipaddr($ip)) {
		$url = "https://api.hackertarget.com/geoip/?q={$ip}";
		$conn = curl_init("https://api.hackertarget.com/geoip/?q={$ip}");
		curl_setopt($conn, CURLOPT_SSL_VERIFYPEER, true);
		curl_setopt($conn, CURLOPT_FRESH_CONNECT,  true);
		curl_setopt($conn, CURLOPT_RETURNTRANSFER, 1);
		set_curlproxy($conn);
		$res = curl_exec($conn);
		curl_close($conn);
	} else {
		$res = '';
	}

	if ($res && $res != $ip && !preg_match('/error/', $res))
		$response = array('geoip_text' => $res);
	else
		$response = array('geoip_text' => gettext("Cannot check {$ip}"));

	echo json_encode(str_replace("\\","\\\\", $response)); // single escape chars can break JSON decode
	exit;
}
# --- AJAX GEOIP CHECK End ---

# --- AJAX RULE LOOKUP Start ---
if (isset($_POST['rulelookup2'])) {
	list($gid, $sid) = explode(':', $_POST['rulelookup']);
	foreach (glob("{$suricatadir}suricata_{$suricata_uuid}_{$if_real}/rules/*") as $rule) {
		$fd = fopen($rule, "r");
		$buf = "";
		while (($buf = fgets($fd)) !== FALSE) {
			$matches = array();
			preg_match('/sid\:([0-9]+);/i', $buf, $matches);
			if ($sid == $matches[1]) {
				preg_match('/gid\:([0-9]+);/i', $buf, $matches);
				if (($gid == $matches[1]) ||
				    (empty($matches[1]) && ($gid == 1))) {
					$res = $buf;
					break 2;
				}
			}
		}
	}

	if ($res)
		$response = array('gidsid' => $_POST['rulelookup'], 'rule_text' => $res);
	else
		$response = array('gidsid' => $_POST['rulelookup'], 'rule_text' => gettext("Unable to find the rule"));

	echo json_encode(str_replace("\\","\\\\", $response)); // single escape chars can break JSON decode
	exit;
}
# --- AJAX RULE LOOKUP End ---

# --- AJAX RULE LOOKUP Start ---
if ($_POST['action'] == 'loadRule') {
	$currentruleset = '';
	if (isset($_POST['gid']) && isset($_POST['sid'])) {
		$gid = $_POST['gid'];
		$sid = $_POST['sid'];
		$rules = array_merge(glob(SURICATA_RULES_DIR . "/*.rules"), array("{$suricatadir}suricata_{$suricata_uuid}_{$if_real}/rules/custom.rules", "{$suricatadir}suricata_{$suricata_uuid}_{$if_real}/rules/flowbit-required.rules"));
		foreach ($rules as $rule) {
			$rules_map = suricata_load_rules_map($rule);
			if ($rules_map[$gid][$sid]['rule']) {
				$rule_text = base64_encode($rules_map[$gid][$sid]['rule']);
				$currentruleset = basename($rule);
				break;
			}
		}
	} else {
		$rule_text = base64_encode(gettext('Invalid rule signature - no matching rule was found!'));
	}
	if (strpos($currentruleset, 'snort_') !== false) {
		$rule_link = "https://www.snort.org/rule_docs/{$gid}-{$sid}";
	} else {
		$rule_link = '';
	}	
	$response = array('rule_text' => $rule_text, 'rule_link' => $rule_link, 'category' => $currentruleset);
	echo json_encode(str_replace("\\","\\\\", $response)); // single escape chars can break JSON decode
	exit;
}
# --- AJAX RULE LOOKUP End ---

# Check for persisted filtering of alerts log entries and populate
# the required $filterfieldsarray when persisting filtered entries.
if ($_POST['persist_filter'] == "yes" && !empty($_POST['persist_filter_content'])) {
	$filterlogentries = TRUE;
	$persist_filter_log_entries = "yes";
	$filterlogentries_exact_match = $_POST['persist_filter_exact_match'];
	$filterfieldsarray = json_decode($_POST['persist_filter_content'], TRUE);
}
else {
	$filterlogentries = FALSE;
	$persist_filter_log_entries = "";
	$filterfieldsarray = array();
}

if ($_POST['filterlogentries_submit']) {
	// Set flags for filtering alert log entries
	$filterlogentries = TRUE;
	$persist_filter_log_entries = "yes";

	// Set 'exact match only' flag if enabled
	if ($_POST['filterlogentries_exact_match'] == 'on') {
		$filterlogentries_exact_match = TRUE;
	}
	else {
		$filterlogentries_exact_match = FALSE;
	}

	// -- IMPORTANT --
	// Note the order of these fields must match the order decoded from the alerts log
	$filterfieldsarray = array();
	$filterfieldsarray['time'] = $_POST['filterlogentries_time'] ? $_POST['filterlogentries_time'] : null;
	if ($a_instance['ips_mode'] == 'ips_mode_inline') {
		if ($_POST['filterlogentries_action_drop']) {
			$filterfieldsarray['action'] = $_POST['filterlogentries_action_drop'] ? $_POST['filterlogentries_action_drop'] : null;
		}
		elseif ($_POST['filterlogentries_action_ndrop']) {
			$filterfieldsarray['action'] = $_POST['filterlogentries_action_ndrop'] ? $_POST['filterlogentries_action_ndrop'] : null;
		}
	}
	else {
		$filterfieldsarray['action'] = null;
	}
	$filterfieldsarray['gid'] = $_POST['filterlogentries_gid'] ? $_POST['filterlogentries_gid'] : null;
	$filterfieldsarray['sid'] = $_POST['filterlogentries_sid'] ? $_POST['filterlogentries_sid'] : null;
	$filterfieldsarray['rev'] = null;
	$filterfieldsarray['msg'] = $_POST['filterlogentries_description'] ? $_POST['filterlogentries_description'] : null;
	$filterfieldsarray['class'] = $_POST['filterlogentries_classification'] ? $_POST['filterlogentries_classification'] : null;
	$filterfieldsarray['priority'] = $_POST['filterlogentries_priority'] ? $_POST['filterlogentries_priority'] : null;
	$filterfieldsarray['proto'] = $_POST['filterlogentries_protocol'] ? $_POST['filterlogentries_protocol'] : null;
	// Remove any zero-length spaces added to the IP address that could creep in from a copy-paste operation
	$filterfieldsarray['src'] = $_POST['filterlogentries_sourceipaddress'] ? str_replace("\xE2\x80\x8B", "", $_POST['filterlogentries_sourceipaddress']) : null;
	$filterfieldsarray['sport'] = $_POST['filterlogentries_sourceport'] ? $_POST['filterlogentries_sourceport'] : null;
	// Remove any zero-length spaces added to the IP address that could creep in from a copy-paste operation
	$filterfieldsarray['dst'] = $_POST['filterlogentries_destinationipaddress'] ? str_replace("\xE2\x80\x8B", "", $_POST['filterlogentries_destinationipaddress']) : null;
	$filterfieldsarray['dport'] = $_POST['filterlogentries_destinationport'] ? $_POST['filterlogentries_destinationport'] : null;
}

if ($_POST['filterlogentries_clear']) {
	$filterfieldsarray = array();
	$filterlogentries = TRUE;
	$persist_filter_log_entries = "";
}

if ($_POST['save']) {
	config_set_path('installedpackages/suricata/alertsblocks/arefresh', $_POST['arefresh'] ? 'on' : 'off');
	config_set_path('installedpackages/suricata/alertsblocks/alertnumber', $_POST['alertnumber']);

	write_config("Suricata pkg: saved change to ALERTS tab configuration.");

	header("Location: /suricata/suricata_alerts.php?instance={$instanceid}");
	exit;
}

if (isset($_POST['rule_action_save']) && $_POST['mode'] == "toggle_action" && isset($_POST['ruleActionOptions']) && is_numeric($_POST['sidid']) && is_numeric($_POST['gen_id'])) {

	// Get the GID:SID tags embedded in the clicked rule icon.
	$gid = $_POST['gen_id'];
	$sid = $_POST['sidid'];

	// Get the posted rule action
	$action = $_POST['ruleActionOptions'];

	// Put the target SID in the appropriate lists of modified
	// SID actions based on the requested action; if default
	// action is requested, remove the SID from all SID modified
	// action lists.
	switch ($action) {
		case "action_default":
			array_del_path($alertsid, "{$gid}/{$sid}");
			array_del_path($dropsid, "{$gid}/{$sid}");
			array_del_path($rejectsid, "{$gid}/{$sid}");
			break;

		case "action_alert":
			array_set_path($alertsid, "{$gid}/{$sid}", "alertsid");
			array_del_path($dropsid, "{$gid}/{$sid}");
			array_del_path($rejectsid, "{$gid}/{$sid}");
			break;

		case "action_drop":
			array_set_path($dropsid, "{$gid}/{$sid}", "dropsid");
			array_del_path($alertsid, "{$gid}/{$sid}");
			array_del_path($rejectsid, "{$gid}/{$sid}");
			break;

		case "action_reject":
			array_set_path($rejectsid, "{$gid}/{$sid}", "rejectsid");
			array_del_path($alertsid, "{$gid}/{$sid}");
			array_del_path($dropsid, "{$gid}/{$sid}");
			break;

		default:
			$input_errors[] = gettext("WARNING - unknown rule action of '{$action}' passed in $_POST parameter.  No change made to rule action.");
	}

	if (!$input_errors) {
		// Write the updated forced rule action values to the config file.
		$tmp = "";
		foreach (array_keys($alertsid) as $k1) {
			foreach (array_keys($alertsid[$k1]) as $k2)
				$tmp .= "{$k1}:{$k2}||";
		}
		$tmp = rtrim($tmp, "||");

		if (!empty($tmp))
			$a_instance['rule_sid_force_alert'] = $tmp;
		else
			unset($a_instance['rule_sid_force_alert']);

		$tmp = "";
		foreach (array_keys($dropsid) as $k1) {
			foreach (array_keys($dropsid[$k1]) as $k2)
				$tmp .= "{$k1}:{$k2}||";
		}
		$tmp = rtrim($tmp, "||");

		if (!empty($tmp))
			$a_instance['rule_sid_force_drop'] = $tmp;
		else
			unset($a_instance['rule_sid_force_drop']);

		$tmp = "";
		foreach (array_keys($rejectsid) as $k1) {
			foreach (array_keys($rejectsid[$k1]) as $k2)
				$tmp .= "{$k1}:{$k2}||";
		}
		$tmp = rtrim($tmp, "||");

		if (!empty($tmp))
			$a_instance['rule_sid_force_reject'] = $tmp;
		else
			unset($a_instance['rule_sid_force_reject']);

		/* Update the config.xml file. */
		config_set_path("installedpackages/suricata/rule/{$instanceid}", $a_instance);
		write_config("Suricata pkg: User-forced rule action override applied for rule {$gid}:{$sid} on ALERTS tab for interface {$a_instance['interface']}.");

		/*************************************************/
		/* Update the suricata.yaml file and rebuild the */
		/* rules for this interface.                     */
		/*************************************************/
		$rebuild_rules = true;
		suricata_generate_yaml($a_instance);
		$rebuild_rules = false;

		/* Signal Suricata to live-load the new rules */
		suricata_reload_config($a_instance);

		// Sync to configured CARP slaves if any are enabled
		suricata_sync_on_changes();

		$savemsg = gettext("The action for rule {$gid}:{$sid} has been modified.  Suricata is 'live-reloading' the new rules list.  Please wait at least 15 secs for the process to complete before toggling additional rule actions.");
	}
}

if ($_POST['mode']=='unblock' && $_POST['ip']) {
	if (is_ipaddr($_POST['ip'])) {
		exec("/sbin/pfctl -t {$suri_pf_table} -T delete {$_POST['ip']}");
		$savemsg = gettext("Host IP address {$_POST['ip']} has been removed from the Blocked Table.");
	}
}

if (($_POST['mode'] == 'addsuppress_srcip' || $_POST['mode'] == 'addsuppress_dstip' || $_POST['mode'] == 'addsuppress') && is_numeric($_POST['sidid']) && is_numeric($_POST['gen_id'])) {
	if ($_POST['mode'] == 'addsuppress_srcip')
		$method = "by_src";
	elseif ($_POST['mode'] == 'addsuppress_dstip')
		$method = "by_dst";
	else
		$method ="all";

	// See which kind of Suppress Entry to create
	switch ($method) {
		case "all":
			if (empty($_POST['descr']))
				$suppress = "suppress gen_id {$_POST['gen_id']}, sig_id {$_POST['sidid']}\n";
			else
				$suppress = "#{$_POST['descr']}\nsuppress gen_id {$_POST['gen_id']}, sig_id {$_POST['sidid']}\n";
			$success = gettext("An entry for 'suppress gen_id {$_POST['gen_id']}, sig_id {$_POST['sidid']}' has been added to the Suppress List.  Suricata is 'live-reloading' the new rules list.  Please wait at least 15 secs for the process to complete before toggling additional rule actions.");
			break;
		case "by_src":
		case "by_dst":
			// Check for valid IP addresses, exit if not valid
			if (is_ipaddr($_POST['ip'])) {
				if (empty($_POST['descr']))
					$suppress = "suppress gen_id {$_POST['gen_id']}, sig_id {$_POST['sidid']}, track {$method}, ip {$_POST['ip']}\n";
				else
					$suppress = "#{$_POST['descr']}\nsuppress gen_id {$_POST['gen_id']}, sig_id {$_POST['sidid']}, track {$method}, ip {$_POST['ip']}\n";
				$success = gettext("An entry for 'suppress gen_id {$_POST['gen_id']}, sig_id {$_POST['sidid']}, track {$method}, ip {$_POST['ip']}' has been added to the Suppress List.  Suricata is 'live-reloading' the new rules list.  Please wait at least 15 secs for the process to complete before toggling additional rule actions.");
			}
			else {
				header("Location: /suricata/suricata_alerts.php");
				exit;
			}
			break;
		default:
			header("Location: /suricata/suricata_alerts.php");
			exit;
	}

	/* Add the new entry to the Suppress List and signal Suricata to reload config */
	if (suricata_add_supplist_entry($suppress)) {
		suricata_reload_config($a_instance);

		// See if this Suppress List is assigned to any other interface
		// and signal that interface to reload its configuration if true.
		foreach (config_get_path('installedpackages/suricata/rule', []) as $insid => $insconf) {
			if (($insid != $instanceid) &&
			    ($a_instance['suppresslistname'] == $insconf['suppresslistname'])) {
				suricata_reload_config($insconf);
			}
		}
		$savemsg = $success;

		// Sync to configured CARP slaves if any are enabled
		suricata_sync_on_changes();
		sleep(2);
	}
	else
		$input_errors[] = gettext("Suppress List '{$a_instance['suppresslistname']}' is defined for this interface, but it could not be found!");
}

if ($_POST['mode'] == 'togglesid' && is_numeric($_POST['sidid']) && is_numeric($_POST['gen_id'])) {
	// Get the GID and SID tags embedded in the clicked rule icon.
	$gid = $_POST['gen_id'];
	$sid= $_POST['sidid'];

	// See if the target SID is in our list of modified SIDs,
	// and toggle it if present.
	array_del_path($enablesid, "{$gid}/{$sid}");
	if (array_get_path($disablesid, "{$gid}/{$sid}")) {
		array_del_path($disablesid, "{$gid}/{$sid}");
	} else {
		array_set_path($disablesid, "{$gid}/{$sid}", 'disablesid');
	}

	// Write the updated enablesid and disablesid values to the config file.
	$tmp = "";
	foreach (array_keys($enablesid) as $k1) {
		foreach (array_keys($enablesid[$k1]) as $k2)
			$tmp .= "{$k1}:{$k2}||";
	}
	$tmp = rtrim($tmp, "||");

	if (!empty($tmp))
		$a_instance['rule_sid_on'] = $tmp;
	else
		unset($a_instance['rule_sid_on']);

	$tmp = "";
	foreach (array_keys($disablesid) as $k1) {
		foreach (array_keys($disablesid[$k1]) as $k2)
			$tmp .= "{$k1}:{$k2}||";
	}
	$tmp = rtrim($tmp, "||");

	if (!empty($tmp))
		$a_instance['rule_sid_off'] = $tmp;
	else
		unset($a_instance['rule_sid_off']);

	/* Update the config.xml file. */
	config_set_path("installedpackages/suricata/rule/{$instanceid}", $a_instance);
	write_config("Suricata pkg: User-forced rule state override applied for rule {$gid}:{$sid} on ALERTS tab for interface {$a_instance['interface']}.");

	/*************************************************/
	/* Update the suricata.yaml file and rebuild the */
	/* rules for this interface.                     */
	/*************************************************/
	$rebuild_rules = true;
	suricata_generate_yaml($a_instance);
	$rebuild_rules = false;

	/* Signal Suricata to live-load the new rules */
	suricata_reload_config($a_instance);

	// Sync to configured CARP slaves if any are enabled
	suricata_sync_on_changes();
	sleep(2);

	$savemsg = gettext("The state for rule {$gid}:{$sid} has been modified.  Suricata is 'live-reloading' the new rules list.  Please wait at least 15 secs for the process to complete before toggling additional rules.");
}

if ($_POST['clear']) {

	// Truncate the active alerts.log file
	$fd = @fopen("{$suricatalogdir}suricata_{$if_real}{$suricata_uuid}/alerts.log", "r+");
	if ($fd !== FALSE) {
		ftruncate($fd, 0);
		fclose($fd);
	}

	// Signal the Suricata instance that logs have been rotated
	suricata_reload_config($a_instance, SIGHUP);

	/* XXX: This is needed if suricata is run as suricata user */
	mwexec('/bin/chmod 660 {$suricatalogdir}*', true);
	header("Location: /suricata/suricata_alerts.php?instance={$instanceid}");
	exit;
}

if ($_POST['download']) {
	$save_date = date("Y-m-d-H-i-s");
	$file_name = "suricata_logs_{$save_date}_{$if_real}.tar.gz";
	exec("cd {$suricatalogdir}suricata_{$if_real}{$suricata_uuid} && /usr/bin/tar -czf {$g['tmp_path']}/{$file_name} alert*");

	if (file_exists("{$g['tmp_path']}/{$file_name}")) {
		ob_start(); //important or other posts will fail
		if (isset($_SERVER['HTTPS'])) {
			header('Pragma: ');
			header('Cache-Control: ');
		} else {
			header("Pragma: private");
			header("Cache-Control: private, must-revalidate");
		}
		header("Content-Type: application/octet-stream");
		header("Content-length: " . filesize("{$g['tmp_path']}/{$file_name}"));
		header("Content-disposition: attachment; filename = {$file_name}");
		ob_end_clean(); //important or other post will fail
		readfile("{$g['tmp_path']}/{$file_name}");

		// Clean up the temp file
		unlink_if_exists("{$g['tmp_path']}/{$file_name}");
	}
	else
		$savemsg = gettext("An error occurred while creating archive");
}

/* Load up an array with the current Suppression List GID,SID values */
$supplist = suricata_load_suppress_sigs($a_instance, true);

function build_instance_list() {
	$list = array();

	foreach (config_get_path('installedpackages/suricata/rule', []) as $id => $instance) {
		$list[$id] = '(' . convert_friendly_interface_to_friendly_descr($instance['interface']) . ') ' . $instance['descr'];
	}

	return($list);
}

function build_logfile_list() {
	global $suricatalogdir;

	$list = array();

	$logs = array( "alerts.log", "block.log", "dns.log", "eve.json", "files-json.log", "http.log", "sid_changes.log", "stats.log", "suricata.log", "tls.log" );
	foreach ($logs as $log) {
		$list[$suricatalogdir . $log] = $log;
	}

	return($list);
}

/* ---------------------------------------------------------------- read the log */

$is_ips_view = ($a_instance['blockoffenders'] == 'on' && ($a_instance['ips_mode'] == 'ips_mode_inline' || $a_instance['block_drops_only'] == 'on'));
$can_change_action = $is_ips_view;
$is_filtered = ($filterlogentries && count($filterfieldsarray));
$alerts = array();

/* make sure alert file exists */
if (file_exists("{$suricatalogdir}suricata_{$if_real}{$suricata_uuid}/alerts.log")) {
	exec("tail -{$anentries} -r {$suricatalogdir}suricata_{$if_real}{$suricata_uuid}/alerts.log > {$g['tmp_path']}/alerts_suricata{$suricata_uuid}");
	if (file_exists("{$g['tmp_path']}/alerts_suricata{$suricata_uuid}")) {
		$tmpblocked = array_flip(suricata_get_blocked_ips());

		/*************** FORMAT without CSV patch -- ALERT -- ***********************************************************************************/
		/* Line format: timestamp  action[**] [gid:sid:rev] msg [**] [Classification: class] [Priority: pri] {proto} src:srcport -> dst:dstport */
		/**************** FORMAT without CSV patch -- DECODER EVENT -- **************************************************************************/
		/* Line format: timestamp  action[**] [gid:sid:rev] msg [**] [Classification: class] [Priority: pri] [**] [Raw pkt: ...]                */
		/****************************************************************************************************************************************/

		$fd = fopen("{$g['tmp_path']}/alerts_suricata{$suricata_uuid}", "r");
		$buf = "";
		while (($buf = fgets($fd)) !== FALSE) {
			$fields = array();
			$tmp = array();
			$decoder_event = FALSE;
			$raw_pkt = '';

			// Drop any invalid line read from the log excerpt
			if (empty(trim($buf)))
				continue;

			// Field 0 is the event timestamp
			$fields['time'] = substr($buf, 0, strpos($buf, '  '));

			// Field 1 is the rule action (value is '**' when mode is not inline IPS or 'block-drops-only')
			if (($a_instance['ips_mode'] == 'ips_mode_inline'  || $a_instance['block_drops_only'] == 'on') && preg_match('/\[([A-Z]+)\]\s/i', $buf, $tmp)) {
				$fields['action'] = trim($tmp[1]);
			}
			else {
				$fields['action'] = null;
			}

			// [2] => GID, [3] => SID, [4] => REV, [5] => MSG, [6] => CLASSIFICATION, [7] = PRIORITY
			preg_match('/\[\*{2}\]\s\[((\d+):(\d+):(\d+))\]\s(.*)\[\*{2}\]\s\[Classification:\s(.*)\]\s\[Priority:\s(\d+)\]\s/', $buf, $tmp);
			$fields['gid'] = trim($tmp[2]);
			$fields['sid'] = trim($tmp[3]);
			$fields['rev'] = trim($tmp[4]);
			$fields['msg'] = trim($tmp[5]);
			$fields['class'] = trim($tmp[6]);
			$fields['priority'] = trim($tmp[7]);

			// [1] = PROTO, [2] => SRC:SPORT [3] => DST:DPORT
			if (preg_match('/\{(.*)\}\s(.*)\s->\s(.*)/', $buf, $tmp)) {
				$fields['proto'] = trim($tmp[1]);
				$fields['src'] = trim(substr($tmp[2], 0, strrpos($tmp[2], ':')));
				if (is_ipaddrv6($fields['src']))
					$fields['src'] = inet_ntop(inet_pton($fields['src']));
				$fields['sport'] = trim(substr($tmp[2], strrpos($tmp[2], ':') + 1));
				$fields['dst'] = trim(substr($tmp[3], 0, strrpos($tmp[3], ':')));
				if (is_ipaddrv6($fields['dst']))
					$fields['dst'] = inet_ntop(inet_pton($fields['dst']));
				$fields['dport'] = trim(substr($tmp[3], strrpos($tmp[3], ':') + 1));
			}
			else {
				// If no PROTO nor IP ADDR, then this is a DECODER EVENT
				$decoder_event = TRUE;
				$fields['proto'] = gettext("n/a");
				$fields['sport'] = gettext("n/a");
				$fields['dport'] = gettext("n/a");
				if (preg_match('/\s\[Raw pkt:(.*)\]/', $buf, $tmp))
					$raw_pkt = trim($tmp[1]);
			}

			try {
				$event_tm = date_create_from_format("m/d/Y-H:i:s.u", $fields['time']);
			} catch (Exception $e) {
				logger(LOG_WARNING, localize_text("found invalid timestamp entry in current alerts.log, the line will be ignored and skipped."), LOG_PREFIX_PKG_SURICATA);
				continue;
			}

			// Check the 'CATEGORY' field for the text "(null)" and substitute "Not Assigned".
			if ($fields['class'] == "(null)")
				$fields['class'] = gettext("Not Assigned");

			@$fields['time'] = date_format($event_tm, "m/d/Y") . " " . date_format($event_tm, "H:i:s");

			if ($filterlogentries && !suricata_match_filter_field($fields, $filterfieldsarray, $filterlogentries_exact_match)) {
				continue;
			}

			$alerts[] = array(
				'f' => $fields,
				'date' => @date_format($event_tm, "m/d/Y"),
				'clock' => @date_format($event_tm, "H:i:s"),
				'decoder' => $decoder_event,
				'raw' => $raw_pkt,
				'src_blocked' => !$decoder_event && isset($tmpblocked[$fields['src']]),
				'dst_blocked' => !$decoder_event && isset($tmpblocked[$fields['dst']]),
			);
		}
		unset($fields, $buf, $tmp);
		fclose($fd);
		unlink_if_exists("{$g['tmp_path']}/alerts_suricata{$suricata_uuid}");
	}
}

/* summary numbers */
$sum_high = $sum_drop = 0;
$sum_src = $sum_sig = $protos = array();
foreach ($alerts as $a) {
	if ($a['f']['priority'] === '1')
		$sum_high++;
	if (!empty($a['f']['action']))
		$sum_drop++;
	if (!$a['decoder'])
		$sum_src[$a['f']['src']] = true;
	$sum_sig["{$a['f']['gid']}:{$a['f']['sid']}"] = true;
	$protos[strtolower($a['f']['proto'])] = $a['f']['proto'];
}
ksort($protos);

/* ------------------------------------------------------------------ the page */

$pglinks = array("", "/suricata/suricata_overview.php", "/suricata/suricata_events.php", "@self");
$pgtitle = array(gettext("Services"), gettext("Suricata"), gettext("Events"), gettext("Alerts"));

$sf_post = 'suricata_alerts.php?instance=' . (int)$instanceid;
fs_page_action(gettext('View settings'), '#', 'fa-sliders', 'secondary', ['data-fs-modal' => '#alerts-settings']);
fs_page_action(gettext('Download logs'), $sf_post . '&download=Download', 'fa-download', 'secondary', ['usepost' => true]);
fs_page_action(gettext('Clear log'), $sf_post . '&clear=Clear', 'fa-trash-can', 'danger', [
	'usepost' => true,
	'data-fs-confirm' => gettext('Clear the alert log of this interface?'),
	'data-fs-confirm-detail' => gettext('The active alerts.log file is emptied. Rotated log files are kept.'),
	'data-fs-confirm-action' => gettext('Clear log'),
]);

include_once("head.inc");
suricata_display_primary_navigation('events');

echo '<nav class="fs-viewswitch" aria-label="' . fs_h(gettext('Events')) . '">';
foreach (array(
	array('alerts', gettext('Alerts'), "/suricata/suricata_alerts.php?instance={$instanceid}"),
	array('blocked', gettext('Blocked hosts'), '/suricata/suricata_blocked.php'),
	array('files', gettext('Files'), "/suricata/suricata_files.php?instance={$instanceid}"),
	array('events', gettext('EVE events'), '/suricata/suricata_events.php'),
	array('logs', gettext('Log files'), "/suricata/suricata_logs_browser.php?instance={$instanceid}"),
) as $sf_v) {
	echo '<a href="' . fs_h($sf_v[2]) . '"' . (($sf_v[0] === 'alerts') ? ' aria-current="page"' : '') . '>' . fs_h($sf_v[1]) . '</a>';
}
echo '</nav>';

/* refresh every 60 secs */
if ($pconfig['arefresh'] == 'on')
	print '<meta http-equiv="refresh" content="60;url=/suricata/suricata_alerts.php?instance=' . (int)$instanceid . '" />';

/* Display Alert message */
if ($input_errors) {
	print_input_errors($input_errors);
}
if ($savemsg) {
	print_info_box($savemsg);
}

/* Priority badge (1 = high … 4+ = informational); icon + text, never color alone */
$sf_pri = function ($p) {
	$map = array(
		'1' => array('block', 'fa-circle-exclamation', gettext('High')),
		'2' => array('warn', 'fa-triangle-exclamation', gettext('Medium')),
		'3' => array('info', 'fa-circle-info', gettext('Low')),
	);
	list($v, $i, $t) = $map[$p] ?? array('neutral', 'fa-circle-minus', gettext('Info'));
	return '<span class="fs-badge fs-badge--' . $v . '" title="' . fs_h(sprintf(gettext('Priority %s'), $p)) . '"><i class="fa-solid ' . $i . '" aria-hidden="true"></i>'
	    . fs_h($p) . ' · ' . fs_h($t) . '</span>';
};

/* Row action rendered as a submit button of #formalert; the page script copies
 * its data-sf-* values into the hidden fields before the form posts. */
$sf_btn = function ($icon, $label, array $data, $confirm = null, $detail = null, $verb = null) {
	$attrs = array(
		'type' => 'submit',
		'class' => 'fs-action',
		'title' => $label,
		'aria-label' => $label,
		'data-fs-confirm' => $confirm,
		'data-fs-confirm-detail' => $detail,
		'data-fs-confirm-action' => $verb,
	);
	foreach ($data as $k => $v) {
		$attrs['data-sf-' . $k] = $v;
	}
	return '<button' . fs_attrs($attrs) . '><i class="' . fs_h(fs_icon_class($icon)) . '" aria-hidden="true"></i></button>';
};

$sf_is_public = function ($ip) {
	return !is_private_ip($ip) && (substr($ip, 0, 2) != 'fc') && (substr($ip, 0, 2) != 'fd');
};

/* Address cell: mono address and port, then the host tools that apply */
$sf_host = function ($a, $side) use ($sf_btn, $sf_is_public, $supplist) {
	$f = $a['f'];
	$ip = ($side === 'src') ? $f['src'] : $f['dst'];
	$port = ($side === 'src') ? $f['sport'] : $f['dport'];
	$track = ($side === 'src') ? 'by_src' : 'by_dst';
	$html = '<span class="fs-mono sf-ip">' . fs_h($ip) . '</span>';
	if ($port !== '' && $port !== null) {
		$html .= '<span class="fs-mono fs-muted">:' . fs_h($port) . '</span>';
	}
	$html .= '<div class="fs-actions sf-hostactions">';
	$html .= '<button type="button" class="fs-action" data-sf-lookup="' . fs_h($ip) . '" data-sf-geo="' . ($sf_is_public($ip) ? '1' : '0') . '"'
	    . ' title="' . fs_h(sprintf(gettext('Look up %s'), $ip)) . '" aria-label="' . fs_h(sprintf(gettext('Look up %s'), $ip)) . '">'
	    . '<i class="fa-solid fa-magnifying-glass" aria-hidden="true"></i></button>';
	if (!suricata_is_alert_globally_suppressed($supplist, $f['gid'], $f['sid'])) {
		if (!isset($supplist[$f['gid']][$f['sid']][$track][$ip])) {
			$html .= $sf_btn('fa-bell-slash',
			    ($side === 'src') ? sprintf(gettext('Suppress %1$s:%2$s for source %3$s'), $f['gid'], $f['sid'], $ip) : sprintf(gettext('Suppress %1$s:%2$s for destination %3$s'), $f['gid'], $f['sid'], $ip),
			    array('mode' => ($side === 'src') ? 'addsuppress_srcip' : 'addsuppress_dstip', 'gid' => $f['gid'], 'sid' => $f['sid'], 'ip' => $ip, 'descr' => $f['msg']),
			    ($side === 'src') ? sprintf(gettext('Suppress %1$s:%2$s when the source is %3$s?'), $f['gid'], $f['sid'], $ip) : sprintf(gettext('Suppress %1$s:%2$s when the destination is %3$s?'), $f['gid'], $f['sid'], $ip),
			    gettext('A suppress entry is added to the interface Suppress List and Suricata reloads its rules.'),
			    gettext('Suppress'));
		} else {
			$html .= '<span class="fs-action sf-done" title="' . fs_h(gettext('Already suppressed for this address')) . '"><i class="fa-solid fa-bell-slash" aria-hidden="true"></i>'
			    . '<span class="visually-hidden">' . fs_h(gettext('Already suppressed for this address')) . '</span></span>';
		}
	}
	if ($a[$side . '_blocked']) {
		$html .= $sf_btn('fa-unlock', sprintf(gettext('Remove block for %s'), $ip),
		    array('mode' => 'unblock', 'ip' => $ip),
		    sprintf(gettext('Remove the block for %s?'), $ip),
		    gettext('The address is deleted from the blocked hosts table. A new alert can block it again.'),
		    gettext('Remove block'));
	}
	$html .= '</div>';
	if ($a[$side . '_blocked']) {
		$html .= ' ' . fs_badge('block', gettext('Blocked'));
	}
	return $html;
};
?>

<style>
.sf-sig { min-width: 16rem; }
.sf-sig-msg { color: var(--fs-text-strong); font-weight: 500; overflow-wrap: anywhere; }
.sf-sig-meta { display: flex; flex-wrap: wrap; align-items: center; gap: .15rem .6rem; margin-top: .15rem; font-size: var(--fs-fs-sm); }
.sf-gidsid { padding: 0; border: 0; background: none; color: var(--fs-coral-text); font-family: var(--fs-font-mono, var(--bs-font-monospace)); font-size: var(--fs-fs-sm); }
.sf-gidsid:hover, .sf-gidsid:focus-visible { text-decoration: underline; }
.sf-ip { overflow-wrap: anywhere; }
.sf-hostactions { display: inline-flex; gap: 0; margin-left: .25rem; vertical-align: middle; }
.sf-hostactions .fs-action { width: 1.6rem; height: 1.6rem; }
.sf-done { opacity: .45; cursor: default; }
.sf-time { white-space: nowrap; }
tr.sf-row-drop > td:first-child { box-shadow: inset 3px 0 0 var(--fs-block, var(--bs-danger)); }
.sf-instance { width: auto; max-width: 18rem; }
.sf-advfilter { padding: var(--fs-sp-3) var(--fs-sp-4); border-bottom: 1px solid var(--fs-border); }
.sf-advgrid { display: grid; grid-template-columns: repeat(auto-fill, minmax(11rem, 1fr)); gap: .6rem 1rem; }
.sf-advgrid .form-label { margin-bottom: .2rem; font-size: var(--fs-fs-sm); color: var(--fs-text-muted); }
.sf-advchecks { display: flex; flex-wrap: wrap; gap: .4rem 1.25rem; margin-top: .75rem; }
.sf-advbuttons { display: flex; flex-wrap: wrap; gap: .5rem; margin-top: .75rem; }
.sf-filtered { display: flex; flex-wrap: wrap; align-items: center; gap: .5rem; }
.sf-notes { display: flex; flex-wrap: wrap; gap: .4rem 1.5rem; margin: -.5rem 0 var(--fs-sp-5); color: var(--fs-text-muted); font-size: var(--fs-fs-sm); }
.sf-rule-meta { display: flex; flex-wrap: wrap; gap: .25rem 1rem; margin-bottom: .75rem; font-size: var(--fs-fs-sm); }
.sf-lookup dl { display: grid; grid-template-columns: 8rem minmax(0, 1fr); gap: .5rem 1rem; margin: 0; }
.sf-lookup dt { color: var(--fs-text-muted); font-weight: 500; }
.sf-lookup dd { margin: 0; overflow-wrap: anywhere; white-space: pre-line; }
@media (max-width: 575.98px) { .sf-lookup dl { grid-template-columns: 1fr; gap: .15rem; } .sf-lookup dd { margin-bottom: .5rem; } }
</style>

<div class="fs-tiles">
<?php
	fs_tile(gettext('Alerts shown'), count($alerts), null, $is_filtered ? gettext('Filtered view') : sprintf(gettext('Last %s log lines'), $anentries));
	fs_tile(gettext('High priority'), $sum_high, $sum_high ? 'warn' : null);
	fs_tile(gettext('Signatures'), count($sum_sig));
	if ($is_ips_view) {
		fs_tile(gettext('Dropped'), $sum_drop, $sum_drop ? 'block' : null);
	} else {
		fs_tile(gettext('Source hosts'), count($sum_src));
	}
?>
</div>

<form action="/suricata/suricata_alerts.php" method="post" name="formalert" id="formalert">
	<input type="hidden" name="sidid" id="sidid" value="">
	<input type="hidden" name="ip" id="ip" value="">
	<input type="hidden" name="gen_id" id="gen_id" value="">
	<input type="hidden" name="mode" id="mode" value="">
	<input type="hidden" name="descr" id="descr" value="">
<?php if ($persist_filter_log_entries == "yes"): ?>
	<input type="hidden" name="persist_filter" id="persist_filter" value="<?=fs_h($persist_filter_log_entries)?>">
	<input type="hidden" name="persist_filter_exact_match" id="persist_filter_exact_match" value="<?=fs_h($filterlogentries_exact_match)?>">
	<input type="hidden" name="persist_filter_content" id="persist_filter_content" value="<?=fs_h(json_encode($filterfieldsarray))?>">
<?php endif; ?>

<div class="panel panel-default fs-table">
<?php
	$instance_select = '<select class="form-select form-select-sm sf-instance" name="instance" id="instance" aria-label="' . fs_h(gettext('Interface')) . '">';
	foreach (build_instance_list() as $k => $v) {
		$instance_select .= '<option value="' . fs_h($k) . '"' . (((string)$k === (string)$instanceid) ? ' selected' : '') . '>' . fs_h($v) . '</option>';
	}
	$instance_select .= '</select>';

	$active_filters = count(array_filter($filterfieldsarray, function ($v) { return $v !== null && $v !== ''; }));
	$filter_btn = '<button type="button" class="btn btn-sm btn-outline-secondary" data-bs-toggle="collapse" data-bs-target="#sf-advfilter" aria-expanded="' . ($is_filtered ? 'true' : 'false') . '" aria-controls="sf-advfilter">'
	    . '<i class="fa-solid fa-filter icon-embed-btn" aria-hidden="true"></i>' . fs_h(gettext('Advanced filter'))
	    . ($active_filters ? ' <span class="badge text-bg-secondary">' . (int)$active_filters . '</span>' : '') . '</button>';

	$filters = array('pri' => array(gettext('All priorities'), '1' => gettext('1 · High'), '2' => gettext('2 · Medium'), '3' => gettext('3 · Low'), '4' => gettext('4 · Info')));
	if (count($protos) > 1) {
		$filters['proto'] = array(gettext('All protocols')) + array_combine(array_keys($protos), array_values($protos));
	}
	if ($is_ips_view) {
		$filters['action'] = array(gettext('All actions'), 'dropped' => gettext('Dropped'), 'alert' => gettext('Alert only'));
	}

	fs_table_toolbar(array(
		'search' => gettext('Search signatures, addresses, classes…'),
		'noun' => gettext('alerts'),
		'noun_one' => gettext('alert'),
		'custom' => $instance_select,
		'filters' => $filters,
		'actions' => $filter_btn,
	));
?>
	<div class="collapse sf-advfilter<?=$is_filtered ? ' show' : ''?>" id="sf-advfilter">
		<p class="fs-muted small mb-2"><?=gettext('Matches the whole log window on the server. Prefix a value with ! to exclude it; values are regular expressions unless exact match is on.')?></p>
		<div class="sf-advgrid">
<?php
	foreach (array(
		array('filterlogentries_time', gettext('Date'), 'time'),
		array('filterlogentries_priority', gettext('Priority'), 'priority'),
		array('filterlogentries_protocol', gettext('Protocol'), 'proto'),
		array('filterlogentries_classification', gettext('Classification'), 'class'),
		array('filterlogentries_sourceipaddress', gettext('Source address'), 'src'),
		array('filterlogentries_sourceport', gettext('Source port'), 'sport'),
		array('filterlogentries_destinationipaddress', gettext('Destination address'), 'dst'),
		array('filterlogentries_destinationport', gettext('Destination port'), 'dport'),
		array('filterlogentries_gid', gettext('GID'), 'gid'),
		array('filterlogentries_sid', gettext('SID'), 'sid'),
		array('filterlogentries_description', gettext('Description'), 'msg'),
	) as $ff):
?>
			<div>
				<label class="form-label" for="<?=$ff[0]?>"><?=fs_h($ff[1])?></label>
				<input type="text" class="form-control form-control-sm<?=in_array($ff[2], array('src', 'dst', 'sport', 'dport', 'gid', 'sid')) ? ' fs-mono' : ''?>" name="<?=$ff[0]?>" id="<?=$ff[0]?>" value="<?=fs_h($filterfieldsarray[$ff[2]] ?? '')?>">
			</div>
<?php endforeach; ?>
		</div>
		<div class="sf-advchecks">
<?php if ($a_instance['ips_mode'] == 'ips_mode_inline'): ?>
			<div class="form-check"><input class="form-check-input" type="checkbox" name="filterlogentries_action_drop" id="filterlogentries_action_drop" value="Drop"<?=($filterfieldsarray['action'] ?? '') == "Drop" ? ' checked' : ''?>><label class="form-check-label" for="filterlogentries_action_drop"><?=gettext('Dropped only')?></label></div>
			<div class="form-check"><input class="form-check-input" type="checkbox" name="filterlogentries_action_ndrop" id="filterlogentries_action_ndrop" value="!Drop"<?=($filterfieldsarray['action'] ?? '') == "!Drop" ? ' checked' : ''?>><label class="form-check-label" for="filterlogentries_action_ndrop"><?=gettext('Not dropped')?></label></div>
<?php endif; ?>
			<div class="form-check"><input class="form-check-input" type="checkbox" name="filterlogentries_exact_match" id="filterlogentries_exact_match" value="on"<?=$filterlogentries_exact_match == "on" ? ' checked' : ''?>><label class="form-check-label" for="filterlogentries_exact_match"><?=gettext('Exact match only')?></label></div>
		</div>
		<div class="sf-advbuttons">
			<button type="submit" class="btn btn-sm btn-primary" name="filterlogentries_submit" id="filterlogentries_submit" value="Apply Filter"><i class="fa-solid fa-filter icon-embed-btn" aria-hidden="true"></i><?=gettext('Apply filter')?></button>
			<button type="submit" class="btn btn-sm btn-outline-secondary no-confirm" name="filterlogentries_clear" id="filterlogentries_clear" value="Clear Filter"><?=gettext('Clear filter')?></button>
		</div>
	</div>
	<div class="panel-body table-responsive">
		<table class="table table-hover" data-sortable>
			<thead>
				<tr>
					<th data-sortable-type="alpha"><?=gettext("Time")?></th>
					<th data-sortable-type="numeric"><?=gettext("Priority")?></th>
<?php if ($is_ips_view): ?>
					<th><?=gettext("Action")?></th>
<?php endif; ?>
					<th data-fs-search><?=gettext("Signature")?></th>
					<th data-fs-search><?=gettext("Source")?></th>
					<th data-fs-search><?=gettext("Destination")?></th>
					<th data-fs-search><?=gettext("Protocol")?></th>
					<th class="fs-col-actions"><span class="visually-hidden"><?=gettext('Actions')?></span></th>
				</tr>
			</thead>
			<tbody>
<?php foreach ($alerts as $a):
	$f = $a['f'];
	$gidsid = "{$f['gid']}:{$f['sid']}";
	$dropped = !empty($f['action']);
	$rule_disabled = isset($disablesid[$f['gid']][$f['sid']]);
	$suppressed = suricata_is_alert_globally_suppressed($supplist, $f['gid'], $f['sid']);
?>
				<tr data-fs-filter-pri="<?=fs_h(in_array($f['priority'], array('1', '2', '3'), true) ? $f['priority'] : '4')?>" data-fs-filter-proto="<?=fs_h(strtolower($f['proto']))?>" data-fs-filter-action="<?=$dropped ? 'dropped' : 'alert'?>"<?=$dropped ? ' class="sf-row-drop"' : ''?>>
					<td class="fs-mono sf-time" data-value="<?=fs_h($f['time'])?>"><?=fs_h($a['clock'])?><div class="fs-muted small"><?=fs_h($a['date'])?></div></td>
					<td data-value="<?=fs_h($f['priority'])?>"><?=$sf_pri($f['priority'])?></td>
<?php if ($is_ips_view):
	if (!$dropped) {
		$act = fs_badge('warn', gettext('Alert'));
	} elseif ($a_instance['ips_mode'] == 'ips_mode_inline' && isset($rejectsid[$f['gid']][$f['sid']])) {
		$act = fs_badge('reject', gettext('Rejected'));
	} else {
		$act = fs_badge('block', gettext('Dropped'));
	}
	if (isset($dropsid[$f['gid']][$f['sid']]) || isset($alertsid[$f['gid']][$f['sid']]) || isset($rejectsid[$f['gid']][$f['sid']])) {
		$act .= '<div class="fs-muted small">' . fs_h(gettext('Forced by user')) . '</div>';
	}
?>
					<td><?=$act?></td>
<?php endif; ?>
					<td class="sf-sig">
						<div class="sf-sig-msg"><?=fs_h($f['msg'])?></div>
						<div class="sf-sig-meta">
							<button type="button" class="sf-gidsid" data-sf-rule="<?=fs_h($gidsid)?>" title="<?=fs_h(sprintf(gettext('Show rule %s'), $gidsid))?>"><?=fs_h($gidsid)?></button>
							<span class="fs-muted"><?=fs_h($f['class'])?></span>
<?php if ($suppressed): ?>
							<span class="fs-chip fs-chip--muted"><?=gettext('Suppressed')?></span>
<?php endif; ?>
<?php if ($rule_disabled): ?>
							<span class="fs-chip is-off"><?=gettext('Rule disabled')?></span>
<?php endif; ?>
						</div>
					</td>
<?php if ($a['decoder']): ?>
					<td colspan="2"><span title="<?=fs_h($a['raw'] !== '' ? '[Raw pkt: ' . $a['raw'] . ']' : '')?>"><?=fs_badge('info', gettext('Decoder event'))?></span></td>
<?php else: ?>
					<td><?=$sf_host($a, 'src')?></td>
					<td><?=$sf_host($a, 'dst')?></td>
<?php endif; ?>
					<td class="fs-mono"><?=fs_h($f['proto'])?></td>
					<td class="fs-col-actions"><div class="fs-actions">
						<button type="button" class="fs-action" data-sf-rule="<?=fs_h($gidsid)?>" title="<?=fs_h(sprintf(gettext('Show rule %s'), $gidsid))?>" aria-label="<?=fs_h(sprintf(gettext('Show rule %s'), $gidsid))?>"><i class="fa-solid fa-file-lines" aria-hidden="true"></i></button>
<?php if ($can_change_action): ?>
						<a class="fs-action" href="#" data-fs-modal="#sid-action" data-fs-modal-title="<?=fs_h(sprintf(gettext('Action for rule %s'), $gidsid))?>" data-fs-fill="<?=fs_h(json_encode(array('gen_id' => $f['gid'], 'sidid' => $f['sid'])))?>" title="<?=fs_h(sprintf(gettext('Change the action of rule %s'), $gidsid))?>" aria-label="<?=fs_h(sprintf(gettext('Change the action of rule %s'), $gidsid))?>"><i class="fa-solid fa-sliders" aria-hidden="true"></i></a>
<?php endif; ?>
<?php if (!$suppressed): ?>
						<?=$sf_btn('fa-bell-slash', sprintf(gettext('Suppress rule %s'), $gidsid),
							array('mode' => 'addsuppress', 'gid' => $f['gid'], 'sid' => $f['sid'], 'ip' => '', 'descr' => $f['msg']),
							sprintf(gettext('Suppress all alerts of rule %s?'), $gidsid),
							gettext('A suppress entry is added to the interface Suppress List and Suricata reloads its rules. The rule keeps running but no longer alerts.'),
							gettext('Suppress'))?>
<?php endif; ?>
<?php if ($rule_disabled): ?>
						<?=$sf_btn('fa-regular fa-square-check', sprintf(gettext('Remove the forced disable of rule %s'), $gidsid),
							array('mode' => 'togglesid', 'gid' => $f['gid'], 'sid' => $f['sid'], 'ip' => '', 'descr' => ''),
							sprintf(gettext('Remove the forced disable of rule %s?'), $gidsid),
							gettext('The rule returns to its default state and Suricata reloads its rules.'),
							gettext('Re-enable'))?>
<?php else: ?>
						<?=$sf_btn('fa-ban', sprintf(gettext('Disable rule %s'), $gidsid),
							array('mode' => 'togglesid', 'gid' => $f['gid'], 'sid' => $f['sid'], 'ip' => '', 'descr' => ''),
							sprintf(gettext('Disable rule %s on this interface?'), $gidsid),
							gettext('The rule is forced off and removed from the active rule set; Suricata reloads its rules.'),
							gettext('Disable rule'))?>
<?php endif; ?>
					</div></td>
				</tr>
<?php endforeach; ?>
<?php
	if (empty($alerts)) {
		fs_empty_row($is_ips_view ? 8 : 7, $is_filtered ? gettext('No alerts match the advanced filter.') : gettext('No alerts were logged on this interface.'));
	}
?>
			</tbody>
		</table>
	</div>
</div>
</form>

<div class="sf-notes">
<?php if ($is_ips_view): ?>
	<span><?=gettext('Rows with a red edge were dropped (blocked) by a DROP rule.')?></span>
<?php endif; ?>
	<span><?=sprintf(gettext('Showing up to the last %s log lines, most recent first.'), (int)$anentries)?></span>
<?php if ($pconfig['arefresh'] == 'on'): ?>
	<span><?=gettext('The page refreshes every 60 seconds.')?></span>
<?php endif; ?>
</div>

<?php
fs_modal_form_begin('alerts-settings', gettext('Alert view settings'), '/suricata/suricata_alerts.php', array('instance' => $instanceid));
?>
	<div class="mb-3 form-check">
		<input class="form-check-input" type="checkbox" name="arefresh" id="arefresh" value="on"<?=($pconfig['arefresh'] == 'on') ? ' checked' : ''?>>
		<label class="form-check-label" for="arefresh"><?=gettext('Refresh the page every 60 seconds')?></label>
	</div>
	<div class="mb-1">
		<label class="form-label" for="alertnumber"><?=gettext('Alerts to show')?></label>
		<input class="form-control" type="number" min="1" name="alertnumber" id="alertnumber" value="<?=fs_h($anentries)?>">
		<div class="form-text"><?=gettext('Number of most recent log lines to read. Default is 250.')?></div>
	</div>
<?php
fs_modal_form_end(gettext('Save'), 'save', 'Save', 'fa-floppy-disk');

if ($can_change_action) {
	$hidden = array('instance' => $instanceid, 'mode' => 'toggle_action', 'gen_id' => '', 'sidid' => '');
	if ($persist_filter_log_entries == "yes") {
		$hidden['persist_filter'] = $persist_filter_log_entries;
		$hidden['persist_filter_exact_match'] = $filterlogentries_exact_match;
		$hidden['persist_filter_content'] = json_encode($filterfieldsarray);
	}
	fs_modal_form_begin('sid-action', gettext('Rule action'), '/suricata/suricata_alerts.php', $hidden);
	$choices = array('action_default' => array(gettext('Default'), gettext('The action the rule author set, usually alert.')),
	    'action_alert' => array(gettext('Alert'), gettext('Log the alert, let the traffic pass.')),
	    'action_drop' => array(gettext('Drop'), gettext('Drop the traffic and log the alert.')));
	if ($a_instance['ips_mode'] == 'ips_mode_inline') {
		$choices['action_reject'] = array(gettext('Reject'), gettext('Drop the traffic and send a reset or ICMP unreachable.'));
	}
	foreach ($choices as $value => $c):
?>
	<div class="form-check mb-2">
		<input class="form-check-input" type="radio" name="ruleActionOptions" id="<?=$value?>" value="<?=$value?>"<?=($value === 'action_default') ? ' required' : ''?>>
		<label class="form-check-label" for="<?=$value?>"><strong><?=fs_h($c[0])?></strong> <span class="fs-muted"><?=fs_h($c[1])?></span></label>
	</div>
<?php
	endforeach;
	fs_modal_form_end(gettext('Save'), 'rule_action_save', 'Save', 'fa-floppy-disk');
}
?>

<div class="modal fade" id="rulesviewer" tabindex="-1" aria-labelledby="rulesviewer-title" aria-hidden="true">
	<div class="modal-dialog modal-lg modal-dialog-centered modal-dialog-scrollable">
		<div class="modal-content">
			<div class="modal-header">
				<h2 class="modal-title" id="rulesviewer-title"><?=gettext('Rule')?></h2>
				<button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="<?=gettext('Close')?>"></button>
			</div>
			<div class="modal-body">
				<div class="sf-rule-meta">
					<span><span class="fs-muted"><?=gettext('Category')?></span> <span class="fs-mono" id="modal_rule_category"></span></span>
					<span id="modal_rule_doc" hidden><span class="fs-muted"><?=gettext('Rule documentation')?></span> <a id="modal_rule_link" target="_blank" rel="noopener noreferrer"></a></span>
				</div>
				<pre class="fs-console" id="rulesviewer_text"></pre>
			</div>
			<div class="modal-footer">
				<button type="button" class="btn btn-outline-secondary" data-fs-copy="#rulesviewer_text"><i class="fa-regular fa-copy icon-embed-btn" aria-hidden="true"></i><?=gettext('Copy')?></button>
				<button type="button" class="btn btn-primary" data-bs-dismiss="modal"><?=gettext('Close')?></button>
			</div>
		</div>
	</div>
</div>

<div class="modal fade" id="sf-lookup" tabindex="-1" aria-labelledby="sf-lookup-title" aria-hidden="true">
	<div class="modal-dialog modal-dialog-centered">
		<div class="modal-content">
			<div class="modal-header">
				<h2 class="modal-title" id="sf-lookup-title"><?=gettext('Host lookup')?></h2>
				<button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="<?=gettext('Close')?>"></button>
			</div>
			<div class="modal-body sf-lookup">
				<dl>
					<dt><?=gettext('Address')?></dt><dd class="fs-mono" id="sf-lookup-ip"></dd>
					<dt><?=gettext('Reverse DNS')?></dt><dd id="sf-lookup-dns"></dd>
					<dt><?=gettext('GeoIP')?></dt><dd id="sf-lookup-geo"></dd>
				</dl>
			</div>
			<div class="modal-footer">
				<button type="button" class="btn btn-primary" data-bs-dismiss="modal"><?=gettext('Close')?></button>
			</div>
		</div>
	</div>
</div>

<script type="text/javascript">
//<![CDATA[
events.push(function() {
	var page = "/suricata/suricata_alerts.php";
	var instance = <?=json_encode((string)$instanceid)?>;
	var form = document.getElementById('formalert');
	var loading = <?=json_encode(gettext('Loading…'))?>;

	function parse(req) {
		try { return JSON.parse(req.responseText); } catch (e) { return {}; }
	}

	// Pick another interface: post the form so an active filter is kept
	$('#instance').on('change', function() {
		form.submit();
	});

	// Row actions copy their values into the hidden fields, then the form posts
	document.addEventListener('click', function(e) {
		var btn = e.target.closest('button[data-sf-mode]');
		if (!btn || e.defaultPrevented) {
			return;
		}
		$('#mode').val(btn.getAttribute('data-sf-mode'));
		$('#gen_id').val(btn.getAttribute('data-sf-gid') || '');
		$('#sidid').val(btn.getAttribute('data-sf-sid') || '');
		$('#ip').val(btn.getAttribute('data-sf-ip') || '');
		$('#descr').val(btn.getAttribute('data-sf-descr') || '');
	});

	// Rule text
	document.addEventListener('click', function(e) {
		var btn = e.target.closest('[data-sf-rule]');
		if (!btn) {
			return;
		}
		var gs = btn.getAttribute('data-sf-rule').split(':');
		$('#rulesviewer-title').text(<?=json_encode(gettext('Rule'))?> + ' ' + gs[0] + ':' + gs[1]);
		$('#rulesviewer_text').text(loading);
		$('#modal_rule_category').text('');
		$('#modal_rule_doc').prop('hidden', true);
		bootstrap.Modal.getOrCreateInstance(document.getElementById('rulesviewer')).show();
		$.ajax(page, {
			type: 'post',
			data: {gid: gs[0], sid: gs[1], instance: instance, action: 'loadRule'},
			complete: function(req) {
				var r = parse(req);
				var text = '';
				try { text = atob(r.rule_text || ''); } catch (err) { text = ''; }
				$('#rulesviewer_text').text(text || <?=json_encode(gettext('The rule text could not be loaded.'))?>);
				$('#modal_rule_category').text(r.category || '');
				if (r.rule_link) {
					$('#modal_rule_link').attr('href', r.rule_link).text(r.rule_link);
					$('#modal_rule_doc').prop('hidden', false);
				}
			}
		});
	});

	// Host lookup: reverse DNS, and GeoIP for public addresses
	document.addEventListener('click', function(e) {
		var btn = e.target.closest('[data-sf-lookup]');
		if (!btn) {
			return;
		}
		var ip = btn.getAttribute('data-sf-lookup');
		$('#sf-lookup-ip').text(ip);
		$('#sf-lookup-dns').text(loading);
		bootstrap.Modal.getOrCreateInstance(document.getElementById('sf-lookup')).show();
		$.ajax(page, {type: 'post', dataType: 'json', data: {resolve: ip}, complete: function(req) {
			$('#sf-lookup-dns').text(parse(req).resolve_text || <?=json_encode(gettext('Cannot resolve'))?>);
		}});
		if (btn.getAttribute('data-sf-geo') === '1') {
			$('#sf-lookup-geo').text(loading);
			$.ajax(page, {type: 'post', dataType: 'json', data: {geoip: ip}, complete: function(req) {
				$('#sf-lookup-geo').text(parse(req).geoip_text || <?=json_encode(gettext('Not available'))?>);
			}});
		} else {
			$('#sf-lookup-geo').text(<?=json_encode(gettext('Private address'))?>);
		}
	});

	// Dropped / not dropped filters exclude each other
	$('#filterlogentries_action_drop').on('click', function() {
		$('#filterlogentries_action_ndrop').prop('checked', false);
	});
	$('#filterlogentries_action_ndrop').on('click', function() {
		$('#filterlogentries_action_drop').prop('checked', false);
	});
});
//]]>
</script>
<?php
include("foot.inc");
?>
