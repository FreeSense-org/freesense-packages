<?php
/*
 * suricata_rules.php
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
$rules_map = array();
$pconfig = array();
$filterrules = FALSE;

if (isset($_POST['id']) && is_numericint($_POST['id']))
	$id = $_POST['id'];
elseif (isset($_GET['id']) && is_numericint($_GET['id']))
	$id = htmlspecialchars($_GET['id']);

// If postback is from system function print_apply_box(),
// then we won't have our customary $_POST['id'] and
// $_POST['openruleset'] fields set in the response,
// but the system function will pass back a
// $_POST['if'] field we can use instead.
if (!is_numericint($id)) {
	if (isset($_POST['if'])) {
		// Split the posted string at the '|' delimiter
		$response = explode('|', $_POST['if']);
		$id = $response[0];
		$_POST['openruleset'] = $response[1];
	}
	else {
		$id = 0;
	}
}

$a_rule = config_get_path("installedpackages/suricata/rule/{$id}", []);

if (!empty($a_rule)) {
	$pconfig['interface'] = $a_rule['interface'];
	$pconfig['rulesets'] = $a_rule['rulesets'];
	$pconfig['customrules'] = base64_decode($a_rule['customrules']);
}

function add_title_attribute($tag, $title) {

	/********************************
	 * This function adds a "title" *
	 * attribute to the passed tag  *
	 * and sets the value to the    *
	 * value specified by "$title". *
	 ********************************/
	$result = "";
	if (empty($tag)) {
		// If passed an empty element tag, then
		// just create a <span> tag with title
		$result = "<span title=\"" . $title . "\">";
	}
	else {
		// Find the ending ">" for the element tag
		$pos = strpos($tag, ">");
		if ($pos !== false) {
			// We found the ">" delimter, so add "title"
			// attribute and close the element tag
			$result = substr($tag, 0, $pos) . " title=\"" . $title . "\">";
		}
		else {
			// We did not find the ">" delimiter, so
			// something is wrong, just return the
			// tag "as-is"
			$result = $tag;
		}
	}
	return $result;
}

/* convert fake interfaces to real */
$if_real = get_real_interface($pconfig['interface']);
$suricata_uuid = $a_rule['uuid'];
$suricatacfgdir = "{$suricatadir}suricata_{$suricata_uuid}_{$if_real}";
$suricata_rules_dir = SURICATA_RULES_DIR;
$snortdownload = config_get_path('installedpackages/suricata/config/0/enable_vrt_rules');
$emergingdownload = config_get_path('installedpackages/suricata/config/0/enable_etopen_rules');
$etpro = config_get_path('installedpackages/suricata/config/0/enable_etpro_rules');
$categories = explode("||", $pconfig['rulesets']);

// Get any automatic rule category enable/disable modifications
// if auto-SID Mgmt is enabled, and adjust the available rulesets
// in the CATEGORY drop-down box as necessary by removing disabled
// categories and adding enabled ones.
$cat_mods = suricata_sid_mgmt_auto_categories($a_rule, FALSE);
foreach ($cat_mods as $k => $v) {
	switch ($v) {
		case 'disabled':
			if (($key = array_search($k, $categories, true)) !== FALSE)
				unset($categories[$key]);
			break;

		case 'enabled':
			if (!in_array($k, $categories))
				$categories[] = $k;
			break;

		default:
			break;
	}
}

// Add custom Categories list items for User Forced rules
$categories[] = "User Forced Enabled Rules";
$categories[] = "User Forced Disabled Rules";

// Only add custom ALERT or DROP Action Rules
// option if blocking is enabled.
if ($a_rule['blockoffenders'] == 'on') {
	$categories[] = "User Forced ALERT Action Rules";

	// Show custom DROP rules only if using Inline IPS
	// mode or "Block Drops Only" option.
	if ($a_rule['block_drops_only'] == 'on' || $a_rule['ips_mode'] == 'ips_mode_inline') {
		$categories[] = "User Forced DROP Action Rules";
	}
}

// Only add custom REJECT option if using IPS Inline Mode with blocking enabled
if ($a_rule['ips_mode'] == 'ips_mode_inline' && $a_rule['blockoffenders'] == 'on') {
	$categories[] = "User Forced REJECT Action Rules";
}

// Add custom Category to view all Active Rules
// on the interface.
$categories[] = "Active Rules";

// See if we should open a specific ruleset or
// just default to the first one in the list.
if ($_GET['openruleset'])
	$currentruleset = htmlspecialchars($_GET['openruleset'], ENT_QUOTES | ENT_HTML401);
elseif ($_POST['selectbox'])
	$currentruleset = $_POST['selectbox'];
elseif ($_POST['openruleset'])
	$currentruleset = $_POST['openruleset'];
else
	$currentruleset = $categories[array_key_first($categories)];

$currentruleset = basename($currentruleset);

// If we don't have any Category to display, then
// default to showing the Custom Rules text control.
if (empty($categories) && ($currentruleset != "custom.rules") && ($currentruleset != "Auto-Flowbit Rules")) {
	if (!empty($a_rule['ips_policy']))
		$currentruleset = "IPS Policy - " . ucfirst($a_rule['ips_policy']);
	else
		$currentruleset = "custom.rules";
}

// One last sanity check -- if the rules directory is empty, or we were
// not passed a ruleset name to load, default to loading custom rules.
$tmp = glob("{$suricata_rules_dir}*.rules");
if (empty($tmp) || empty($currentruleset))
	$currentruleset = "custom.rules";

$ruledir = SURICATA_RULES_DIR;
$rulefile = "{$ruledir}{$currentruleset}";

if ($currentruleset != 'custom.rules') {
	// Read the currently selected rules file into our rules map array.
	// There are a few special cases possible, so test and adjust as
	// necessary to get the correct set of rules to display.

	// If it is the auto-flowbits file, set the full path.
	if ($currentruleset == "Auto-Flowbit Rules") {
		$rules_map = suricata_load_rules_map("{$suricatacfgdir}/rules/" . FLOWBITS_FILENAME);
	}
	// Test for the special case of an IPS Policy file
	// and load the selected policy's rules.
	elseif (substr($currentruleset, 0, 10) == "IPS Policy") {
		$rules_map = suricata_load_vrt_policy($a_rule['ips_policy'], $a_rule['ips_policy_mode']);
	}
	// Test for the special case of "Active Rules".  This
	// displays all currently active rules for the
	// interface.
	elseif ($currentruleset == "Active Rules") {
		$rules_map = suricata_load_rules_map("{$suricatacfgdir}/rules/");
	}
	// Test for the special cases of "User Forced" rules
	// and load the required rules for display.
	elseif ($currentruleset == "User Forced Enabled Rules") {
		// Search and display forced enabled rules only from
		// the enabled rule categories for this interface.
		$rule_files = explode("||", $pconfig['rulesets']);

		// Prepend the Suricata rules path to each entry.
		foreach ($rule_files as $k => $v) {
			$rule_files[$k] = $ruledir . $v;
		}
		$rule_files[] = "{$suricatacfgdir}/rules/" . FLOWBITS_FILENAME;
		$rule_files[] = "{$suricatacfgdir}/rules/custom.rules";
		$rules_map = suricata_get_filtered_rules($rule_files, suricata_load_sid_mods($a_rule['rule_sid_on']));
	}
	elseif ($currentruleset == "User Forced Disabled Rules") {
		// Search and display forced disabled rules only from
		// the enabled rule categories for this interface.
		$rule_files = explode("||", $pconfig['rulesets']);

		// Prepend the Suricata rules path to each entry.
		foreach ($rule_files as $k => $v) {
			$rule_files[$k] = $ruledir . $v;
		}
		$rule_files[] = "{$suricatacfgdir}/rules/" . FLOWBITS_FILENAME;
		$rule_files[] = "{$suricatacfgdir}/rules/custom.rules";
		$rules_map = suricata_get_filtered_rules($rule_files, suricata_load_sid_mods($a_rule['rule_sid_off']));
	}
	elseif ($currentruleset == "User Forced ALERT Action Rules") {
		$rules_map = suricata_get_filtered_rules("{$suricatacfgdir}/rules/", suricata_load_sid_mods($a_rule['rule_sid_force_alert']));
	}
	elseif ($currentruleset == "User Forced DROP Action Rules") {
		$rules_map = suricata_get_filtered_rules("{$suricatacfgdir}/rules/", suricata_load_sid_mods($a_rule['rule_sid_force_drop']));
	}
	elseif ($currentruleset == "User Forced REJECT Action Rules") {
		$rules_map = suricata_get_filtered_rules("{$suricatacfgdir}/rules/", suricata_load_sid_mods($a_rule['rule_sid_force_reject']));
	}
	// If it's not a special case, and we can't find
	// the given rule file, then notify the user.
	elseif (!file_exists($rulefile)) {
		$input_errors[] = gettext("{$currentruleset} seems to be missing!!! Please verify rules files have been downloaded, then go to the Categories tab and save the rule set again.");
	}
	// Not a special case, and we have the matching
	// rule file, so load it up for display.
	else {
		$rules_map = suricata_load_rules_map($rulefile);
	}
}

/* Process the current category rules through any auto SID MGMT changes if enabled */
suricata_auto_sid_mgmt($rules_map, $a_rule, FALSE);

/* Load up our enablesid and disablesid arrays with manually enabled or disabled SIDs */
$enablesid = suricata_load_sid_mods($a_rule['rule_sid_on']);
$disablesid = suricata_load_sid_mods($a_rule['rule_sid_off']);
suricata_modify_sids($rules_map, $a_rule);

/* Load up our rule action arrays with manually changed SID actions */
$alertsid = suricata_load_sid_mods($a_rule['rule_sid_force_alert']);
$dropsid = suricata_load_sid_mods($a_rule['rule_sid_force_drop']);
$rejectsid = suricata_load_sid_mods($a_rule['rule_sid_force_reject']);
suricata_modify_sids_action($rules_map, $a_rule);

/* Process AJAX request to view content of a specific rule */
if ($_POST['action'] == 'loadRule') {
	if (isset($_POST['gid']) && isset($_POST['sid'])) {
		$gid = $_POST['gid'];
		$sid = $_POST['sid'];
		$rule_text = base64_encode($rules_map[$gid][$sid]['rule']);
	}
	else {
		$rule_text = base64_encode(gettext('Invalid rule signature - no matching rule was found!'));
	}
	if (strpos($currentruleset, 'snort_') !== false) {
		$rule_link = "https://www.snort.org/rule_docs/{$gid}-{$sid}";
	} else {
		$rule_link = "";
	}	
	$response = array('rule_text' => $rule_text, 'rule_link' => $rule_link);
	echo json_encode(str_replace("\\","\\\\", $response)); // single escape chars can break JSON decode
	exit;
}

if (isset($_POST['rule_state_save']) && isset($_POST['ruleStateOptions']) && is_numeric($_POST['sid']) && is_numeric($_POST['gid']) && !empty($rules_map)) {

	// Get the GID:SID tags embedded in the clicked rule icon.
	$gid = $_POST['gid'];
	$sid = $_POST['sid'];

	// Get the posted rule state
	$state = $_POST['ruleStateOptions'];

	// Use the user-desired rule state to set or clear
	// entries in the Forced Rule State arrays stored
	// in the firewall config.xml configuration file.

	switch ($state) {
		case "state_default":
			// Return the rule to it's default state
			// by removing all state override entries.
			array_del_path($enablesid, "{$gid}/{$sid}");
			array_del_path($disablesid, "{$gid}/{$sid}");

			// Restore the default state flag so we
			// can display state properly on RULES
			// page without needing to reload the
			// entire set of rules.
			if (array_get_path($rules_map, "{$gid}/{$sid}")) {
				$rules_map[$gid][$sid]['disabled'] = !$rules_map[$gid][$sid]['default_state'];
			}
			break;

		case "state_enabled":
			array_del_path($disablesid, "{$gid}/{$sid}");
			array_set_path($enablesid, "{$gid}/{$sid}", 'enablesid');
			break;

		case "state_disabled":
			array_del_path($enablesid, "{$gid}/{$sid}");
			array_set_path($disablesid, "{$gid}/{$sid}", 'disablesid');
			break;

		default:
			$input_errors[] = gettext("WARNING - unknown rule state of '{$state}' passed in $_POST parameter.  No change made to rule state.");
	}

	// Write the updated enablesid and disablesid values to the config file.
	$tmp = "";
	foreach (array_keys($enablesid) as $k1) {
		foreach (array_keys($enablesid[$k1]) as $k2)
			$tmp .= "{$k1}:{$k2}||";
	}
	$tmp = rtrim($tmp, "||");

	if (!empty($tmp))
		$a_rule['rule_sid_on'] = $tmp;
	else
		unset($a_rule['rule_sid_on']);

	$tmp = "";
	foreach (array_keys($disablesid) as $k1) {
		foreach (array_keys($disablesid[$k1]) as $k2)
			$tmp .= "{$k1}:{$k2}||";
	}
	$tmp = rtrim($tmp, "||");

	if (!empty($tmp))
		$a_rule['rule_sid_off'] = $tmp;
	else
		unset($a_rule['rule_sid_off']);

	/* Update the config.xml file. */
	config_set_path("installedpackages/suricata/rule/{$id}", $a_rule);
	write_config("Suricata pkg: modified state for rule {$gid}:{$sid} on {$a_rule['interface']}.");

	// We changed a rule state, remind user to apply the changes
	mark_subsystem_dirty('suricata_rules');

	// Update our in-memory rules map with the changes just saved
	// to the Suricata configuration file.
	suricata_modify_sids($rules_map, $a_rule);

	// Set a scroll-to anchor location
	$anchor = "rule_{$gid}_{$sid}";
}
elseif (isset($_POST['rule_action_save']) && isset($_POST['ruleActionOptions']) && is_numeric($_POST['sid']) && is_numeric($_POST['gid']) && !empty($rules_map)) {

	// Get the GID:SID tags embedded in the clicked rule icon.
	$gid = $_POST['gid'];
	$sid = $_POST['sid'];

	// Get the posted rule action
	$action = $_POST['ruleActionOptions'];

	// Put the target SID in the appropriate lists of modified
	// SID actions based on the requested action; if default
	// action is requested, remove the SID from all SID modified
	// action lists.
	switch ($action) {
		case "action_default":
			$rules_map[$gid][$sid]['action'] = $rules_map[$gid][$sid]['default_action'];
			array_del_path($alertsid, "{$gid}/{$sid}");
			array_del_path($dropsid, "{$gid}/{$sid}");
			array_del_path($rejectsid, "{$gid}/{$sid}");
			break;

		case "action_alert":
			$rules_map[$gid][$sid]['action'] = $rules_map[$gid][$sid]['alert'];
			array_set_path($alertsid, "{$gid}/{$sid}", "alertsid");
			array_del_path($dropsid, "{$gid}/{$sid}");
			array_del_path($rejectsid, "{$gid}/{$sid}");
			break;

		case "action_drop":
			$rules_map[$gid][$sid]['action'] = $rules_map[$gid][$sid]['drop'];
			array_set_path($dropsid, "{$gid}/{$sid}", "dropsid");
			array_del_path($alertsid, "{$gid}/{$sid}");
			array_del_path($rejectsid, "{$gid}/{$sid}");
			break;

		case "action_reject":
			$rules_map[$gid][$sid]['action'] = $rules_map[$gid][$sid]['reject'];
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
			$a_rule['rule_sid_force_alert'] = $tmp;
		else
			unset($a_rule['rule_sid_force_alert']);

		$tmp = "";
		foreach (array_keys($dropsid) as $k1) {
			foreach (array_keys($dropsid[$k1]) as $k2)
				$tmp .= "{$k1}:{$k2}||";
		}
		$tmp = rtrim($tmp, "||");

		if (!empty($tmp))
			$a_rule['rule_sid_force_drop'] = $tmp;
		else
			unset($a_rule['rule_sid_force_drop']);

		$tmp = "";
		foreach (array_keys($rejectsid) as $k1) {
			foreach (array_keys($rejectsid[$k1]) as $k2)
				$tmp .= "{$k1}:{$k2}||";
		}
		$tmp = rtrim($tmp, "||");

		if (!empty($tmp))
			$a_rule['rule_sid_force_reject'] = $tmp;
		else
			unset($a_rule['rule_sid_force_reject']);

		/* Update the config.xml file. */
		config_set_path("installedpackages/suricata/rule/{$id}", $a_rule);
		write_config("Suricata pkg: modified action for rule {$gid}:{$sid} on {$a_rule['interface']}.");

		// We changed a rule action, remind user to apply the changes
		mark_subsystem_dirty('suricata_rules');

		// Update our in-memory rules map with the changes just saved
		// to the Suricata configuration file.
		suricata_modify_sids_action($rules_map, $a_rule);

		// Set a scroll-to anchor location
		$anchor = "rule_{$gid}_{$sid}";
	}
}
elseif (isset($_POST['disable_all']) && !empty($rules_map)) {
	// Mark all rules in the currently selected category "disabled".
	foreach (array_keys($rules_map) as $k1) {
		foreach (array_keys($rules_map[$k1]) as $k2) {
			array_del_path($enablesid, "{$k1}/{$k2}");
			array_set_path($disablesid, "{$k1}/{$k2}", 'disablesid');
		}
	}

	// Write the updated enablesid and disablesid values to the config file.
	$tmp = "";
	foreach (array_keys($enablesid) as $k1) {
		foreach (array_keys($enablesid[$k1]) as $k2)
			$tmp .= "{$k1}:{$k2}||";
	}
	$tmp = rtrim($tmp, "||");

	if (!empty($tmp))
		$a_rule['rule_sid_on'] = $tmp;
	else
		unset($a_rule['rule_sid_on']);

	$tmp = "";
	foreach (array_keys($disablesid) as $k1) {
		foreach (array_keys($disablesid[$k1]) as $k2)
			$tmp .= "{$k1}:{$k2}||";
	}
	$tmp = rtrim($tmp, "||");

	if (!empty($tmp))
		$a_rule['rule_sid_off'] = $tmp;
	else
		unset($a_rule['rule_sid_off']);

	// We changed a rule state, remind user to apply the changes
	mark_subsystem_dirty('suricata_rules');
	config_set_path("installedpackages/suricata/rule/{$id}", $a_rule);
	write_config("Suricata pkg: disabled all rules in category {$currentruleset} for {$a_rule['interface']}.");

	// Update our in-memory rules map with the changes just saved
	// to the Suricata configuration file.
	suricata_modify_sids($rules_map, $a_rule);
}
elseif (isset($_POST['enable_all']) && !empty($rules_map)) {

	// Mark all rules in the currently selected category "enabled".
	foreach (array_keys($rules_map) as $k1) {
		foreach (array_keys($rules_map[$k1]) as $k2) {
			array_del_path($disablesid, "{$k1}/{$k2}");
			array_set_path($enablesid, "{$k1}/{$k2}", 'enablesid');
		}
	}
	// Write the updated enablesid and disablesid values to the config file.
	$tmp = "";
	foreach (array_keys($enablesid) as $k1) {
		foreach (array_keys($enablesid[$k1]) as $k2)
			$tmp .= "{$k1}:{$k2}||";
	}
	$tmp = rtrim($tmp, "||");

	if (!empty($tmp))
		$a_rule['rule_sid_on'] = $tmp;
	else
		unset($a_rule['rule_sid_on']);

	$tmp = "";
	foreach (array_keys($disablesid) as $k1) {
		foreach (array_keys($disablesid[$k1]) as $k2)
			$tmp .= "{$k1}:{$k2}||";
	}
	$tmp = rtrim($tmp, "||");

	if (!empty($tmp))
		$a_rule['rule_sid_off'] = $tmp;
	else
		unset($a_rule['rule_sid_off']);

	// We changed a rule state, remind user to apply the changes
	mark_subsystem_dirty('suricata_rules');
	config_set_path("installedpackages/suricata/rule/{$id}", $a_rule);
	write_config("Suricata pkg: enable all rules in category {$currentruleset} for {$a_rule['interface']}.");

	// Update our in-memory rules map with the changes just saved
	// to the Suricata configuration file.
	suricata_modify_sids($rules_map, $a_rule);
}
elseif (isset($_POST['resetcategory']) && !empty($rules_map)) {

	// Reset any modified SIDs in the current rule category to their defaults.
	foreach (array_keys($rules_map) as $k1) {
		foreach (array_keys($rules_map[$k1]) as $k2) {
			array_del_path($enablesid, "{$k1}/{$k2}");
			array_del_path($disablesid, "{$k1}/{$k2}");
			array_del_path($alertsid, "{$k1}/{$k2}");
			array_del_path($dropsid, "{$k1}/{$k2}");
			array_del_path($rejectsid, "{$k1}/{$k2}");
		}
	}

	// Write the updated enablesid and disablesid values to the config file.
	$tmp = "";
	foreach (array_keys($enablesid) as $k1) {
		foreach (array_keys($enablesid[$k1]) as $k2)
			$tmp .= "{$k1}:{$k2}||";
	}
	$tmp = rtrim($tmp, "||");

	if (!empty($tmp))
		$a_rule['rule_sid_on'] = $tmp;
	else
		unset($a_rule['rule_sid_on']);

	$tmp = "";
	foreach (array_keys($disablesid) as $k1) {
		foreach (array_keys($disablesid[$k1]) as $k2)
			$tmp .= "{$k1}:{$k2}||";
	}
	$tmp = rtrim($tmp, "||");

	if (!empty($tmp))
		$a_rule['rule_sid_off'] = $tmp;
	else
		unset($a_rule['rule_sid_off']);

	// Write the updated alertsid, dropsid and rejectsid values to the config file.
	$tmp = "";
	foreach (array_keys($alertsid) as $k1) {
		foreach (array_keys($alertsid[$k1]) as $k2)
			$tmp .= "{$k1}:{$k2}||";
	}
	$tmp = rtrim($tmp, "||");

	if (!empty($tmp))
		$a_rule['rule_sid_force_alert'] = $tmp;
	else
		unset($a_rule['rule_sid_force_alert']);

	$tmp = "";
	foreach (array_keys($dropsid) as $k1) {
		foreach (array_keys($dropsid[$k1]) as $k2)
			$tmp .= "{$k1}:{$k2}||";
	}
	$tmp = rtrim($tmp, "||");

	if (!empty($tmp))
		$a_rule['rule_sid_force_drop'] = $tmp;
	else
		unset($a_rule['rule_sid_force_drop']);

	$tmp = "";
	foreach (array_keys($rejectsid) as $k1) {
		foreach (array_keys($rejectsid[$k1]) as $k2)
			$tmp .= "{$k1}:{$k2}||";
	}
	$tmp = rtrim($tmp, "||");

	if (!empty($tmp))
		$a_rule['rule_sid_force_reject'] = $tmp;
	else
		unset($a_rule['rule_sid_force_reject']);

	// We changed a rule state or action, remind user to apply the changes
	mark_subsystem_dirty('suricata_rules');
	config_set_path("installedpackages/suricata/rule/{$id}", $a_rule);
	write_config("Suricata pkg: remove rule state/action changes for category {$currentruleset} on {$a_rule['interface']}.");

	// Reload the rules so we can accurately show content after
	// resetting any user overrides.
	// Test for the auto-flowbits file.
	if ($currentruleset == "Auto-Flowbit Rules") {
		$rulefile = "{$suricatacfgdir}/rules/" . FLOWBITS_FILENAME;
		$rules_map = suricata_load_rules_map($rulefile);
	}
	// Test for the special case of an IPS Policy file
	// and load the selected policy's rules.
	elseif (substr($currentruleset, 0, 10) == "IPS Policy") {
		$rules_map = suricata_load_vrt_policy($a_rule['ips_policy'], $a_rule['ips_policy_mode']);
	}
	// Test for the special case of "Active Rules".  This
	// displays all currently active rules for the
	// interface.
	elseif ($currentruleset == "Active Rules") {
		$rules_map = suricata_load_rules_map("{$suricatacfgdir}/rules/");
	}
	// Test for the special cases of "User Forced" rules
	// and load the required rules for display.
	elseif ($currentruleset == "User Forced Enabled Rules") {
		// Search and display forced enabled rules only from
		// the enabled rule categories for this interface.
		$rule_files = explode("||", $pconfig['rulesets']);

		// Prepend the Suricata rules path to each entry.
		foreach ($rule_files as $k => $v) {
			$rule_files[$k] = $ruledir . $v;
		}
		$rule_files[] = "{$suricatacfgdir}/rules/" . FLOWBITS_FILENAME;
		$rule_files[] = "{$suricatacfgdir}/rules/custom.rules";
		$rules_map = suricata_get_filtered_rules($rule_files, suricata_load_sid_mods($a_rule['rule_sid_on']));
	}
	elseif ($currentruleset == "User Forced Disabled Rules") {
		// Search and display forced disabled rules only from
		// the enabled rule categories for this interface.
		$rule_files = explode("||", $pconfig['rulesets']);

		// Prepend the Suricata rules path to each entry.
		foreach ($rule_files as $k => $v) {
			$rule_files[$k] = $ruledir . $v;
		}
		$rule_files[] = "{$suricatacfgdir}/rules/" . FLOWBITS_FILENAME;
		$rule_files[] = "{$suricatacfgdir}/rules/custom.rules";
		$rules_map = suricata_get_filtered_rules($rule_files, suricata_load_sid_mods($a_rule['rule_sid_off']));
	}
	elseif ($currentruleset == "User Forced ALERT Action Rules") {
		$rules_map = suricata_get_filtered_rules("{$suricatacfgdir}/rules/", suricata_load_sid_mods($a_rule['rule_sid_force_alert']));
	}
	elseif ($currentruleset == "User Forced DROP Action Rules") {
		$rules_map = suricata_get_filtered_rules("{$suricatacfgdir}/rules/", suricata_load_sid_mods($a_rule['rule_sid_force_drop']));
	}
	elseif ($currentruleset == "User Forced REJECT Action Rules") {
		$rules_map = suricata_get_filtered_rules("{$suricatacfgdir}/rules/", suricata_load_sid_mods($a_rule['rule_sid_force_reject']));
	}
	// If it's not a special case, and we can't find
	// the given rule file, then notify the user.
	elseif (!file_exists($rulefile)) {
		$input_errors[] = gettext("{$currentruleset} seems to be missing!!! Please verify rules files have been downloaded, then go to the Categories tab and save the rule set again.");
	}
	// Not a special case, and we have the matching
	// rule file, so load it up for display.
	else {
		$rules_map = suricata_load_rules_map($rulefile);
	}
}
elseif (isset($_POST['resetall']) && !empty($rules_map)) {

	// Remove all modified SIDs from config.xml and save the changes.
	unset($a_rule['rule_sid_on']);
	unset($a_rule['rule_sid_off']);
	unset($a_rule['rule_sid_force_alert']);
	unset($a_rule['rule_sid_force_drop']);
	unset($a_rule['rule_sid_force_reject']);

	// We changed a rule state or action, remind user to apply the changes
	mark_subsystem_dirty('suricata_rules');

	/* Update the config.xml file. */
	config_set_path("installedpackages/suricata/rule/{$id}", $a_rule);
	config_set_path("installedpackages/suricata/rule/{$id}", $a_rule);
	write_config("Suricata pkg: remove all rule state/action changes for {$a_rule['interface']}.");

	// Reload the rules so we can accurately show content after
	// resetting any user overrides.
	// If it is the auto-flowbits file, set the full path.
	if ($currentruleset == "Auto-Flowbit Rules") {
		$rulefile = "{$suricatacfgdir}/rules/" . FLOWBITS_FILENAME;
	}
	// Test for the special case of an IPS Policy file
	// and load the selected policy's rules.
	elseif (substr($currentruleset, 0, 10) == "IPS Policy") {
		$rules_map = suricata_load_vrt_policy($a_rule['ips_policy'], $a_rule['ips_policy_mode']);
	}
	// Test for the special case of "Active Rules".  This
	// displays all currently active rules for the
	// interface.
	elseif ($currentruleset == "Active Rules") {
		$rules_map = suricata_load_rules_map("{$suricatacfgdir}/rules/");
	}
	// Test for the special cases of "User Forced" rules
	// and load the required rules for display.
	elseif ($currentruleset == "User Forced Enabled Rules") {
		// Search and display forced enabled rules only from
		// the enabled rule categories for this interface.
		$rule_files = explode("||", $pconfig['rulesets']);

		// Prepend the Suricata rules path to each entry.
		foreach ($rule_files as $k => $v) {
			$rule_files[$k] = $ruledir . $v;
		}
		$rules_file[] = "{$suricatacfgdir}/rules/" . FLOWBITS_FILENAME;
		$rules_file[] = "{$suricatacfgdir}/rules/custom.rules";
		$rules_map = suricata_get_filtered_rules($rule_files, suricata_load_sid_mods($a_rule['rule_sid_on']));
	}
	elseif ($currentruleset == "User Forced Disabled Rules") {
		// Search and display forced disabled rules only from
		// the enabled rule categories for this interface.
		$rule_files = explode("||", $pconfig['rulesets']);

		// Prepend the Suricata rules path to each entry.
		foreach ($rule_files as $k => $v) {
			$rule_files[$k] = $ruledir . $v;
		}
		$rules_file[] = "{$suricatacfgdir}/rules/" . FLOWBITS_FILENAME;
		$rules_file[] = "{$suricatacfgdir}/rules/custom.rules";
		$rules_map = suricata_get_filtered_rules($rule_files, suricata_load_sid_mods($a_rule['rule_sid_off']));
	}
	elseif ($currentruleset == "User Forced ALERT Action Rules") {
		$rules_map = suricata_get_filtered_rules("{$suricatacfgdir}/rules/", suricata_load_sid_mods($a_rule['rule_sid_force_alert']));
	}
	elseif ($currentruleset == "User Forced DROP Action Rules") {
		$rules_map = suricata_get_filtered_rules("{$suricatacfgdir}/rules/", suricata_load_sid_mods($a_rule['rule_sid_force_drop']));
	}
	elseif ($currentruleset == "User Forced REJECT Action Rules") {
		$rules_map = suricata_get_filtered_rules("{$suricatacfgdir}/rules/", suricata_load_sid_mods($a_rule['rule_sid_force_reject']));
	}
	// If it's not a special case, and we can't find
	// the given rule file, then notify the user.
	elseif (!file_exists($rulefile)) {
		$input_errors[] = gettext("{$currentruleset} seems to be missing!!! Please verify rules files have been downloaded, then go to the Categories tab and save the rule set again.");
	}
	// Not a special case, and we have the matching
	// rule file, so load it up for display.
	else {
		$rules_map = suricata_load_rules_map($rulefile);
	}
}
elseif (isset($_POST['clear'])) {
	unset($a_rule['customrules']);
	config_set_path("installedpackages/suricata/rule/{$id}", $a_rule);
	write_config("Suricata pkg: clear all custom rules for {$a_rule['interface']}.");
	$rebuild_rules = true;
	suricata_generate_yaml($a_rule);
	$rebuild_rules = false;
	$pconfig['customrules'] = '';

	// Sync to configured CARP slaves if any are enabled
	suricata_sync_on_changes();
}
elseif (isset($_POST['cancel'])) {
	$pconfig['customrules'] = base64_decode($a_rule['customrules']);
	clear_subsystem_dirty('suricata_rules');
}
elseif (isset($_POST['save'])) {
	$pconfig['customrules'] = $_POST['customrules'];
	if ($_POST['customrules'])
		$a_rule['customrules'] = base64_encode(str_replace("\r\n", "\n", $_POST['customrules']));
	else
		unset($a_rule['customrules']);
	config_set_path("installedpackages/suricata/rule/{$id}", $a_rule);
	write_config("Suricata pkg: save modified custom rules for {$a_rule['interface']}.");
	$rebuild_rules = true;
	suricata_generate_yaml($a_rule);
	$rebuild_rules = false;
	/* Signal Suricata to "live reload" the rules */
	suricata_reload_config($a_rule);
	clear_subsystem_dirty('suricata_rules');

	// Sync to configured CARP slaves if any are enabled
	suricata_sync_on_changes();
}
elseif ($_POST['filterrules_submit']) {
	// Set flag for filtering rules
	$filterrules = TRUE;
	$filterfieldsarray = array();
	$filterfieldsarray['show_enabled'] = $_POST['filterrules_enabled'] ? $_POST['filterrules_enabled'] : null;
	$filterfieldsarray['show_disabled'] = $_POST['filterrules_disabled'] ? $_POST['filterrules_disabled'] : null;
	if ($a_rule['blockoffenders'] == 'on'){
		$filterfieldsarray['show_drop'] = $_POST['filterrules_drop'] ? $_POST['filterrules_drop'] : null;
	}
	if ($a_rule['ips_mode'] == 'ips_mode_inline' && $a_rule['blockoffenders'] == 'on') {
		$filterfieldsarray['show_reject'] = $_POST['filterrules_reject'] ? $_POST['filterrules_reject'] : null;
	}
}
elseif ($_POST['filterrules_clear']) {
	$filterfieldsarray = array();
	$filterrules = TRUE;
}
elseif (isset($_POST['apply'])) {

	/* Save new configuration */
	config_set_path("installedpackages/suricata/rule/{$id}", $a_rule);
	write_config("Suricata pkg: new rules configuration for {$a_rule['interface']}.");

	/*************************************************/
	/* Update the suricata.yaml file and rebuild the */
	/* rules for this interface.                     */
	/*************************************************/
	$rebuild_rules = true;
	suricata_generate_yaml($a_rule);
	$rebuild_rules = false;

	/* Signal Suricata to "live reload" the rules */
	suricata_reload_config($a_rule);

	// We have saved changes and done a soft restart, so clear "dirty" flag
	clear_subsystem_dirty('suricata_rules');

	// Sync to configured CARP slaves if any are enabled
	suricata_sync_on_changes();
}

function build_cat_list() {
	global $categories, $a_rule, $snortdownload, $emergingdownload, $etpro;

	$list = array();

	$files = $categories;

	if ($a_rule['ips_policy_enable'] == 'on')
		$files[] = "IPS Policy - " . ucfirst($a_rule['ips_policy']);

	if ($a_rule['autoflowbitrules'] == 'on')
		$files[] = "Auto-Flowbit Rules";

	natcasesort($files);

	foreach ($files as $value) {
		if ($snortdownload != 'on' && substr($value, 0, mb_strlen(VRT_FILE_PREFIX)) == VRT_FILE_PREFIX)
			continue;
		if ($emergingdownload != 'on' && substr($value, 0, mb_strlen(ET_OPEN_FILE_PREFIX)) == ET_OPEN_FILE_PREFIX)
			continue;
		if ($etpro != 'on' && substr($value, 0, mb_strlen(ET_PRO_FILE_PREFIX)) == ET_PRO_FILE_PREFIX)
			continue;
		if (empty($value))
			continue;

		$list[$value] = $value;
	}

	return(['custom.rules' => 'custom.rules'] + $list);
}

$if_friendly = convert_friendly_interface_to_friendly_descr($pconfig['interface']);
$pglinks = array("", "/suricata/suricata_overview.php", "/suricata/suricata_interfaces.php", "/suricata/suricata_interfaces_edit.php?id={$id}", "@self");
$pgtitle = array(gettext("Services"), gettext("Suricata"), gettext("Interfaces"), htmlspecialchars($a_rule['descr'] ?: $if_friendly), gettext("Rules"));
include_once("head.inc");
suricata_display_primary_navigation('policies');

/* Interface context (same block on every per-interface Suricata page): settings switch + summary */
$sf_rule = config_get_path("installedpackages/suricata/rule/{$id}", []);
$sf_real = get_real_interface($sf_rule['interface'] ?? '');
$sf_name = convert_friendly_interface_to_friendly_descr($sf_rule['interface'] ?? '');
echo '<nav class="fs-viewswitch" aria-label="' . fs_h(gettext('Interface settings')) . '">';
foreach (array(
	array('suricata_interfaces_edit.php', gettext('Settings')),
	array('suricata_rulesets.php', gettext('Categories')),
	array('suricata_rules.php', gettext('Rules')),
	array('suricata_flow_stream.php', gettext('Flow & stream')),
	array('suricata_app_parsers.php', gettext('App parsers')),
	array('suricata_define_vars.php', gettext('Variables')),
	array('suricata_ip_reputation.php', gettext('IP reputation')),
) as $sf_v) {
	echo '<a href="/suricata/' . $sf_v[0] . '?id=' . (int)$id . '"' . (($sf_v[0] === basename(__FILE__)) ? ' aria-current="page"' : '') . '>' . fs_h($sf_v[1]) . '</a>';
}
echo '</nav>';
if (($sf_rule['blockoffenders'] ?? '') != 'on') {
	$sf_mode = gettext('Detection only');
} elseif (($sf_rule['ips_mode'] ?? '') == 'ips_mode_inline') {
	$sf_mode = gettext('Inline IPS');
} else {
	$sf_mode = gettext('Legacy blocking');
}
$sf_running = !empty($sf_rule['uuid']) && suricata_is_running($sf_rule['uuid'], $sf_real);
fs_summary_card(array(
	'icon' => 'fa-shield-halved',
	'title' => $sf_rule['descr'] ?? '',
	'placeholder' => $sf_name,
	'subtitle' => sprintf(gettext('Suricata on %s'), $sf_name),
	'badges' => array(
		fs_badge((($sf_rule['enable'] ?? '') == 'on') ? 'enabled' : 'disabled'),
		$sf_running ? fs_badge('up', gettext('Running')) : fs_badge('down', gettext('Stopped')),
	),
	'meta' => $sf_real,
	'label' => gettext('Interface summary'),
	'facts' => array(
		array(gettext('Mode'), $sf_mode),
		array(gettext('Rule categories'), (string)count(array_filter(explode('||', $sf_rule['rulesets'] ?? '')))),
		array(gettext('Home net'), (($sf_rule['homelistname'] ?? 'default') == 'default') ? gettext('Default') : $sf_rule['homelistname']),
		array(gettext('Suppress list'), (empty($sf_rule['suppresslistname']) || $sf_rule['suppresslistname'] == 'default') ? '' : $sf_rule['suppresslistname'], 'empty' => gettext('None')),
	),
	'actions' => array(array(gettext('Alerts'), '/suricata/suricata_alerts.php?instance=' . (int)$id, 'fa-bell')),
));

if (is_subsystem_dirty('suricata_rules')) {
	$_POST['if'] = $id . "|" . $currentruleset;
	print_apply_box(gettext("A rule state or action was changed.") . "<br/>" . gettext("Apply the changes to send them to the running configuration."));
}

if ($input_errors) {
	print_input_errors($input_errors);
}

if ($savemsg) {
	print_info_box($savemsg);
}

$can_block = ($a_rule['blockoffenders'] == 'on');
$can_reject = ($a_rule['ips_mode'] == 'ips_mode_inline' && $can_block);

/* ------------------------------------------------ build the rows of the category */

$rows = array();
$counter = $enable_cnt = $disable_cnt = $user_enable_cnt = $user_disable_cnt = $managed_count = 0;
if ($currentruleset != 'custom.rules' && is_array($rules_map) && !empty($rules_map)) {
	foreach ($rules_map as $k1 => $rulem) {
		if (!is_array($rulem)) {
			$rulem = array();
		}
		foreach ($rulem as $k2 => $v) {
			$sid = $k2;
			$gid = $k1;
			$origin = 'default';
			$on = true;

			// Auto-managed by the SID MGMT tab feature
			if ($v['managed'] == 1) {
				if ($v['disabled'] == 1 && $v['state_toggled'] == 1) {
					$origin = 'auto';
					$on = false;
				}
				elseif ($v['disabled'] == 0 && $v['state_toggled'] == 1) {
					$origin = 'auto';
					$on = true;
				}
				$managed_count++;
			}
			// User overrides, then the default state
			if (isset($disablesid[$gid][$sid])) {
				$origin = 'user';
				$on = false;
				$disable_cnt++;
				$user_disable_cnt++;
			}
			elseif (isset($enablesid[$gid][$sid])) {
				$origin = 'user';
				$on = true;
				$enable_cnt++;
				$user_enable_cnt++;
			}
			elseif (($v['disabled'] == 1) && ($v['state_toggled'] == 0) && (!isset($enablesid[$gid][$sid]))) {
				$origin = 'default';
				$on = false;
				$disable_cnt++;
			}
			elseif ($v['disabled'] == 0 && $v['state_toggled'] == 0) {
				$origin = 'default';
				$on = true;
				$enable_cnt++;
			}

			// Rule action
			if ($v['noalert'] == 1) {
				$act = 'noalert';
			} elseif ($v['action'] == 'drop' && $can_block) {
				$act = 'drop';
			} elseif ($v['action'] == 'reject' && $can_reject) {
				$act = 'reject';
			} else {
				$act = 'alert';
			}

			// The header of the rule (before the options) holds proto, source and destination
			$tmp = substr($v['rule'], 0, strpos($v['rule'], "("));
			$tmp = trim(preg_replace('/^\s*#+\s*/', '', $tmp));
			$rule_content = preg_split('/[\s]+/', $tmp);

			$rows[] = array(
				'gid' => $gid, 'sid' => $sid, 'on' => $on, 'origin' => $origin, 'act' => $act,
				'modified' => ($v['managed'] == 1 && $v['modified'] == 1),
				'proto' => $rule_content[1] ?? '', 'src' => $rule_content[2] ?? '', 'sport' => $rule_content[3] ?? '',
				'dst' => $rule_content[5] ?? '', 'dport' => $rule_content[6] ?? '',
				'msg' => suricata_get_msg($v['rule']),
			);
			$counter++;
		}
	}
	unset($rulem, $v);
}

$state_badges = array(
	'on' => fs_badge('enabled', gettext('Enabled')),
	'off' => fs_badge('disabled', gettext('Disabled')),
);
$origin_chips = array(
	'default' => '<span class="fs-chip fs-chip--muted">' . fs_h(gettext('default')) . '</span>',
	'user' => '<span class="fs-chip">' . fs_h(gettext('by user')) . '</span>',
	'auto' => '<span class="fs-chip" title="' . fs_h(gettext('Set by the SID Mgmt configuration')) . '">' . fs_h(gettext('SID Mgmt')) . '</span>',
);
$action_badges = array(
	'alert' => fs_badge('warn', gettext('Alert')),
	'drop' => fs_badge('block', gettext('Drop')),
	'reject' => fs_badge('reject', gettext('Reject')),
	'noalert' => fs_badge('neutral', gettext('No alert'), gettext("Rule contains the 'noalert;' and/or 'flowbits:noalert;' options.")),
);
?>

<style>
.sf-category { width: auto; max-width: 22rem; }
.sf-rule { min-width: 16rem; }
.sf-rule-msg { overflow-wrap: anywhere; }
.sf-sid { padding: 0; border: 0; background: none; color: var(--fs-coral-text); font-family: var(--fs-font-mono); font-size: var(--fs-fs-sm); }
.sf-sid:hover, .sf-sid:focus-visible { text-decoration: underline; }
.sf-traffic { font-family: var(--fs-font-mono); font-size: var(--fs-fs-sm); color: var(--fs-text-muted); max-width: 22rem; overflow-wrap: anywhere; }
.sf-traffic b { color: var(--fs-text); font-weight: 500; }
.sf-state { display: flex; flex-wrap: wrap; align-items: center; gap: .25rem .4rem; }
tr.sf-off .sf-rule-msg, tr.sf-off .sf-traffic { color: var(--fs-text-muted); }
.sf-more .dropdown-item { display: flex; align-items: center; gap: .5rem; }
.sf-rule-meta { display: flex; flex-wrap: wrap; gap: .25rem 1rem; margin-bottom: .75rem; font-size: var(--fs-fs-sm); }
.sf-choice { display: block; padding: .5rem .75rem; margin-bottom: .5rem; border: 1px solid var(--fs-border); border-radius: var(--fs-r-sm); cursor: pointer; }
.sf-choice:has(input:checked) { border-color: var(--fs-coral-text); }
.sf-choice input { margin-right: .5rem; }
.sf-notes { display: flex; flex-wrap: wrap; gap: .4rem 1.5rem; margin: -.5rem 0 var(--fs-sp-5); color: var(--fs-text-muted); font-size: var(--fs-fs-sm); }
</style>

<form action="/suricata/suricata_rules.php" method="post" enctype="multipart/form-data" name="iform" id="iform">
<input type='hidden' name='id' id='id' value='<?=(int)$id;?>'/>
<input type='hidden' name='openruleset' id='openruleset' value='<?=fs_h($currentruleset);?>'/>
<input type='hidden' name='sid' id='sid' value=''/>
<input type='hidden' name='gid' id='gid' value=''/>

<?php
/* Category picker (posts the form on change) and the raw view of the category */
$picker = '<select class="form-select form-select-sm sf-category" name="selectbox" id="selectbox" aria-label="' . fs_h(gettext('Category')) . '">';
foreach (build_cat_list() as $k => $v) {
	$picker .= '<option value="' . fs_h($k) . '"' . (((string)$k === (string)$currentruleset) ? ' selected' : '') . '>' . fs_h($v) . '</option>';
}
$picker .= '</select>';
if ($currentruleset != 'custom.rules' && $currentruleset != 'Active Rules' && strpos($currentruleset, 'User Forced ') === FALSE) {
	$picker .= '<a class="btn btn-sm btn-outline-secondary" href="' . fs_h('/suricata/suricata_rules_edit.php?id=' . $id . '&openruleset=' . urlencode($currentruleset)) . '" target="_blank" rel="noopener" title="' . fs_h(gettext('View raw text for all rules in selected category')) . '">'
	    . '<i class="fa-regular fa-file-lines icon-embed-btn" aria-hidden="true"></i>' . fs_h(gettext('View all')) . '</a>';
}
?>

<?php if ($currentruleset == 'custom.rules'): ?>
<div class="panel panel-default">
	<div class="panel-heading">
		<h2 class="panel-title"><?=gettext('Custom rules')?></h2>
		<div class="d-flex flex-wrap gap-2 ms-auto"><?=$picker?></div>
	</div>
	<div class="panel-body">
		<label class="visually-hidden" for="customrules"><?=gettext('Custom rules')?></label>
		<textarea class="form-control fs-mono" name="customrules" id="customrules" rows="18" wrap="off" spellcheck="false"><?=htmlspecialchars(base64_decode($a_rule['customrules']))?></textarea>
		<div class="form-text help-block"><?=gettext('One rule per line, in Suricata rule syntax. Saving rebuilds the rules of this interface and live-reloads Suricata.')?></div>
	</div>
</div>
<div class="fs-actionbar">
	<button type="submit" id="save" name="save" class="btn btn-primary" title="<?=gettext('Save custom rules for this interface');?>"><i class="fa-solid fa-floppy-disk icon-embed-btn" aria-hidden="true"></i><?=gettext('Save');?></button>
	<button type="submit" id="cancel" name="cancel" class="btn btn-outline-secondary" title="<?=gettext('Discard the edits and reload the saved rules');?>"><?=gettext('Cancel');?></button>
	<button type="submit" id="clear" name="clear" class="btn btn-outline-danger ms-auto" title="<?=gettext('Deletes all custom rules for this interface');?>"
		data-fs-confirm="<?=gettext('Delete all custom rules of this interface?')?>" data-fs-confirm-detail="<?=gettext('The rules are removed and the interface rules are rebuilt.')?>" data-fs-confirm-action="<?=gettext('Delete all')?>"><i class="fa-solid fa-trash-can icon-embed-btn" aria-hidden="true"></i><?=gettext('Clear');?></button>
</div>

<?php else: ?>

<div class="fs-tiles">
<?php
	fs_tile(gettext('Rules'), $counter);
	fs_tile(gettext('Enabled'), $enable_cnt, null, $user_enable_cnt ? sprintf(gettext('%d by user'), $user_enable_cnt) : null);
	fs_tile(gettext('Disabled'), $disable_cnt, null, $user_disable_cnt ? sprintf(gettext('%d by user'), $user_disable_cnt) : null);
	fs_tile(gettext('SID Mgmt'), $managed_count, null, gettext('Auto-managed rules'));
?>
</div>

<div class="panel panel-default fs-table">
<?php
	$warn_flowbits = ($currentruleset == 'Auto-Flowbit Rules') ? gettext('Flowbit rules should not be disabled; suppress their alerts instead.') : null;
	$more = '<div class="dropdown sf-more">'
	    . '<button type="button" class="btn btn-sm btn-outline-secondary dropdown-toggle" data-bs-toggle="dropdown" aria-expanded="false">' . fs_h(gettext('Overrides')) . '</button>'
	    . '<ul class="dropdown-menu dropdown-menu-end">'
	    . '<li><button type="submit" class="dropdown-item" name="enable_all" id="enable_all" value="Enable All" title="' . fs_h(gettext('Enable all rules in the currently selected category')) . '"><i class="fa-regular fa-circle-check" aria-hidden="true"></i>' . fs_h(gettext('Enable all in category')) . '</button></li>'
	    . '<li><button type="submit" class="dropdown-item" name="disable_all" id="disable_all" value="Disable All" title="' . fs_h(gettext('Disable all rules in the currently selected category')) . '"'
	    . ' data-fs-confirm="' . fs_h(gettext('Disable every rule in this category?')) . '"' . ($warn_flowbits ? ' data-fs-confirm-detail="' . fs_h($warn_flowbits) . '"' : '') . ' data-fs-confirm-action="' . fs_h(gettext('Disable all')) . '"><i class="fa-regular fa-circle-xmark" aria-hidden="true"></i>' . fs_h(gettext('Disable all in category')) . '</button></li>'
	    . '<li><hr class="dropdown-divider"></li>'
	    . '<li><button type="submit" class="dropdown-item" name="resetcategory" id="resetcategory" value="Reset Current" title="' . fs_h(gettext('Remove user overrides for only the currently selected category')) . '"'
	    . ' data-fs-confirm="' . fs_h(gettext('Reset the overrides of this category?')) . '" data-fs-confirm-detail="' . fs_h(gettext('State and action changes made by users in this category return to their defaults.')) . '" data-fs-confirm-action="' . fs_h(gettext('Reset')) . '"><i class="fa-solid fa-arrow-rotate-left" aria-hidden="true"></i>' . fs_h(gettext('Reset this category')) . '</button></li>'
	    . '<li><button type="submit" class="dropdown-item" name="resetall" id="resetall" value="Reset All" title="' . fs_h(gettext('Remove user overrides for all rule categories')) . '"'
	    . ' data-fs-confirm="' . fs_h(gettext('Reset the overrides of every category?')) . '" data-fs-confirm-detail="' . fs_h(gettext('All rule state and action changes made by users on this interface are removed.')) . '" data-fs-confirm-action="' . fs_h(gettext('Reset all')) . '"><i class="fa-solid fa-arrow-rotate-left" aria-hidden="true"></i>' . fs_h(gettext('Reset all categories')) . '</button></li>'
	    . '<li><hr class="dropdown-divider"></li>'
	    . '<li><button type="submit" class="dropdown-item" name="apply" id="apply" value="Apply" title="' . fs_h(gettext('Apply changes made on this tab and rebuild the interface rules')) . '"><i class="fa-solid fa-check" aria-hidden="true"></i>' . fs_h(gettext('Apply and rebuild rules')) . '</button></li>'
	    . '</ul></div>';

	$filters = array(
		'state' => array(gettext('All states'), 'on' => gettext('Enabled'), 'off' => gettext('Disabled')),
		'origin' => array(gettext('Any origin'), 'default' => gettext('Default'), 'user' => gettext('Changed by user'), 'auto' => gettext('SID Mgmt')),
	);
	$act_filter = array(gettext('All actions'), 'alert' => gettext('Alert'));
	if ($can_block) {
		$act_filter['drop'] = gettext('Drop');
	}
	if ($can_reject) {
		$act_filter['reject'] = gettext('Reject');
	}
	$act_filter['noalert'] = gettext('No alert');
	$filters['action'] = $act_filter;

	fs_table_toolbar(array(
		'search' => gettext('Search SIDs, messages, addresses…'),
		'noun' => gettext('rules'),
		'noun_one' => gettext('rule'),
		'custom' => $picker,
		'filters' => $filters,
		'actions' => $more,
	));
?>
	<div class="panel-body table-responsive">
		<table class="table table-hover" data-sortable>
			<thead>
				<tr>
					<th data-sortable="false"><?=gettext("State")?></th>
					<th data-sortable="false"><?=gettext("Action")?></th>
					<th data-fs-search data-sortable-type="numeric"><?=gettext("Rule")?></th>
					<th data-fs-search><?=gettext("Traffic")?></th>
					<th class="fs-col-actions"><span class="visually-hidden"><?=gettext('Actions')?></span></th>
				</tr>
			</thead>
			<tbody>
<?php foreach ($rows as $r):
	$gs = "{$r['gid']}:{$r['sid']}";
?>
				<tr id="rule_<?=$r['gid']?>_<?=$r['sid']?>" data-fs-filter-state="<?=$r['on'] ? 'on' : 'off'?>" data-fs-filter-origin="<?=$r['origin']?>" data-fs-filter-action="<?=$r['act']?>"<?=$r['on'] ? '' : ' class="sf-off"'?>>
					<td><div class="sf-state"><?=$state_badges[$r['on'] ? 'on' : 'off']?><?=$origin_chips[$r['origin']]?><?=$r['modified'] ? '<span class="fs-chip is-warn" title="' . fs_h(gettext('Action or content modified by settings on SID Mgmt tab')) . '">' . fs_h(gettext('modified')) . '</span>' : ''?></div></td>
					<td><?=$action_badges[$r['act']]?></td>
					<td class="sf-rule" data-value="<?=fs_h($r['sid'])?>"><button type="button" class="sf-sid" data-sf-rule="<?=fs_h($gs)?>"><?=fs_h($gs)?></button><div class="sf-rule-msg"><?=fs_h($r['msg'])?></div></td>
					<td class="sf-traffic"><b><?=fs_h($r['proto'])?></b> <?=fs_h($r['src'])?> <?=fs_h($r['sport'])?> → <?=fs_h($r['dst'])?> <?=fs_h($r['dport'])?></td>
					<td class="fs-col-actions"><div class="fs-actions">
						<button type="button" class="fs-action" data-sf-modal="#sid_state_selector" data-sf-gid="<?=$r['gid']?>" data-sf-sid="<?=$r['sid']?>" aria-label="<?=fs_h(sprintf(gettext('Change the state of %s'), $gs))?>" title="<?=fs_h(gettext('Change state'))?>"><i class="fa-solid <?=$r['on'] ? 'fa-toggle-on' : 'fa-toggle-off'?>" aria-hidden="true"></i></button>
<?php if ($can_block && $r['act'] != 'noalert'): ?>
						<button type="button" class="fs-action" data-sf-modal="#sid_action_selector" data-sf-gid="<?=$r['gid']?>" data-sf-sid="<?=$r['sid']?>" aria-label="<?=fs_h(sprintf(gettext('Change the action of %s'), $gs))?>" title="<?=fs_h($r['on'] ? gettext('Change action') : gettext('Enable the rule to change its action'))?>"<?=$r['on'] ? '' : ' disabled'?>><i class="fa-solid fa-sliders" aria-hidden="true"></i></button>
<?php endif; ?>
						<button type="button" class="fs-action" data-sf-rule="<?=fs_h($gs)?>" aria-label="<?=fs_h(sprintf(gettext('Show rule %s'), $gs))?>" title="<?=fs_h(gettext('Show rule'))?>"><i class="fa-solid fa-file-lines" aria-hidden="true"></i></button>
					</div></td>
				</tr>
<?php endforeach; ?>
<?php
	if (empty($rows)) {
		fs_empty_row(5, gettext('This category has no rules.'));
	}
?>
			</tbody>
		</table>
	</div>
</div>

<div class="sf-notes">
	<span><?=gettext('State and action changes are saved at once and take effect after Apply.')?></span>
<?php if ($warn_flowbits): ?>
	<span><?=$warn_flowbits?> <a href="/suricata/suricata_rules_flowbits.php?id=<?=(int)$id?>"><?=gettext('Suppress flowbit rules')?></a></span>
<?php endif; ?>
</div>
<?php endif;?>

<!-- Rule state selector -->
<div class="modal fade" id="sid_state_selector" tabindex="-1" aria-labelledby="sid_state_title" aria-hidden="true">
	<div class="modal-dialog modal-dialog-centered">
		<div class="modal-content">
			<div class="modal-header">
				<h2 class="modal-title" id="sid_state_title"><?=gettext("Rule state")?></h2>
				<button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="<?=gettext('Close')?>"></button>
			</div>
			<div class="modal-body">
				<label class="sf-choice"><input type="radio" class="form-check-input" name="ruleStateOptions" id="state_default" value="state_default"><strong><?=gettext('Default')?></strong> <span class="fs-muted"><?=gettext('The state set by the rule package author.')?></span></label>
				<label class="sf-choice"><input type="radio" class="form-check-input" name="ruleStateOptions" id="state_enabled" value="state_enabled"><strong><?=gettext('Enabled')?></strong></label>
				<label class="sf-choice"><input type="radio" class="form-check-input" name="ruleStateOptions" id="state_disabled" value="state_disabled"><strong><?=gettext('Disabled')?></strong></label>
			</div>
			<div class="modal-footer">
				<button type="button" class="btn btn-outline-secondary" id="cancel_state_action" data-bs-dismiss="modal"><?=gettext("Cancel")?></button>
				<button type="submit" class="btn btn-primary" id="rule_state_save" name="rule_state_save" value="<?=gettext("Save")?>"><i class="fa-solid fa-floppy-disk icon-embed-btn" aria-hidden="true"></i><?=gettext("Save")?></button>
			</div>
		</div>
	</div>
</div>

<!-- Rule action selector -->
<div class="modal fade" id="sid_action_selector" tabindex="-1" aria-labelledby="sid_action_title" aria-hidden="true">
	<div class="modal-dialog modal-dialog-centered">
		<div class="modal-content">
			<div class="modal-header">
				<h2 class="modal-title" id="sid_action_title"><?=gettext("Rule action")?></h2>
				<button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="<?=gettext('Close')?>"></button>
			</div>
			<div class="modal-body">
				<label class="sf-choice"><input type="radio" class="form-check-input" name="ruleActionOptions" id="action_default" value="action_default"><strong><?=gettext('Default')?></strong> <span class="fs-muted"><?=gettext('The action set by the rule author, usually alert.')?></span></label>
				<label class="sf-choice"><input type="radio" class="form-check-input" name="ruleActionOptions" id="action_alert" value="action_alert"><strong><?=gettext('Alert')?></strong></label>
				<label class="sf-choice"><input type="radio" class="form-check-input" name="ruleActionOptions" id="action_drop" value="action_drop"><strong><?=gettext('Drop')?></strong></label>
<?php if ($can_reject): ?>
				<label class="sf-choice"><input type="radio" class="form-check-input" name="ruleActionOptions" id="action_reject" value="action_reject"><strong><?=gettext('Reject')?></strong></label>
<?php endif; ?>
			</div>
			<div class="modal-footer">
				<button type="button" class="btn btn-outline-secondary" id="cancel_sid_action" data-bs-dismiss="modal"><?=gettext("Cancel")?></button>
				<button type="submit" class="btn btn-primary" id="rule_action_save" name="rule_action_save" value="<?=gettext("Save")?>"><i class="fa-solid fa-floppy-disk icon-embed-btn" aria-hidden="true"></i><?=gettext("Save")?></button>
			</div>
		</div>
	</div>
</div>

</form>

<div class="modal fade" id="rulesviewer" tabindex="-1" aria-labelledby="rulesviewer-title" aria-hidden="true">
	<div class="modal-dialog modal-lg modal-dialog-centered modal-dialog-scrollable">
		<div class="modal-content">
			<div class="modal-header">
				<h2 class="modal-title" id="rulesviewer-title"><?=gettext('Rule')?></h2>
				<button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="<?=gettext('Close')?>"></button>
			</div>
			<div class="modal-body">
				<div class="sf-rule-meta">
					<span><span class="fs-muted"><?=gettext('Category')?></span> <span class="fs-mono" id="modal_rule_category"><?=fs_h($currentruleset)?></span></span>
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

<script type="text/javascript">
//<![CDATA[
events.push(function() {
	var page = "/suricata/suricata_rules.php";

	// State / action selectors: remember the rule, then open the modal
	document.addEventListener('click', function(e) {
		var btn = e.target.closest('[data-sf-modal]');
		if (!btn || btn.disabled) {
			return;
		}
		$('#sid').val(btn.getAttribute('data-sf-sid'));
		$('#gid').val(btn.getAttribute('data-sf-gid'));
		$('#openruleset').val($('#selectbox').val());
		var modal = document.querySelector(btn.getAttribute('data-sf-modal'));
		$(modal).find('input[type=radio]').prop('checked', false);
		bootstrap.Modal.getOrCreateInstance(modal).show();
	});

	// Rule text
	document.addEventListener('click', function(e) {
		var btn = e.target.closest('[data-sf-rule]');
		if (!btn) {
			return;
		}
		var gs = btn.getAttribute('data-sf-rule').split(':');
		$('#rulesviewer-title').text(<?=json_encode(gettext('Rule'))?> + ' ' + gs[0] + ':' + gs[1]);
		$('#rulesviewer_text').text(<?=json_encode(gettext('Loading…'))?>);
		$('#modal_rule_doc').prop('hidden', true);
		bootstrap.Modal.getOrCreateInstance(document.getElementById('rulesviewer')).show();
		$.ajax(page, {
			type: 'post',
			data: {sid: gs[1], gid: gs[0], id: $('#id').val(), openruleset: $('#selectbox').val(), action: 'loadRule'},
			complete: function(req) {
				var r = {};
				try { r = JSON.parse(req.responseText); } catch (err) { r = {}; }
				var text = '';
				try { text = atob(r.rule_text || ''); } catch (err) { text = ''; }
				$('#rulesviewer_text').text(text || <?=json_encode(gettext('The rule text could not be loaded.'))?>);
				if (r.rule_link) {
					$('#modal_rule_link').attr('href', r.rule_link).text(r.rule_link);
					$('#modal_rule_doc').prop('hidden', false);
				}
			}
		});
	});

	// Pick another category
	$('#selectbox').on('change', function() {
		var ruleset = $(this).val();
		if (ruleset) {
			$('#openruleset').val(ruleset);
			document.getElementById('iform').submit();
		}
	});

<?php if (!empty($anchor)): ?>
	// Scroll the last changed SID into view
	var row = document.getElementById(<?=json_encode($anchor)?>);
	if (row) {
		row.scrollIntoView({block: 'center'});
		row.classList.add('table-active');
	}
<?php endif;?>
});
//]]>
</script>

<?php include("foot.inc"); ?>
