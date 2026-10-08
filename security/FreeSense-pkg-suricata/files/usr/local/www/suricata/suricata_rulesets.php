<?php
/*
 * suricata_rulesets.php
 *
 * part of FreeSense (https://www.freesense.org)
 * Copyright (c) 2006-2026 Rubicon Communications, LLC (Netgate)
 * Copyright (c) 2025-2026 The FreeSense Project
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

$suricatadir = SURICATADIR;
$suricata_rules_dir = SURICATA_RULES_DIR;
$flowbit_rules_file = FLOWBITS_FILENAME;

// Array of default events rules for Suricata
$default_rules = SURICATA_DEFAULT_RULES;

if (isset($_POST['id']) && is_numericint($_POST['id']))
	$id = $_POST['id'];
elseif (isset($_GET['id']) && is_numericint($_GET['id']))
	$id = htmlspecialchars($_GET['id']);
if (!is_numericint($id))
	$id = 0;

$a_nat = config_get_path("installedpackages/suricata/rule/{$id}", []);

if (!empty($a_nat)) {
	$pconfig['autoflowbits'] = $a_nat['autoflowbitrules'];
	$pconfig['ips_policy_enable'] = $a_nat['ips_policy_enable'];
	$pconfig['ips_policy'] = $a_nat['ips_policy'];
	$pconfig['ips_policy_mode'] = $a_nat['ips_policy_mode'];
}

$if_real = get_real_interface($a_nat['interface']);
$suricata_uuid = $a_nat['uuid'];
$snortdownload = config_get_path('installedpackages/suricata/config/0/enable_vrt_rules') == 'on' ? 'on' : 'off';
$emergingdownload = config_get_path('installedpackages/suricata/config/0/enable_etopen_rules') == 'on' ? 'on' : 'off';
$etpro = config_get_path('installedpackages/suricata/config/0/enable_etpro_rules') == 'on' ? 'on' : 'off';
$snortcommunitydownload = config_get_path('installedpackages/suricata/config/0/snortcommunityrules') == 'on' ? 'on' : 'off';
$feodotrackerdownload = config_get_path('installedpackages/suricata/config/0/enable_feodo_botnet_c2_rules') == 'on' ? 'on' : 'off';
$sslbldownload = config_get_path('installedpackages/suricata/config/0/enable_abuse_ssl_blacklist_rules') == 'on' ? 'on' : 'off';
$enable_extra_rules = config_get_path('installedpackages/suricata/config/0/enable_extra_rules') == "on" ? 'on' : 'off';
$extra_rules = config_get_path('installedpackages/suricata/config/0/extra_rules/rule', []);

$no_emerging_files = false;
$no_snort_files = false;
$inline_ips_mode = $a_nat['ips_mode'] == 'ips_mode_inline' ? true:false;
$ips_policy_mode_enable = $a_nat['block_drops_only'] == 'on' ? true:false;

$enabled_rulesets_array = explode("||", $a_nat['rulesets']);

/* Test rule categories currently downloaded to SURICATA_RULES_DIR and set appropriate flags */
if ($emergingdownload == 'on') {
	$test = glob("{$suricata_rules_dir}" . ET_OPEN_FILE_PREFIX . "*.rules");
	$et_type = "ET Open";
}
elseif ($etpro == 'on') {
	$test = glob("{$suricata_rules_dir}" . ET_PRO_FILE_PREFIX . "*.rules");
	$et_type = "ET Pro";
}
else
	$et_type = "Emerging Threats";

if (empty($test))
	$no_emerging_files = true;

$test = glob("{$suricata_rules_dir}" . VRT_FILE_PREFIX . "*.rules");
if (empty($test))
	$no_snort_files = true;

if (!file_exists("{$suricata_rules_dir}" . GPL_FILE_PREFIX . "community.rules"))
	$no_community_files = true;

if (!file_exists("{$suricata_rules_dir}" . "feodotracker.rules"))
	$no_feodotracker_files = true;

if (!file_exists("{$suricata_rules_dir}" . "sslblacklist_tls_cert.rules"))
	$no_sslbl_files = true;

// If a Snort rules policy is enabled and selected, remove all Snort
// rules from the configured rule sets to allow automatic selection.
if ($a_nat['ips_policy_enable'] == 'on') {
	if (isset($a_nat['ips_policy'])) {
		$disable_vrt_rules = "disabled";
		$enabled_sets = explode("||", $a_nat['rulesets']);

		foreach ($enabled_sets as $k => $v) {
			if (substr($v, 0, 6) == "suricata_")
				unset($enabled_sets[$k]);
		}
		$a_nat['rulesets'] = implode("||", $enabled_sets);
	}
}
else
	$disable_vrt_rules = "";

if (isset($_POST["save"])) {
	if ($_POST['ips_policy_enable'] == "on") {
		$a_nat['ips_policy_enable'] = 'on';
		$a_nat['ips_policy'] = $_POST['ips_policy'];
		$a_nat['ips_policy_mode'] = $_POST['ips_policy_mode'];
	}
	else {
		$a_nat['ips_policy_enable'] = 'off';
		unset($a_nat['ips_policy']);
		unset($a_nat['ips_policy_mode']);
	}

	if (is_array($_POST['toenable']))
		$enabled_items = implode("||", $_POST['toenable']);
	else
		$enabled_items =  "{$_POST['toenable']}";

	$a_nat['rulesets'] = $enabled_items;

	if ($_POST['autoflowbits'] == "on") {
		$a_nat['autoflowbitrules'] = 'on';
	}
	else {
		$a_nat['autoflowbitrules'] = 'off';
		// Need this here so the GUI renders correctly after saving
		$_POST['autoflowbits'] = "off";
		unlink_if_exists("{$suricatadir}suricata_{$suricata_uuid}_{$if_real}/rules/{$flowbit_rules_file}");
	}

	config_set_path("installedpackages/suricata/rule/{$id}", $a_nat);
	write_config("Suricata pkg: save enabled rule categories for {$a_nat['interface']}.");

	/*************************************************/
	/* Update the suricata.yaml file and rebuild the */
	/* rules for this interface.                     */
	/*************************************************/
	$rebuild_rules = true;
	suricata_generate_yaml($a_nat);
	$rebuild_rules = false;

	/* Signal Suricata to "live reload" the rules */
	suricata_reload_config($a_nat);

	$pconfig = $_POST;
	$enabled_rulesets_array = explode("||", $enabled_items);
	if (suricata_is_running($suricata_uuid, $if_real))
		$savemsg = gettext("Suricata is 'live-loading' the new rule set on this interface.");

	// Sync to configured CARP slaves if any are enabled
	suricata_sync_on_changes();
} elseif (isset($_POST['unselectall'])) {
	if ($_POST['ips_policy_enable'] == "on") {
		$a_nat['ips_policy_enable'] = 'on';
		$a_nat['ips_policy'] = $_POST['ips_policy'];
		$a_nat['ips_policy_mode'] = $_POST['ips_policy_mode'];
	}
	else {
		$a_nat['ips_policy_enable'] = 'off';
		unset($a_nat['ips_policy']);
		unset($a_nat['ips_policy_mode']);
	}

	$pconfig['autoflowbits'] = $_POST['autoflowbits'];
	$pconfig['ips_policy_enable'] = $_POST['ips_policy_enable'];
	$pconfig['ips_policy'] = $_POST['ips_policy'];
	$pconfig['ips_policy_mode'] = $_POST['ips_policy_mode'];

	// Remove all the rules
	$enabled_rulesets_array = array();

	$savemsg = gettext("All rule categories, including default events rules, have been de-selected.  ");
	if ($_POST['ips_policy_enable'] == "on")
		$savemsg .= gettext("Only the rules included in the selected IPS Policy will be used.");
	else
		$savemsg .= gettext("There currently are no inspection rules enabled for this Suricata instance!");
} elseif (isset($_POST['selectall'])) {
	if ($_POST['ips_policy_enable'] == "on") {
		$a_nat['ips_policy_enable'] = 'on';
		$a_nat['ips_policy'] = $_POST['ips_policy'];
		$a_nat['ips_policy_mode'] = $_POST['ips_policy_mode'];
	}
	else {
		$a_nat['ips_policy_enable'] = 'off';
		unset($a_nat['ips_policy']);
		unset($a_nat['ips_policy_mode']);
	}

	$pconfig['autoflowbits'] = $_POST['autoflowbits'];
	$pconfig['ips_policy_enable'] = $_POST['ips_policy_enable'];
	$pconfig['ips_policy'] = $_POST['ips_policy'];
	$pconfig['ips_policy_mode'] = $_POST['ips_policy_mode'];

	// Start with the required default events and files rules
	$enabled_rulesets_array = $default_rules;

	if ($emergingdownload == 'on') {
		$files = glob("{$suricata_rules_dir}" . ET_OPEN_FILE_PREFIX . "*.rules");
		foreach ($files as $file)
			$enabled_rulesets_array[] = basename($file);
	}
	elseif ($etpro == 'on') {
		$files = glob("{$suricata_rules_dir}" . ET_PRO_FILE_PREFIX . "*.rules");
		foreach ($files as $file)
			$enabled_rulesets_array[] = basename($file);
	}

	if ($snortcommunitydownload == 'on') {
		$files = glob("{$suricata_rules_dir}" . GPL_FILE_PREFIX . "community.rules");
		foreach ($files as $file)
			$enabled_rulesets_array[] = basename($file);
	}

	if ($feodotrackerdownload == 'on') {
		$enabled_rulesets_array[] = "feodotracker.rules";
	}

	if ($sslbldownload == 'on') {
		$enabled_rulesets_array[] = "sslblacklist_tls_cert.rules";
	}

	/* Include the Snort rules only if enabled and no IPS policy is set */
	if ($snortdownload == 'on' && empty($_POST['ips_policy_enable'])) {
		$files = glob("{$suricata_rules_dir}" . VRT_FILE_PREFIX . "*.rules");
		foreach ($files as $file)
			$enabled_rulesets_array[] = basename($file);
	}

	if ($enable_extra_rules == 'on') {
		$files = glob("{$suricata_rules_dir}" . EXTRARULE_FILE_PREFIX . "*.rules");
		foreach ($files as $file)
			$enabled_rulesets_array[] = basename($file);
	}
}

// Get any automatic rule category enable/disable modifications
// if auto-SID Mgmt is enabled.
$cat_mods = suricata_sid_mgmt_auto_categories($a_nat, FALSE);

$if_friendly = convert_friendly_interface_to_friendly_descr($a_nat['interface']);
$pglinks = array("", "/suricata/suricata_overview.php", "/suricata/suricata_interfaces.php", "/suricata/suricata_interfaces_edit.php?id={$id}", "@self");
$pgtitle = array(gettext("Services"), gettext("Suricata"), gettext("Interfaces"), htmlspecialchars($a_nat['descr'] ?: $if_friendly), gettext("Rule categories"));

include_once("head.inc");
suricata_display_primary_navigation('policies');
suricata_display_section_navigation('policies', 'rules');

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

if ($input_errors) {
	print_input_errors($input_errors);
}

if ($savemsg) {
	print_info_box($savemsg);
}

$isrulesfolderempty = glob("{$suricata_rules_dir}*.rules");
$iscfgdirempty = array();

if (file_exists("{$suricatadir}suricata_{$suricata_uuid}_{$if_real}/rules/custom.rules")) {
	$iscfgdirempty = (array)("{$suricatadir}suricata_{$suricata_uuid}_{$if_real}/rules/custom.rules");
}

if (empty($isrulesfolderempty)):
	print_info_box(sprintf(gettext("The rules directory %s is empty."), '<strong>' . htmlspecialchars($suricatadir) . 'rules</strong>') . ' ' .
		sprintf(gettext('Choose the rule sources on the %1$sGlobal settings%2$s page, then download them on the %3$sUpdates%4$s page.'),
		'<a href="/suricata/suricata_global.php">', '</a>', '<a href="/suricata/suricata_download_updates.php">', '</a>'), 'warning');

else:

/* ------------------------------------------------- collect every category row */

$rows = array();

/*
 * Add one category file. $kind: 'special' (Community/Feodo/SSLBL: an auto-managed
 * category keeps no hidden field, as before), 'snort' (locked while an IPS policy
 * is used) or 'normal'. $missing marks a source that is enabled but not downloaded.
 */
$add_row = function ($file, $source, $source_key, $kind = 'normal', $label = null, $missing = false) use (&$rows, $cat_mods, $enabled_rulesets_array, $disable_vrt_rules) {
	$row = array('file' => $file, 'label' => $label ?? $file, 'source' => $source, 'source_key' => $source_key, 'missing' => $missing, 'hidden' => false, 'disabled' => false);
	$in = is_array($enabled_rulesets_array) && in_array($file, $enabled_rulesets_array);
	if (isset($cat_mods[$file])) {
		$row['auto'] = ($cat_mods[$file] == 'enabled') ? 'enabled' : 'disabled';
		if ($kind == 'normal' && $cat_mods[$file] != 'enabled' && $cat_mods[$file] != 'disabled') {
			$row['auto'] = null;
		}
		$row['hidden'] = ($kind != 'special') && $in;
		$row['checked'] = ($row['auto'] == 'enabled');
	} else {
		$row['auto'] = false;
		if ($kind == 'snort' && !empty($disable_vrt_rules)) {
			$row['disabled'] = true;
			$row['checked'] = false;
		} else {
			$row['checked'] = $in;
		}
	}
	$rows[] = $row;
};

if ($snortcommunitydownload == 'on') {
	$add_row(GPL_FILE_PREFIX . "community.rules", gettext('Snort Community'), 'community', 'special',
	    gettext("Snort GPLv2 Community Rules (Talos-certified)"), !empty($no_community_files));
}
if ($feodotrackerdownload == 'on') {
	$add_row("feodotracker.rules", gettext('Feodo Tracker'), 'feodo', 'special', gettext("Feodo Tracker Botnet C2 IP Rules"), !empty($no_feodotracker_files));
}
if ($sslbldownload == 'on') {
	$add_row("sslblacklist_tls_cert.rules", gettext('ABUSE.ch SSLBL'), 'sslbl', 'special', gettext("ABUSE.ch SSL Blacklist Rules"), !empty($no_sslbl_files));
}

$emergingrules = array();
$snortrules = array();
if (empty($isrulesfolderempty))
	$dh  = opendir("{$suricatadir}suricata_{$suricata_uuid}_{$if_real}/rules/");
else
	$dh  = opendir("{$suricata_rules_dir}");

while (false !== ($filename = readdir($dh))) {
	$filename = basename($filename);
	if (substr($filename, -5) != "rules")
		continue;
	if (strstr($filename, ET_OPEN_FILE_PREFIX) && $emergingdownload == 'on')
		$emergingrules[] = $filename;
	else if (strstr($filename, ET_PRO_FILE_PREFIX) && $etpro == 'on')
		$emergingrules[] = $filename;
	else if (strstr($filename, VRT_FILE_PREFIX) && $snortdownload == 'on') {
		$snortrules[] = $filename;
	}
}

sort($default_rules);
sort($emergingrules);
sort($snortrules);

foreach ($default_rules as $file) {
	$add_row($file, gettext('Suricata events'), 'default');
}
foreach ($emergingrules as $file) {
	$add_row($file, ($etpro == 'on' && $emergingdownload != 'on') ? gettext('ET Pro') : gettext('ET Open'), 'et');
}
foreach ($snortrules as $file) {
	$add_row($file, gettext('Snort'), 'snort', 'snort');
}

if (($enable_extra_rules == 'on') && !empty($extra_rules)) {
	foreach ($extra_rules as $exrule) {
		$extrarules = array();
		if (empty($isrulesfolderempty)) {
			$dh  = opendir("{$suricatadir}suricata_{$suricata_uuid}_{$if_real}/rules/");
		} else {
			$dh  = opendir("{$suricata_rules_dir}");
		}
		while (false !== ($filename = readdir($dh))) {
			$filename = basename($filename);
			if (substr($filename, -5) != "rules") {
				continue;
			}
			preg_match("/" . EXTRARULE_FILE_PREFIX . "([A-Za-z0-9_]+)/", $filename, $matches);
			if ($exrule['name'] == $matches[1]) {
				$extrarules[] = $filename;
			}
		}
		sort($extrarules);
		foreach ($extrarules as $file) {
			$add_row($file, sprintf(gettext('Extra: %s'), $exrule['name']), 'extra-' . $exrule['name']);
		}
	}
}

$sources = array();
foreach ($rows as $r) {
	$sources[$r['source_key']] = $r['source'];
}
$count_on = count(array_filter($rows, function ($r) { return !empty($r['checked']); }));

/* Notes when a configured source has no files */
$notes = array();
if (($emergingdownload == 'on' || $etpro == 'on') && $no_emerging_files) {
	$notes[] = sprintf(gettext('%s rules have not been downloaded.'), $et_type);
}
if ($snortdownload == 'on' && $no_snort_files) {
	$notes[] = gettext('Snort rules have not been downloaded.');
}
?>

<style>
.sf-cat-name { overflow-wrap: anywhere; }
.sf-cat-name a { font-family: var(--fs-font-mono); font-size: var(--fs-fs-sm); }
.sf-cat-label { color: var(--fs-text-muted); font-size: var(--fs-fs-sm); }
.fs-table td.sf-col-on, .fs-table th.sf-col-on { width: 3.5rem; }
.sf-col-on .form-check-input { margin: 0; }
.sf-notes { display: flex; flex-wrap: wrap; gap: .4rem 1.5rem; margin: -.5rem 0 var(--fs-sp-5); color: var(--fs-text-muted); font-size: var(--fs-fs-sm); }
</style>

<form action="/suricata/suricata_rulesets.php" method="post" enctype="multipart/form-data" name="iform" id="iform">
<input type="hidden" name="id" id="id" value="<?=(int)$id;?>" />
<?php
	$section = new Form_Section("Flowbit resolution");

	$section->addInput(new Form_Checkbox(
		'autoflowbits',
		'Resolve flowbits',
		'Auto-enable rules required for checked flowbits',
		$pconfig['autoflowbits'] != 'off' ? true : false,
		'on'
	))->setHelp('Default is checked. Rules that set flowbits checked by your enabled rules are enabled automatically.');

	// Link to the auto-flowbit rules only when there are some
	$flowbits_file = "{$suricatadir}suricata_{$suricata_uuid}_{$if_real}/rules/{$flowbit_rules_file}";
	if ($pconfig['autoflowbits'] == 'on' && file_exists($flowbits_file) && filesize($flowbits_file) > 0) {
		$viewbtn = '<a class="btn btn-sm btn-outline-secondary" href="' . fs_h('suricata_rules_flowbits.php?id=' . $id . '&returl=' . urlencode($_SERVER['PHP_SELF'])) . '" title="' . fs_h(gettext('View flowbit-required rules')) . '">'
		    . '<i class="fa-regular fa-file-lines icon-embed-btn" aria-hidden="true"></i>' . fs_h(gettext('View flowbit rules')) . '</a>';
	} else {
		$viewbtn = '<span class="fs-muted">' . fs_h(($pconfig['autoflowbits'] == 'on') ? gettext('No rules were added for flowbits yet.') : gettext('Flowbit resolution is off.')) . '</span>';
	}

	$section->addInput(new Form_StaticText(
		'Flowbit rules',
		$viewbtn
	))->setHelp('Rules enabled to satisfy flowbit dependencies. Suppress unwanted alerts from them on the Suppress List instead of disabling them.');

	print($section);

	if ($snortdownload == 'on') {
		$section = new Form_Section("Snort IPS policy");
		$chkips = new Form_Checkbox(
			'ips_policy_enable',
			'Use IPS policy',
			'Use rules from one of the pre-defined Snort IPS policies',
			($a_nat['ips_policy_enable'] == "on"),
			'on'
		);
		$chkips->setHelp('Needs the Snort rules. Manual selection of Snort categories is turned off while a policy is used; Emerging Threats and other categories can still be added.');
		$section->addInput($chkips);
		$section->addInput(new Form_Select(
			'ips_policy',
			'IPS policy',
			$pconfig['ips_policy'],
			array(	'connectivity' => 'Connectivity',
				'balanced'  => 'Balanced',
				'security'  => 'Security',
				'max-detect' => 'Maximum Detection')
			))->setHelp('Connectivity blocks major threats with few false positives. Balanced is a good start and includes Connectivity. ' .
						'Security is stricter and adds policy-type rules. Maximum Detection favours detection over throughput and can reduce it noticeably.');
		$section->addInput(new Form_Select(
			'ips_policy_mode',
			'IPS policy mode',
			$pconfig['ips_policy_mode'],
			array(  'alert' => 'Alert',
				'policy'  => 'Policy')
			))->setHelp('Policy changes the action of the policy rules from alert to the action in the policy metadata (usually drop).');

		print($section);
	}
?>

<div class="panel panel-default fs-table">
<?php
	$bulk = '<button type="submit" id="selectall" name="selectall" class="btn btn-sm btn-outline-secondary" title="' . fs_h(gettext('Select every category, including the default events rules')) . '">'
	    . '<i class="fa-regular fa-square-check icon-embed-btn" aria-hidden="true"></i>' . fs_h(gettext('Select all')) . '</button>'
	    . '<button type="submit" id="unselectall" name="unselectall" class="btn btn-sm btn-outline-secondary" title="' . fs_h(gettext('Clear every category')) . '">'
	    . '<i class="fa-regular fa-square icon-embed-btn" aria-hidden="true"></i>' . fs_h(gettext('Unselect all')) . '</button>';
	$filters = array('state' => array(gettext('All states'), 'on' => gettext('Enabled'), 'off' => gettext('Not enabled'), 'auto' => gettext('Managed by SID Mgmt')));
	if (count($sources) > 1) {
		$filters['source'] = array(gettext('All sources')) + $sources;
	}
	fs_table_toolbar(array(
		'title' => gettext('Categories'),
		'search' => gettext('Search categories…'),
		'noun' => gettext('categories'),
		'noun_one' => gettext('category'),
		'filters' => $filters,
		'actions' => $bulk,
	));
?>
	<div class="panel-body table-responsive">
		<table class="table table-hover" data-sortable>
			<thead>
				<tr>
					<th class="sf-col-on" data-sortable="false"><span class="visually-hidden"><?=gettext('Enabled')?></span></th>
					<th data-fs-search><?=gettext('Category')?></th>
					<th data-fs-search><?=gettext('Source')?></th>
					<th><?=gettext('State')?></th>
				</tr>
			</thead>
			<tbody>
<?php foreach ($rows as $r):
	$file = $r['file'];
	if ($r['auto'] === 'enabled') {
		$state_key = 'auto';
		$state = fs_badge('enabled', gettext('Auto-enabled'), gettext('Auto-enabled by settings on the SID Mgmt tab'));
	} elseif ($r['auto'] === 'disabled' || $r['auto'] === null) {
		$state_key = 'auto';
		$state = fs_badge('disabled', gettext('Auto-disabled'), gettext('Auto-disabled by settings on the SID Mgmt tab'));
	} elseif ($r['disabled']) {
		$state_key = 'off';
		$state = fs_badge('info', gettext('IPS policy'), gettext('Disabled because an IPS policy is selected'));
	} else {
		$state_key = $r['checked'] ? 'on' : 'off';
		$state = '<span data-sf-state>' . fs_badge($r['checked'] ? 'enabled' : 'disabled', $r['checked'] ? gettext('Enabled') : gettext('Not enabled')) . '</span>';
	}
	if ($r['missing']) {
		$state .= ' ' . fs_badge('warn', gettext('Not downloaded'), gettext('Perform a rules update to download this source.'));
	}
	$link_on = $r['checked'] && !$r['disabled'];
	$href = $link_on ? "suricata_rules.php?id={$id}&openruleset=" . urlencode($file) : "suricata_rules_edit.php?id={$id}&openruleset=" . urlencode($file);
?>
				<tr data-fs-filter-state="<?=$state_key?>" data-fs-filter-source="<?=fs_h($r['source_key'])?>">
					<td class="sf-col-on">
<?php if ($r['auto'] !== false): ?>
<?php	if ($r['hidden']): ?>
						<input type="hidden" name="toenable[]" value="<?=fs_h($file)?>" />
<?php	endif; ?>
						<i class="fa-solid fa-robot fs-muted" title="<?=fs_h(gettext('Managed by SID Mgmt'))?>" aria-hidden="true"></i>
<?php else: ?>
						<input class="form-check-input" type="checkbox" name="toenable[]" value="<?=fs_h($file)?>"<?=$r['checked'] ? ' checked="checked"' : ''?><?=$r['disabled'] ? ' disabled title="' . fs_h(gettext('Disabled because an IPS Policy is selected')) . '"' : ''?> aria-label="<?=fs_h(sprintf(gettext('Enable %s'), $file))?>" />
<?php endif; ?>
					</td>
					<td class="sf-cat-name">
<?php if ($r['missing']): ?>
						<span class="fs-mono"><?=fs_h($file)?></span>
<?php elseif ($link_on): ?>
						<a href="<?=fs_h($href)?>" title="<?=fs_h(gettext('Manage the rules of this category'))?>"><?=fs_h($file)?></a>
<?php else: ?>
						<a href="<?=fs_h($href)?>" target="_blank" rel="noopener noreferrer" title="<?=fs_h(gettext('View the rules of this category'))?>"><?=fs_h($file)?></a>
<?php endif; ?>
<?php if ($r['label'] !== $file): ?>
						<div class="sf-cat-label"><?=fs_h($r['label'])?></div>
<?php endif; ?>
					</td>
					<td><span class="fs-chip"><?=fs_h($r['source'])?></span></td>
					<td><?=$state?></td>
				</tr>
<?php endforeach; ?>
<?php
	if (empty($rows)) {
		fs_empty_row(4, gettext('No rule categories are available. Enable rule sources on the Global settings page and download them.'));
	}
?>
			</tbody>
		</table>
	</div>
</div>

<div class="sf-notes">
	<span><?=sprintf(gettext('%1$d of %2$d categories enabled.'), $count_on, count($rows))?></span>
	<span><i class="fa-solid fa-robot" aria-hidden="true"></i> <?=gettext('Managed by SID Mgmt: the state comes from the SID management configuration files.')?></span>
<?php foreach ($notes as $n): ?>
	<span><?=fs_h($n)?></span>
<?php endforeach; ?>
</div>

<template id="sf-badge-on"><?=fs_badge('enabled', gettext('Enabled'))?></template>
<template id="sf-badge-off"><?=fs_badge('disabled', gettext('Not enabled'))?></template>

<div class="fs-actionbar">
	<button type="submit" id="save" name="save" class="btn btn-primary" title="<?=gettext('Save changes and rebuild the rules');?>"><i class="fa-solid fa-floppy-disk icon-embed-btn" aria-hidden="true"></i><?=gettext('Save');?></button>
</div>
</form>

<script type="text/javascript">
//<![CDATA[
events.push(function() {

	function enable_change() {
		var endis = !($('#ips_policy_enable').prop('checked'));

		hideInput('ips_policy', endis);
	<?php if ($inline_ips_mode || $ips_policy_mode_enable): ?>
		hideInput('ips_policy_mode', endis);
	<?php else: ?>
		hideInput('ips_policy_mode', true);
	<?php endif;?>

		$('input[name="toenable[]"][type="checkbox"]').each(function() {
			var str = $(this).val();

			if (str.substr(0,6) == "snort_") {
				$(this).attr('disabled', !endis);
				$(this).prop('title', endis ? '' : <?=json_encode(gettext('Disabled because an IPS Policy is selected'))?>);
			}
		});
	}

	// Keep the state badge and the state filter in step with the checkbox
	$('input[name="toenable[]"][type="checkbox"]').on('change', function() {
		var tr = this.closest('tr');
		var holder = tr.querySelector('[data-sf-state]');
		tr.setAttribute('data-fs-filter-state', this.checked ? 'on' : 'off');
		if (holder) {
			holder.replaceChildren(document.getElementById(this.checked ? 'sf-badge-on' : 'sf-badge-off').content.cloneNode(true));
		}
	});

	$('#ips_policy_enable').on('click', function() {
		enable_change();
	});

	// Set initial state of dynamic HTML form controls
	enable_change();
});
//]]>
</script>
<?php
endif;
include("foot.inc");
?>
