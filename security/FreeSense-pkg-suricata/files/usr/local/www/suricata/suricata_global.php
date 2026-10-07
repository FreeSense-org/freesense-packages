<?php
/*
 * suricata_global.php
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

global $g;

$suricatadir = SURICATADIR;
$pconfig = array();

// If doing a postback, used typed values, else load from stored config
if (!empty($_POST)) {
	$pconfig = $_POST;
}
else {
	$pconfig['enable_vrt_rules'] = config_get_path('installedpackages/suricata/config/0/enable_vrt_rules') == "on" ? 'on' : 'off';
	$pconfig['oinkcode'] = htmlentities(config_get_path('installedpackages/suricata/config/0/oinkcode'));
	$pconfig['etprocode'] = htmlentities(config_get_path('installedpackages/suricata/config/0/etprocode'));
	$pconfig['enable_etopen_rules'] = config_get_path('installedpackages/suricata/config/0/enable_etopen_rules') == "on" ? 'on' : 'off';
	$pconfig['enable_etpro_rules'] = config_get_path('installedpackages/suricata/config/0/enable_etpro_rules') == "on" ? 'on' : 'off';
	$pconfig['rm_blocked'] = config_get_path('installedpackages/suricata/config/0/rm_blocked');
	$pconfig['autoruleupdate'] = config_get_path('installedpackages/suricata/config/0/autoruleupdate');
	$pconfig['autoruleupdatetime'] = htmlentities(config_get_path('installedpackages/suricata/config/0/autoruleupdatetime'));
	$pconfig['live_swap_updates'] = config_get_path('installedpackages/suricata/config/0/live_swap_updates') == "on" ? 'on' : 'off';
	$pconfig['log_to_systemlog'] = config_get_path('installedpackages/suricata/config/0/log_to_systemlog') == "on" ? 'on' : 'off';
	$pconfig['update_notify'] = config_get_path('installedpackages/suricata/config/0/update_notify') == "on" ? 'on' : 'off';
	$pconfig['rule_categories_notify'] = config_get_path('installedpackages/suricata/config/0/rule_categories_notify') == "on" ? 'on' : 'off';
	$pconfig['log_to_systemlog_facility'] = config_get_path('installedpackages/suricata/config/0/log_to_systemlog_facility');
	$pconfig['log_to_systemlog_priority'] = config_get_path('installedpackages/suricata/config/0/log_to_systemlog_priority');
	$pconfig['forcekeepsettings'] = config_get_path('installedpackages/suricata/config/0/forcekeepsettings') == "on" ? 'on' : 'off';
	$pconfig['clearblocks'] = config_get_path('installedpackages/suricata/config/0/clearblocks') == "off" ? 'off' : 'on';
	$pconfig['snortcommunityrules'] = config_get_path('installedpackages/suricata/config/0/snortcommunityrules') == "on" ? 'on' : 'off';
	$pconfig['snort_rules_file'] = htmlentities(config_get_path('installedpackages/suricata/config/0/snort_rules_file'));
	$pconfig['autogeoipupdate'] = config_get_path('installedpackages/suricata/config/0/autogeoipupdate') == "on" ? 'on' : 'off';
	$pconfig['maxmind_geoipdb_uid'] = htmlentities(config_get_path('installedpackages/suricata/config/0/maxmind_geoipdb_uid'));
	$pconfig['maxmind_geoipdb_key'] = htmlentities(config_get_path('installedpackages/suricata/config/0/maxmind_geoipdb_key'));
	$pconfig['hide_deprecated_rules'] = config_get_path('installedpackages/suricata/config/0/hide_deprecated_rules') == "on" ? 'on' : 'off';
	$pconfig['enable_etopen_custom_url'] = config_get_path('installedpackages/suricata/config/0/enable_etopen_custom_url') == "on" ? 'on' : 'off';
	$pconfig['enable_etpro_custom_url'] = config_get_path('installedpackages/suricata/config/0/enable_etpro_custom_url') == "on" ? 'on' : 'off';
	$pconfig['enable_snort_custom_url'] = config_get_path('installedpackages/suricata/config/0/enable_snort_custom_url') == "on" ? 'on' : 'off';
	$pconfig['enable_gplv2_custom_url'] = config_get_path('installedpackages/suricata/config/0/enable_gplv2_custom_url') == "on" ? 'on' : 'off';
	$pconfig['etopen_custom_rule_url'] = htmlentities(config_get_path('installedpackages/suricata/config/0/etopen_custom_rule_url'));
	$pconfig['etpro_custom_rule_url'] = htmlentities(config_get_path('installedpackages/suricata/config/0/etpro_custom_rule_url'));
	$pconfig['snort_custom_url'] = htmlentities(config_get_path('installedpackages/suricata/config/0/snort_custom_url'));
	$pconfig['gplv2_custom_url'] = htmlentities(config_get_path('installedpackages/suricata/config/0/gplv2_custom_url'));
	$pconfig['enable_feodo_botnet_c2_rules'] = config_get_path('installedpackages/suricata/config/0/enable_feodo_botnet_c2_rules') == "on" ? 'on' : 'off';
	$pconfig['enable_abuse_ssl_blacklist_rules'] = config_get_path('installedpackages/suricata/config/0/enable_abuse_ssl_blacklist_rules') == "on" ? 'on' : 'off';
	$pconfig['enable_extra_rules'] = config_get_path('installedpackages/suricata/config/0/enable_extra_rules') == "on" ? 'on' : 'off';
	$pconfig['extra_rules'] = config_get_path('installedpackages/suricata/config/0/extra_rules', []);
}

// Do input validation on parameters
if (empty($pconfig['autoruleupdatetime']))
	$pconfig['autoruleupdatetime'] = '00:' . str_pad(strval(random_int(0,59)), 2, "00", STR_PAD_LEFT);

if (empty($pconfig['log_to_systemlog_facility']))
	$pconfig['log_to_systemlog_facility'] = "local1";

if (empty($pconfig['log_to_systemlog_priority']))
	$pconfig['log_to_systemlog_priority'] = "notice";

if ($_POST['autoruleupdatetime']) {
	if (!preg_match('/^([01]?[0-9]|2[0-3]):?([0-5][0-9])$/', $_POST['autoruleupdatetime']))
		$input_errors[] = "Invalid Rule Update Start Time!  Please supply a value in 24-hour format as 'HH:MM'.";
}

if ($_POST['enable_vrt_rules'] == "on" && empty($_POST['snort_rules_file']))
		$input_errors[] = "You must supply a snort rules tarball filename in the box provided in order to enable Snort Subscriber rules!";

if ($_POST['enable_vrt_rules'] == "on" && empty($_POST['oinkcode']))
		$input_errors[] = "You must supply an Oinkmaster code in the box provided in order to enable Snort Subscriber rules!";

if ($_POST['enable_etpro_rules'] == "on" && empty($_POST['etprocode']))
		$input_errors[] = "You must supply a subscription code in the box provided in order to enable Emerging Threats Pro rules!";

if ($_POST['enable_etopen_custom_url'] == "on" && empty(trim(html_entity_decode($_POST['etopen_custom_rule_url']))))
		$input_errors[] = "'Use Custom ET Open Rule download URL' is checked, but the ET Open Custom URL field is blank!";

if ($_POST['enable_etpro_custom_url'] == "on" && empty(trim(html_entity_decode($_POST['etpro_custom_rule_url']))))
		$input_errors[] = "'Use Custom ET Pro Rule download URL' is checked, but the ET Pro Custom URL field is blank!";

if ($_POST['enable_snort_custom_url'] == "on" && empty(trim(html_entity_decode($_POST['snort_custom_url']))))
		$input_errors[] = "'Use Custom Snort Rule download URL' is checked, but the Snort Custom URL field is blank!";

if ($_POST['enable_gplv2_custom_url'] == "on" && empty(trim(html_entity_decode($_POST['gplv2_custom_url']))))
		$input_errors[] = "'Use Custom Snort GPLv2 Rule download URL' is checked, but the Snort GPLv2 Custom URL field is blank!";

if ($_POST['enable_extra_rules']) {
	for ($x = 0; $x < 99; $x++) {
		if (isset($_POST["name{$x}"]) && isset($_POST["url{$x}"])) { 
			$name = trim($_POST["name{$x}"]);
			$url = $_POST["url{$x}"];
			if (preg_match("/[^A-Za-z0-9_]/", $name)) {
				$input_errors[] = gettext("The rules name may only contain the
				    characters A-Z, 0-9 and '-'.");
			}
			if (!is_URL($url) || ((substr($url, strrpos($url, 'rules')) != 'rules') &&
			    !preg_match('/.+\.tar\.gz$/', $url))) { 
				$input_errors[] = sprintf(gettext('%s is not valid rules or tar.gz rules archive URL.'), htmlspecialchars($url));
			}
			$extra_rules['rule'][] = array(
				'name' => $name,
				'url' => $url,
				'md5' => isset($_POST["md5{$x}"]) ? 'on' : 'off'
			);
			$enabled_extra_rules[] = $name;
		}
	}
	$pconfig['extra_rules'] = $extra_rules;
}

/* if no errors move foward with save */
if (!$input_errors) {
	if ($_POST["save"]) {

		config_set_path('installedpackages/suricata/config/0/enable_vrt_rules', $_POST['enable_vrt_rules'] ? 'on' : 'off');
		config_set_path('installedpackages/suricata/config/0/snortcommunityrules', $_POST['snortcommunityrules'] ? 'on' : 'off');
		config_set_path('installedpackages/suricata/config/0/enable_etopen_rules', $_POST['enable_etopen_rules'] ? 'on' : 'off');
		config_set_path('installedpackages/suricata/config/0/enable_etpro_rules', $_POST['enable_etpro_rules'] ? 'on' : 'off');
		config_set_path('installedpackages/suricata/config/0/autogeoipupdate', $_POST['autogeoipupdate'] ? 'on' : 'off');
		config_set_path('installedpackages/suricata/config/0/hide_deprecated_rules', $_POST['hide_deprecated_rules'] ? 'on' : 'off');
		config_set_path('installedpackages/suricata/config/0/enable_etopen_custom_url', $_POST['enable_etopen_custom_url'] ? 'on' : 'off');
		config_set_path('installedpackages/suricata/config/0/enable_etpro_custom_url', $_POST['enable_etpro_custom_url'] ? 'on' : 'off');
		config_set_path('installedpackages/suricata/config/0/enable_snort_custom_url', $_POST['enable_snort_custom_url'] ? 'on' : 'off');
		config_set_path('installedpackages/suricata/config/0/enable_gplv2_custom_url', $_POST['enable_gplv2_custom_url'] ? 'on' : 'off');
		config_set_path('installedpackages/suricata/config/0/enable_feodo_botnet_c2_rules', $_POST['enable_feodo_botnet_c2_rules'] ? 'on' : 'off');
		config_set_path('installedpackages/suricata/config/0/enable_abuse_ssl_blacklist_rules', $_POST['enable_abuse_ssl_blacklist_rules'] ? 'on' : 'off');
		config_set_path('installedpackages/suricata/config/0/enable_extra_rules', $_POST['enable_extra_rules'] ? 'on' : 'off');
		config_set_path('installedpackages/suricata/config/0/extra_rules', $extra_rules);

		// If any rule sets are being turned off, then remove them
		// from the active rules section of each interface.  Start
		// by building an arry of prefixes for the disabled rules.
		$disabled_rules = array();
		$disable_ips_policy = false;
		if (config_get_path('installedpackages/suricata/config/0/enable_vrt_rules') == 'off') {
			$disabled_rules[] = VRT_FILE_PREFIX;
			$disable_ips_policy = true;
		}
		if (config_get_path('installedpackages/suricata/config/0/snortcommunityrules') == 'off')
			$disabled_rules[] = GPL_FILE_PREFIX;
		if (config_get_path('installedpackages/suricata/config/0/enable_etopen_rules') == 'off')
			$disabled_rules[] = ET_OPEN_FILE_PREFIX;
		if (config_get_path('installedpackages/suricata/config/0/enable_etpro_rules') == 'off')
			$disabled_rules[] = ET_PRO_FILE_PREFIX;

		if (config_get_path('installedpackages/suricata/config/0/enable_feodo_botnet_c2_rules') == 'off')
			$disabled_rules[] = "feodotracker";
		if (config_get_path('installedpackages/suricata/config/0/enable_abuse_ssl_blacklist_rules') == 'off')
			$disabled_rules[] = "sslblacklist_tls_cert";

		if (empty($enabled_extra_rules))
			$disabled_rules[] = EXTRARULE_FILE_PREFIX;

		// Now walk all the configured interface rulesets and remove
		// any matching the disabled ruleset prefixes.
		foreach (config_get_path('installedpackages/suricata/rule', []) as $idx => &$iface) {
			// Disable Snort IPS policy if Snort rules are disabled
			if ($disable_ips_policy) {
				$iface['ips_policy_enable'] = 'off';
				unset($iface['ips_policy']);
			}
			$enabled_rules = explode("||", $iface['rulesets']);
			foreach ($enabled_rules as $k => $v) {
				foreach ($disabled_rules as $d) {
					if (strpos(trim($v), $d) !== false) { 
						unset($enabled_rules[$k]);
						continue;
					} elseif (!empty($enabled_extra_rules)) {
						foreach ($enabled_extra_rules as $exrule) {
							if (strpos(trim($v), EXTRARULE_FILE_PREFIX . $exrule)) {
								unset($enabled_rules[$k]);
								continue 2;
							}
						}
					}
				}
			}
			$iface['rulesets'] = implode("||", $enabled_rules);
			config_set_path("installedpackages/suricata/rule/{$idx}", $iface);
		}
		// Release the config array reference we used
		unset($iface);

		// If deprecated rules should be removed, then do it
		if (config_get_path('installedpackages/suricata/config/0/hide_deprecated_rules') == "on") {
			logger(LOG_NOTICE, localize_text("Hide Deprecated Rules is enabled.  Removing obsoleted rules categories."), LOG_PREFIX_PKG_SURICATA);
			suricata_remove_dead_rules();
		}

		config_set_path('installedpackages/suricata/config/0/snort_rules_file', html_entity_decode($_POST['snort_rules_file']));
		config_set_path('installedpackages/suricata/config/0/oinkcode', trim(html_entity_decode($_POST['oinkcode'])));
		config_set_path('installedpackages/suricata/config/0/etprocode', trim(html_entity_decode($_POST['etprocode'])));
		config_set_path('installedpackages/suricata/config/0/rm_blocked', $_POST['rm_blocked']);
		config_set_path('installedpackages/suricata/config/0/autoruleupdate', $_POST['autoruleupdate']);
		config_set_path('installedpackages/suricata/config/0/etopen_custom_rule_url', trim(html_entity_decode($_POST['etopen_custom_rule_url'])));
		config_set_path('installedpackages/suricata/config/0/etpro_custom_rule_url', trim(html_entity_decode($_POST['etpro_custom_rule_url'])));
		config_set_path('installedpackages/suricata/config/0/snort_custom_url', trim(html_entity_decode($_POST['snort_custom_url'])));
		config_set_path('installedpackages/suricata/config/0/gplv2_custom_url', trim(html_entity_decode($_POST['gplv2_custom_url'])));
		config_set_path('installedpackages/suricata/config/0/maxmind_geoipdb_uid', trim(html_entity_decode($_POST['maxmind_geoipdb_uid'])));
		config_set_path('installedpackages/suricata/config/0/maxmind_geoipdb_key', trim(html_entity_decode($_POST['maxmind_geoipdb_key'])));

		/* Check and adjust format of Rule Update Starttime string to add colon and leading zero if necessary */
		if ($_POST['autoruleupdatetime']) {
			$pos = strpos($_POST['autoruleupdatetime'], ":");
			if ($pos === false) {
				$tmp = str_pad($_POST['autoruleupdatetime'], 4, "0", STR_PAD_LEFT);
				$_POST['autoruleupdatetime'] = substr($tmp, 0, 2) . ":" . substr($tmp, -2);
			}
			config_set_path('installedpackages/suricata/config/0/autoruleupdatetime', str_pad(html_entity_decode($_POST['autoruleupdatetime']), 4, "0", STR_PAD_LEFT));
		}
		config_set_path('installedpackages/suricata/config/0/log_to_systemlog', $_POST['log_to_systemlog'] ? 'on' : 'off');
		config_set_path('installedpackages/suricata/config/0/update_notify', $_POST['update_notify'] ? 'on' : 'off');
		config_set_path('installedpackages/suricata/config/0/rule_categories_notify', $_POST['rule_categories_notify'] ? 'on' : 'off');
		config_set_path('installedpackages/suricata/config/0/log_to_systemlog_facility', $_POST['log_to_systemlog_facility']);
		config_set_path('installedpackages/suricata/config/0/log_to_systemlog_priority', $_POST['log_to_systemlog_priority']);
		config_set_path('installedpackages/suricata/config/0/live_swap_updates', $_POST['live_swap_updates'] ? 'on' : 'off');
		config_set_path('installedpackages/suricata/config/0/forcekeepsettings', $_POST['forcekeepsettings'] ? 'on' : 'off');
		config_set_path('installedpackages/suricata/config/0/clearblocks', $_POST['clearblocks'] ? 'on' : 'off');

		$retval = 0;

		write_config("Suricata pkg: modified global settings.");

		/* Toggle cron task for GeoIP database updates if setting was changed */
		if (config_get_path('installedpackages/suricata/config/0/autogeoipupdate') == 'on' && !suricata_cron_job_exists("/usr/local/pkg/suricata/suricata_geoipupdate.php")) {
			include("/usr/local/pkg/suricata/suricata_geoipupdate.php");
			install_cron_job("/usr/bin/nice -n20 /usr/local/bin/php-cgi -f /usr/local/pkg/suricata/suricata_geoipupdate.php", TRUE, 0, 0, 8, "*", "*", "root");
		}
		elseif (config_get_path('installedpackages/suricata/config/0/autogeoipupdate') == 'off' && suricata_cron_job_exists("/usr/local/pkg/suricata/suricata_geoipupdate.php"))
			install_cron_job("/usr/local/pkg/suricata/suricata_geoipupdate.php", FALSE);

		/* create passlist and homenet file, then sync files */
		sync_suricata_package_config();

		/* forces page to reload new settings */
		header( 'Expires: Sat, 26 Jul 1997 05:00:00 GMT' );
		header( 'Last-Modified: ' . gmdate( 'D, d M Y H:i:s' ) . ' GMT' );
		header( 'Cache-Control: no-store, no-cache, must-revalidate' );
		header( 'Cache-Control: post-check=0, pre-check=0', false );
		header( 'Pragma: no-cache' );
		header("Location: /suricata/suricata_global.php");
		exit;
	}
}

$pglinks = array("", "/suricata/suricata_overview.php", "@self");
$pgtitle = array(gettext("Services"), gettext("Suricata"), gettext("Global settings"));
include_once("head.inc");

/* Display Alert message, under form tag or no refresh */
if ($input_errors)
	print_input_errors($input_errors);

suricata_display_primary_navigation('advanced');

$url_help = 'Complete URL including the file name. A matching ".md5" file must exist at the same location.';
$cb = function ($name, $title, $text, $value = 'on') use (&$pconfig) {
	return new Form_Checkbox($name, $title, $text, $pconfig[$name] == 'on' ? true : false, $value);
};

$form = new Form;

/* -------------------------------------------------------------- rule sources */
$section = new Form_Section('Rule sources', 'suri-sources');

$group = new Form_Group('ET Open');
$group->add($cb('enable_etopen_rules', 'Install ETOpen Emerging Threats rules', 'Emerging Threats Open rules (free)'));
$group->add($cb('enable_etopen_custom_url', 'Enable ETOpen Custom Download URL', 'Custom download URL'));
$group->setHelp('Free open-source rule set with more limited coverage than ET Pro.');
$section->add($group);
$section->addInput(new Form_Input(
	'etopen_custom_rule_url',
	'ET Open URL',
	'text',
	$pconfig['etopen_custom_rule_url']
))->setHelp($url_help);

$group = new Form_Group('ET Pro');
$group->add($cb('enable_etpro_rules', 'Install ETPro Emerging Threats rules', 'Emerging Threats Pro rules (subscription)'));
$group->add($cb('enable_etpro_custom_url', 'Enable ETPro Custom Download URL', 'Custom download URL'));
$group->setHelp('Daily updates with broad malware coverage. ET Pro includes all ET Open rules, so ET Open is turned off when ET Pro is selected. ' .
	'<a href="https://www.proofpoint.com/us/products/et-pro-ruleset" target="_blank" rel="noopener">Get an ET Pro subscription</a>.');
$section->add($group);
$section->addInput(new Form_Input(
	'etpro_custom_rule_url',
	'ET Pro URL',
	'text',
	$pconfig['etpro_custom_rule_url']
))->setHelp($url_help);
$section->addInput(new Form_Input(
	'etprocode',
	'ET Pro subscription code',
	'text',
	$pconfig['etprocode']
))->setHelp('The subscription code from your ET Pro account.');

$group = new Form_Group('Snort');
$group->add($cb('enable_vrt_rules', 'Install Snort rules', 'Snort registered user or subscriber rules'))
	->setHelp('<a href="https://www.snort.org/users/sign_up" target="_blank" rel="noopener">Free registered user account</a> · <a href="https://www.snort.org/products" target="_blank" rel="noopener">Paid subscriber rule set</a>');
$group->add($cb('enable_snort_custom_url', 'Enable Snort Custom Download URL', 'Custom download URL'));
$section->add($group);
$section->addInput(new Form_Input(
	'snort_custom_url',
	'Snort URL',
	'text',
	$pconfig['snort_custom_url']
))->setHelp($url_help);
$section->addInput(new Form_Input(
	'snort_rules_file',
	'Snort rules file name',
	'text',
	$pconfig['snort_rules_file']
))->setHelp('File name only, for example snortrules-snapshot-29200.tar.gz. Do not use a Snort 3 rules file: it is incompatible with Suricata.');
$section->addInput(new Form_Input(
	'oinkcode',
	'Snort Oinkmaster code',
	'text',
	$pconfig['oinkcode']
))->setHelp('The Oinkmaster code from your snort.org account.');

$group = new Form_Group('Snort GPLv2 Community');
$group->add($cb('snortcommunityrules', 'Install Snort GPLv2 Community rules', 'Snort GPLv2 Community rules (free)'));
$group->add($cb('enable_gplv2_custom_url', 'Enable Snort GPLv2 Custom Download URL', 'Custom download URL'));
$group->setHelp('Free daily-updated subset of the subscriber rules. Snort subscribers already receive these rules.');
$section->add($group);
$section->addInput(new Form_Input(
	'gplv2_custom_url',
	'GPLv2 URL',
	'text',
	$pconfig['gplv2_custom_url']
))->setHelp($url_help);

$group = new Form_Group('abuse.ch');
$group->add($cb('enable_feodo_botnet_c2_rules', 'Install Feodo Tracker Suricata Botnet C2 IP rules', 'Feodo Tracker botnet C2 IP rules'));
$group->add($cb('enable_abuse_ssl_blacklist_rules', 'Install ABUSE.ch SSL Blacklist rules', 'SSL Blacklist certificate rules'));
$group->setHelp('Feodo Tracker lists Dridex and Emotet command-and-control servers; the SSL Blacklist contains fingerprints of blacklisted certificates.');
$section->add($group);

$section->addInput($cb('hide_deprecated_rules', 'Deprecated categories', 'Hide deprecated rule categories and remove them from the configuration'));
$section->addInput($cb('enable_extra_rules', 'Extra rules', 'Download extra rule files'))
	->setHelp('A .rules file or a .tar.gz archive per entry. With "Check MD5" a matching ".md5" file must exist at the same URL.');
$form->add($section);

/* ---------------------------------------------------------------- extra rules */
$section = new Form_Section('Extra rules', 'suri-extra');
$section->addClass('extra_rules');

if (!$pconfig['extra_rules']) {
	$pconfig['extra_rules'] = array();
	$pconfig['extra_rules']['rule']  = array(array('name' => '', 'url' => '', 'md5' => false));
}

$counter = 0;
$numrows = count($pconfig['extra_rules']['rule']) -1;

foreach ($pconfig['extra_rules']['rule'] as $rule) {
	$group = new Form_Group(($counter == 0) ? 'Rule':null);
	$group->addClass('repeatable');

	$group->add(new Form_Input(
		'name' . $counter,
		'Name',
		'text',
		$rule['name']
	))->setWidth(2)->setHelp($numrows == $counter ? 'Name':null);

	$group->add(new Form_Input(
		'url' . $counter,
		'URL',
		'text',
		$rule['url']
	))->setWidth(5)->setHelp($numrows == $counter ? 'URL':null);

	$group->add(new Form_Checkbox(
		'md5' . $counter,
		'MD5',
		null,
		$rule['md5'] == 'on' ? true : false,
	))->setHelp($numrows == $counter ? 'Check MD5':null);

	$group->add(new Form_Button(
		'deleterow' . $counter,
		'Delete',
		null,
		'fa-solid fa-trash-can'
	))->addClass('btn-outline-secondary');

	$section->add($group);

	$counter++;
}

$section->addInput(new Form_Button(
	'addrow',
	'Add',
	null,
	'fa-solid fa-plus'
))->addClass('btn-success');

$form->add($section);

/* --------------------------------------------------------------- rule updates */
$section = new Form_Section('Rule updates', 'suri-updates');
$section->addInput(new Form_Select(
	'autoruleupdate',
	'Update interval',
	$pconfig['autoruleupdate'],
	array('never_up' => gettext('NEVER'), '6h_up' => gettext('6 HOURS'), '12h_up' => gettext('12 HOURS'),
		  '1d_up' => gettext('1 DAY'), '4d_up' => gettext('4 DAYS'), '7d_up' => gettext('7 DAYS'), '28d_up' => gettext('28 DAYS'))
))->setHelp('NEVER turns automatic updates off. Every 12 hours suits most installations.');
$section->addInput(new Form_Input(
	'autoruleupdatetime',
	'Start time',
	'text',
	$pconfig['autoruleupdatetime']
))->setHelp('24-hour HH:MM. Updates run at this time and then every interval (00:08 with 12 hours runs at 00:08 and 12:08). ' .
	'Keep the random minutes to spread the load on the download sites.');
$section->addInput($cb('live_swap_updates', 'Live rule swap', 'Reload rules live after an update instead of restarting Suricata'))
	->setHelp('Turn this off if live reloads cause problems; all instances then restart after an update.');
$form->add($section);

/* --------------------------------------------------------------------- GeoIP */
$section = new Form_Section('GeoLite2 database', 'suri-geoip');
$section->addInput($cb('autogeoipupdate', 'GeoLite2 updates', 'Download updates of the free GeoLite2 country database'))
	->setHelp('With a GeoIP2 subscription, leave this off and place the database in /usr/local/share/suricata/GeoLite2/ yourself.');
$section->addInput(new Form_Input(
	'maxmind_geoipdb_uid',
	gettext('Account ID'),
	'text',
	$pconfig['maxmind_geoipdb_uid'],
	['placeholder' => 'Enter your MaxMind GeoLite2 Account ID']
))->setHelp('From a free <a href="https://www.maxmind.com/en/geolite2/signup" target="_blank" rel="noopener">MaxMind account</a> (GeoIP Update 3.1.1 or newer).')
  ->setAttribute('autocomplete', 'off');
$section->addInput(new Form_Input(
	'maxmind_geoipdb_key',
	gettext('License key'),
	'text',
	$pconfig['maxmind_geoipdb_key'],
	['placeholder' => 'Enter your MaxMind GeoLite2 License Key']
))->setHelp('The license key generated in your MaxMind account.')
  ->setAttribute('autocomplete', 'off');
$form->add($section);

/* ---------------------------------------------------------- blocking and logs */
$section = new Form_Section('Blocking and logging', 'suri-general');
$section->addInput(new Form_Select(
	'rm_blocked',
	'Remove blocked hosts after',
	$pconfig['rm_blocked'],
	array('never_b' => gettext('NEVER'), '15m_b' => gettext('15 MINS'), '30m_b' => gettext('30 MINS'),
		  '1h_b' => gettext('1 HOUR'), '3h_b' => gettext('3 HOURS'), '6h_b' => gettext('6 HOURS'),
		  '12h_b' => gettext('12 HOURS'), '1d_b' => gettext('1 DAY'), '4d_b' => gettext('4 DAYS'),
		  '7d_b' => gettext('7 DAYS'), '28d_b' => gettext('28 DAYS'))
))->setHelp('Legacy mode blocking only (ignored in Inline IPS mode). One hour suits most installations.');
$section->addInput($cb('log_to_systemlog', 'Log to system log', 'Copy Suricata messages to the firewall system log'));
$section->addInput(new Form_Select(
	'log_to_systemlog_facility',
	'Log facility',
	$pconfig['log_to_systemlog_facility'],
	array('authpriv' => gettext('AUTHPRIV'), 'daemon' => gettext('DAEMON'), 'kern' => gettext('KERN'),
		'security' => gettext('SECURITY'), 'syslog' => gettext('SYSLOG'), 'user' => gettext('USER'), 'local0' => gettext('LOCAL0'),
		'local1' => gettext('LOCAL1'), 'local2' => gettext('LOCAL2'), 'local3' => gettext('LOCAL3'), 'local4' => gettext('LOCAL4'),
		'local5' => gettext('LOCAL5'), 'local6' => gettext('LOCAL6'), 'local7' => gettext('LOCAL7'))
))->setHelp('Default is LOCAL1.');
$section->addInput(new Form_Select(
	'log_to_systemlog_priority',
	'Log priority',
	$pconfig['log_to_systemlog_priority'],
	array( "debug" => "DEBUG", "config" => "CONF", "perf" => "PERF", "error" => "ERR", "warning" => "WARNING", "notice" => "NOTICE", "info" => "INFO" )
))->setHelp('Default is NOTICE.');
$form->add($section);

/* ------------------------------------------------------------- notifications */
$section = new Form_Section('Notifications', 'suri-notify');
$section->addInput($cb('update_notify', 'Updates', 'Notify about rule, GeoIP and IQRisk updates', 'off'));
$section->addInput($cb('rule_categories_notify', 'Rule categories', 'Notify when new rule categories appear', 'off'))
	->setHelp('Delivered through the e-mail, Telegram or Pushover settings under System > Advanced > Notifications.');
$form->add($section);

/* --------------------------------------------------------------- uninstall */
$section = new Form_Section('Package removal', 'suri-uninstall', COLLAPSIBLE | (!empty($input_errors) ? SEC_OPEN : SEC_CLOSED));
$section->addInput($cb('forcekeepsettings', 'Keep settings', 'Keep the Suricata settings when the package is removed'));
$section->addInput($cb('clearblocks', 'Clear blocked hosts', 'Remove all hosts blocked by Suricata when the package is removed (default)'));
$form->add($section);

print $form;
?>
<p class="small fs-muted"><i class="fa-solid fa-circle-info" aria-hidden="true"></i> <?=gettext('These settings apply to every Suricata interface.')?></p>

<script type="text/javascript">
//<![CDATA[
events.push(function(){

	function enable_snort_vrt() {
		var hide = ! $('#enable_vrt_rules').prop('checked');
		hideInput('snort_rules_file', hide);
		hideInput('oinkcode', hide);
		$('#enable_snort_custom_url').prop('disabled', hide);
		if (!hide && $('#enable_snort_custom_url').prop('checked')) {
			hideInput('snort_custom_url', false);
		}
		else {
			hideInput('snort_custom_url', true);
		}
	}

	function enable_et_rules() {
		var hide = $('#enable_etopen_rules').prop('checked');
		$('#enable_etopen_custom_url').prop('disabled', !hide);
		hideInput('etprocode', true);
		if (hide && $('#enable_etopen_custom_url').prop('checked')) {
			hideInput('etopen_custom_rule_url', false);
		}
		else {
			hideInput('etopen_custom_rule_url', true);
		}
		if (hide && $('#enable_etpro_rules').prop('checked')) {
			hideInput('etprocode', hide);
			hideInput('etpro_custom_rule_url', hide);
			$('#enable_etpro_rules').prop('checked', false);
			$('#enable_etpro_custom_url').prop('disabled', hide);
		}
	}

	function enable_etpro_rules() {
		var hide = ! $('#enable_etpro_rules').prop('checked');
		$('#enable_etpro_custom_url').prop('disabled', hide);
		if (!hide && $('#enable_etpro_custom_url').prop('checked')) {
			hideInput('etpro_custom_rule_url', false);
			hideInput('etprocode', true);
		}
		else {
			hideInput('etpro_custom_rule_url', true);
			hideInput('etprocode', hide);

		}
		if (!hide && $('#enable_etopen_rules').prop('checked')) {
			$('#enable_etopen_rules').prop('checked', false);
			$('#enable_etopen_custom_url').prop('disabled', !hide);
			hideInput('etopen_custom_rule_url', !hide);
			hideInput('etprocode', false);
		}
	}

	function enable_gplv2_rules() {
		var hide = ! $('#snortcommunityrules').prop('checked');
		$('#enable_gplv2_custom_url').prop('disabled', hide);
		if (!hide && $('#enable_gplv2_custom_url').prop('checked')) {
			hideInput('gplv2_custom_url', false);
		}
		else {
			hideInput('gplv2_custom_url', true);
		}
	}

	function enable_change_rules_upd(val) {
		if (val == 0)
			disableInput('autoruleupdatetime', true);
		else
			disableInput('autoruleupdatetime', false);
	}

	function toggle_log_to_systemlog() {
		var hide = ! $('#log_to_systemlog').prop('checked');
		hideInput('log_to_systemlog_facility', hide);
		hideInput('log_to_systemlog_priority', hide);
	}

	function enable_geoip2_upd() {
		var hide = ! $('#autogeoipupdate').prop('checked');
		hideInput('maxmind_geoipdb_uid', hide);
		hideInput('maxmind_geoipdb_key', hide);
	}

	function show_extrarules() {
		hide = !$('#enable_extra_rules').prop('checked');
		hideClass('extra_rules', hide);
	}

	// ---------- Click checkbox handlers ---------------------------------------------------------
	// When 'enable_vrt_rules' is clicked, toggle the Oinkmaster text control
	$('#enable_vrt_rules').click(function() {
		enable_snort_vrt();
	});

	// When 'enable_snort_custom_url' is clicked, toggle the custom URL control
	$('#enable_snort_custom_url').click(function() {
		var hide = ! $('#enable_snort_custom_url').prop('checked');
		hideInput('snort_custom_url', hide);
	});

	// When 'enable_etopen_rules' is clicked, uncheck ETPro and hide the ETPro Code text control
	$('#enable_etopen_rules').click(function() {
		enable_et_rules();
	});

	// When 'enable_etopen_custom_url' is clicked, toggle the custom URL control
	$('#enable_etopen_custom_url').click(function() {
		var hide = ! $('#enable_etopen_custom_url').prop('checked');
		hideInput('etopen_custom_rule_url', hide);
	});

	// When 'enable_etpro_rules' is clicked, uncheck ET Open checkbox control and show code
	$('#enable_etpro_rules').click(function() {
		enable_etpro_rules();
	});

	// When 'enable_etpro_custom_url' is clicked, toggle the custom URL control
	$('#enable_etpro_custom_url').click(function() {
		var hide = ! $('#enable_etpro_custom_url').prop('checked');
		hideInput('etpro_custom_rule_url', hide);
		hideInput('etprocode', !hide);
	});

	// When 'snortcommunityrules' is clicked, toggle the custom URL control
	$('#snortcommunityrules').click(function() {
		enable_gplv2_rules();
	});

	// When 'enable_gplv2_custom_url' is clicked, toggle the custom URL control
	$('#enable_gplv2_custom_url').click(function() {
		var hide = ! $('#enable_gplv2_custom_url').prop('checked');
		hideInput('gplv2_custom_url', hide);
	});

	// When 'autoruleupdate' is set to never, disable 'autoruleupdatetime'
	$('#autoruleupdate').on('change', function() {
		enable_change_rules_upd(this.selectedIndex);
	});

	// When 'log_to_systemlog' is clicked, toggle 'log_to_systemlog_facility'
	$('#log_to_systemlog').click(function() {
		toggle_log_to_systemlog();
	});

	// When 'autogeoipupdate' is clicked, toggle 'maxmind_geoipdb_key'
	$('#autogeoipupdate').click(function() {
		enable_geoip2_upd();
	});

	// When 'enable_extra_rules' is clicked, show 'extra_rules' list
	$('#enable_extra_rules').click(function () {
		show_extrarules();
	});

	// ---------- On initial page load ------------------------------------------------------------
	enable_snort_vrt();
	enable_et_rules();
	enable_etpro_rules();
	enable_gplv2_rules();
	enable_geoip2_upd();
	enable_change_rules_upd($('#autoruleupdate').prop('selectedIndex'));
	toggle_log_to_systemlog();
	show_extrarules();
	checkLastRow();

});
//]]>
</script>

<?php
include("foot.inc");
?>
