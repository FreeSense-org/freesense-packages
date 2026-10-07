<?php
/*
 * acme_generalsettings.php
 *
 * part of FreeSense (https://www.freesense.org/)
 * Copyright (c) 2016 PiBa-NL
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

namespace pfsense_pkg\acme;

$shortcut_section = "acme";
include_once("guiconfig.inc");
include_once("globals.inc");
require_once("acme/acme.inc");
require_once("acme/acme_utils.inc");
require_once("acme/acme_htmllist.inc");
require_once("acme/pkg_acme_tabs.inc");

$simplefields = array('enable', 'writecerts');
$customacme = config_get_path('installedpackages/acme/customacme/servers', []);

if ($_POST) {
	unset($input_errors);
	$pconfig = $_POST;

	for ($x = 0; $x < 50; $x++) {
		if (isset($pconfig["intid{$x}"]) &&
		    !empty($pconfig["intid{$x}"])) {
			$customacme[$x] = array();
			$customacme[$x]['intid'] = strtolower($pconfig["intid{$x}"]);
			$customacme[$x]['name'] = $pconfig["name{$x}"];
			$customacme[$x]['url'] = $pconfig["url{$x}"];
			if (!is_string($customacme[$x]['intid']) ||
			    (strlen($customacme[$x]['intid']) >= 32) ||
			    preg_match('/(^-.*$|[^a-z0-9-])/i', $customacme[$x]['intid'])) {
				$input_errors[] = gettext("A valid Internal ID must be entered for each custom ACME server.");
			}
			if (!filter_var($customacme[$x]['url'], FILTER_VALIDATE_URL)) {
				$input_errors[] = gettext("A valid URL must be entered for each custom ACME server.");
			}
		} else if (isset($customacme[$x])) {
			unset($customacme[$x]);
		}
	}

	if (!$input_errors) {
		foreach($simplefields as $stat) {
			config_set_path("installedpackages/acme/{$stat}", $_POST[$stat]);
		}

		config_set_path('installedpackages/acme/customacme/servers', $customacme);

		set_cronjob();
		acme_write_all_certificates();
		write_config(gettext("Services: ACME: General Settings saved."));
	}
}

foreach($simplefields as $stat) {
	$pconfig[$stat] = config_get_path("installedpackages/acme/{$stat}");
}

$pgtitle = array(gettext("Services"), gettext("ACME"), gettext("General settings"));
$pglinks = array("", "acme_certificates.php", "@self");
include("head.inc");

if ($input_errors) {
	print_input_errors($input_errors);
}
if ($savemsg) {
	print_info_box($savemsg);
}
display_top_tabs_active($acme_tab_array['acme'], "settings");

$counter = 0; // used by htmllist Draw() function.

$form = new \Form;

$section = new \Form_Section(gettext("Renewal"));

$section->addInput(new \Form_Checkbox(
	'enable',
	'Scheduled renewal',
	'Renew certificates automatically',
	$pconfig['enable']
))->setHelp('A cron job runs daily at 03:16 and renews every active certificate that reached its renewal threshold ' .
	'(2/3 of its lifetime, or the configured number of days), then runs its post-renew actions.');

$section->addInput(new \Form_Checkbox(
	'writecerts',
	'Write certificates',
	'Also write certificates to /conf/acme/',
	$pconfig['writecerts']
))->setHelp('After an issue or renewal, writes the certificate in several common formats to %1$s/conf/acme/%2$s ' .
	'for scripts and daemons that do not use the Certificate Manager.', '<code>', '</code>');

$form->add($section);

$section = new \Form_Section(gettext("Custom ACME servers"));
$section->addInput(new \Form_StaticText(
	null,
	'<span class="form-text help-block">' . gettext('ACME servers that are not built into the package. ' .
		'The package cannot tell which features such a server supports: test before relying on it. ' .
		'They appear in the ACME server list of account keys.') . '</span>'
));

if (empty($customacme)) {
	/* Dummy entry to display at least one empty row */
	$customacme[] = [
		'intid' => '',
		'name' => '',
		'url' => ''
	];
}
$numca = count($customacme) - 1;
$counter = 0;

foreach ($customacme as $cas) {
	$group = new \Form_Group($counter == 0 ? 'Servers' : '');

	$group->add(new \Form_Input(
		'intid' . $counter,
		null,
		'text',
		$cas['intid']
	))->setHelp(($counter == $numca) ? 'Internal ID<br>Lowercase letters, digits and dashes, under 32 characters.' : null);

	$group->add(new \Form_Input(
		'name' . $counter,
		null,
		'text',
		$cas['name']
	))->setHelp(($counter == $numca) ? 'Display name' : null);

	$group->add(new \Form_Input(
		'url' . $counter,
		null,
		'url',
		$cas['url']
	))->setHelp(($counter == $numca) ? 'Directory URL' : null);

	$group->add(new \Form_Button(
		'deleterow' . $counter,
		'Delete',
		null,
		'fa-solid fa-trash-can'
	))->addClass('btn-outline-secondary');

	$group->addClass('repeatable');
	$section->add($group);

	$counter++;
}

$form->addGlobal(new \Form_Button(
	'addrow',
	'Add server',
	null,
	'fa-solid fa-plus'
))->addClass('btn-outline-secondary addbtn');

$form->add($section);

print $form;

function group_input_with_text($name, $title, $type = 'text', $value = null, array $attributes = array(), $righttext = "")
{
	$group = new \Form_Group($title);
	$group->add(new \Form_Input(
		$name,
		'',
		$type,
		$value,
		$attributes
	))->setWidth(2);

	$group->add(new \Form_StaticText(
		'',
		$righttext
	));
	return $group;
}

include("foot.inc");
