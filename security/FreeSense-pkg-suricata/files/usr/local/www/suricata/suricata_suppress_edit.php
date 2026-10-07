<?php
/*
 * suricata_suppress_edit.php
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

if (isset($_POST['id']) && is_numericint($_POST['id']))
	$id = $_POST['id'];
elseif (isset($_GET['id']) && is_numericint($_GET['id']))
	$id = htmlspecialchars($_GET['id']);

$a_suppress = config_get_path('installedpackages/suricata/suppress/item', []);

/* returns true if $name is a valid name for a whitelist file name or ip */
function is_validwhitelistname($name) {
	if (!is_string($name))
		return false;

	if (!preg_match("/[^a-zA-Z0-9\_\.\/]/", $name))
		return true;

	return false;
}

if (isset($id) && $a_suppress[$id]) {

	/* old settings */
	$pconfig['name'] = $a_suppress[$id]['name'];
	$pconfig['uuid'] = $a_suppress[$id]['uuid'];
	$pconfig['descr'] = $a_suppress[$id]['descr'];
	if (!empty($a_suppress[$id]['suppresspassthru'])) {
		$pconfig['suppresspassthru'] = base64_decode($a_suppress[$id]['suppresspassthru']);
		$pconfig['suppresspassthru'] = str_replace("&#8203;", "", $pconfig['suppresspassthru']);
	}
	if (empty($a_suppress[$id]['uuid']))
		$pconfig['uuid'] = uniqid();
}

if ($_POST['save']) {
	unset($input_errors);
	$pconfig = $_POST;

	$reqdfields = explode(" ", "name");
	$reqdfieldsn = array("Name");

	do_input_validation($_POST, $reqdfields, $reqdfieldsn, $input_errors);

	if(strtolower($_POST['name']) == "defaultwhitelist")
		$input_errors[] = "Whitelist file names may not be named defaultwhitelist.";

	if (is_validwhitelistname($_POST['name']) == false)
		$input_errors[] = "Whitelist file name may only consist of the characters \"a-z, A-Z, 0-9 and _\". Note: No Spaces or dashes. Press Cancel to reset.";

	/* check for name conflicts */
	foreach ($a_suppress as $s_list) {
		if (isset($id) && ($a_suppress[$id]) && ($a_suppress[$id] === $s_list))
			continue;

		if ($s_list['name'] == $_POST['name']) {
			$input_errors[] = "A whitelist file name with this name already exists.";
			break;
		}
	}

	if (!$input_errors) {
		$s_list = array();
		$s_list['name'] = $_POST['name'];
		$s_list['uuid'] = uniqid();
		$s_list['descr'] = $_POST['descr'];
		if ($_POST['suppresspassthru']) {
			$s_list['suppresspassthru'] = str_replace("&#8203;", "", $s_list['suppresspassthru']);
			$s_list['suppresspassthru'] = base64_encode($_POST['suppresspassthru']);
		}

		if (isset($id) && $a_suppress[$id])
			$a_suppress[$id] = $s_list;
		else
			$a_suppress[] = $s_list;

		config_set_path('installedpackages/suricata/suppress/item', $a_suppress);
		write_config("Suricata pkg: saved changes to Suppress List {$s_list['name']}.");
		sync_suricata_package_config();

		header("Location: /suricata/suricata_suppress.php");
		exit;
	}
}

$is_new = !(isset($id) && $a_suppress[$id]);
$pglinks = array("", "/suricata/suricata_overview.php", "/suricata/suricata_suppress.php", "", "@self");
$pgtitle = array(gettext("Services"), gettext("Suricata"), gettext("Suppress lists"), htmlspecialchars($pconfig['name']), $is_new ? gettext("Add suppress list") : gettext("Edit suppress list"));
if ($is_new) {
	$pglinks = array("", "/suricata/suricata_overview.php", "/suricata/suricata_suppress.php", "@self");
	$pgtitle = array(gettext("Services"), gettext("Suricata"), gettext("Suppress lists"), gettext("Add suppress list"));
}
include_once("head.inc");

if ($input_errors) print_input_errors($input_errors);
if ($savemsg) print_info_box($savemsg);

suricata_display_primary_navigation('lists');
suricata_display_section_navigation('lists', 'suppress');

$form = new Form;
$section = new Form_Section('General', 'sup-general');
$section->addInput(new Form_Input(
	'name',
	'*Name',
	'text',
	$pconfig['name']
))->setPattern('[a-zA-Z0-9_]+')->setHelp('Letters, digits and _ only.');
$section->addInput(new Form_Input(
	'descr',
	'Description',
	'text',
	$pconfig['descr']
))->setHelp('Optional, for your reference.');
$form->add($section);

$content_help = gettext('One entry per line. Keywords: suppress, event_filter and threshold. Examples:') . '<br />';
$content_help .= '<code>suppress gen_id 1, sig_id 1852, track by_src, ip 10.1.1.54</code><br />';
$content_help .= '<code>event_filter gen_id 1, sig_id 1851, type limit, track by_src, count 1, seconds 60</code><br />';
$content_help .= '<code>threshold gen_id 135, sig_id 1, type threshold, track by_src, count 100, seconds 1</code>';

$section = new Form_Section('Entries', 'sup-entries');
$section->addInput(new Form_Textarea (
	'suppresspassthru',
	'Suppression rules',
	$pconfig['suppresspassthru']
))->setHelp($content_help)->setAttribute('rows', 16)->addClass('fs-mono')->setAttribute('wrap', 'off');
$form->add($section);

// Include the Pass List ID in a hidden form field with any $_POST
if (isset($id)) {
	$form->addGlobal(new Form_Input(
		'id',
		'id',
		'hidden',
		$id
	));
}

fs_form_cancel($form, '/suricata/suricata_suppress.php');
print($form);

include("foot.inc"); ?>
