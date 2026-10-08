<?php
/*
 * suricata_passlist_edit.php
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

$pconfig = array();

// Arbitrary limit for IP or Alias entries per Pass List.
$max_addresses = 1000;

$a_passlist = config_get_path('installedpackages/suricata/passlist/item', []);

if (isset($_POST['id']) && is_numericint($_POST['id']))
	$id = $_POST['id'];
elseif (isset($_GET['id']) && is_numericint($_GET['id']))
	$id = htmlspecialchars($_GET['id']);

/* Should never be called without identifying list index, so bail */
if (!is_numericint($id)) {
	header("Location: /suricata/suricata_passlist.php");
	exit;
}

if (isset($id) && isset($a_passlist[$id])) {
	/* Retrieve saved settings */
	$pconfig = $a_passlist[$id];
}

// Set defaults for any non-initialized values
if (!isset($pconfig['localnets'])) {
	$pconfig['localnets'] = "yes";
}
if (!isset($pconfig['wangateips'])) {
	$pconfig['wangateips'] = "yes";
}
if (!isset($pconfig['wandnsips'])) {
	$pconfig['wandnsips'] = "yes";
}
if (!isset($pconfig['vips'])) {
	$pconfig['vips'] = "yes";
}
if (!isset($pconfig['vpnips'])) {
	$pconfig['vpnips'] = "yes";
}
array_init_path($pconfig, 'address/item');

/* If no entry for this passlist, then create a UUID and treat it like a new list */
if (!isset($a_passlist[$id]['uuid']) && empty($pconfig['uuid'])) {
	$passlist_uuid = 0;
	while ($passlist_uuid > 65535 || $passlist_uuid == 0) {
		$passlist_uuid = mt_rand(1, 65535);
		$pconfig['uuid'] = $passlist_uuid;
		$pconfig['name'] = "passlist_{$passlist_uuid}";
	}
}
elseif (!empty($pconfig['uuid'])) {
	$passlist_uuid = $pconfig['uuid'];	
}
else
	$passlist_uuid = $a_passlist[$id]['uuid'];

if ($_POST['save']) {
	unset($input_errors);
	$pconfig = array();
	$p_list = array();

	/* input validation */
	$reqdfields = explode(" ", "name");
	$reqdfieldsn = explode(",", "Name");

	do_input_validation($_POST, $reqdfields, $reqdfieldsn, $input_errors);

	if(strtolower($_POST['name']) == "defaultpasslist")
		$input_errors[] = gettext("Pass List file names may not be named 'defaultpasslist' as that is a reserved name.");

	/* check for name conflicts */
	foreach ($a_passlist as $k) {
		if (isset($id) && isset($a_passlist[$id]) && ($a_passlist[$id] === $k))
			continue;

		if ($k['name'] == $_POST['name']) {
			$input_errors[] = gettext("A Pass List with this name already exists.");
			break;
		}
	}

	// Iterate and validate the returned $_POST['address'] values (these will be "addressX" where "X" is a number from 0 - 999).
	$addrs = array();
	for ($x = 0; $x < ($max_addresses - 1); $x++) {
		if ($_POST["address{$x}"] <> "") {

			// Verify the entry is a valid IP address, subnet or alias name
			if (is_ipaddroralias($_POST["address{$x}"]) || is_subnet($_POST["address{$x}"])) {
				$addrs[] = $_POST["address{$x}"];
				if (is_alias($_POST["address{$x}"])) {
					if (alias_get_type($_POST["address{$x}"]) != "host" && alias_get_type($_POST["address{$x}"]) != "network" && alias_get_type($_POST["address{$x}"]) != "urltable") {
						$input_errors[] = gettext("Custom Address entry '" . $_POST["address{$x}"] . "' is not a Host, Network, or URL Table Alias!");
					}
				}
			} else {
				$input_errors[] = gettext("Custom Address entry '" . $_POST["address{$x}"] . "' is not a valid IP address, IP subnet or Alias name!");
				$addrs[] = $_POST["address{$x}"];
			}
		}
	}

	if (!$input_errors) {

		/* post user input */
		$p_list['name'] = $_POST['name'];
		$p_list['uuid'] = $passlist_uuid;
		$p_list['localnets'] = $_POST['localnets']? 'yes' : 'no';
		$p_list['wangateips'] = $_POST['wangateips']? 'yes' : 'no';
		$p_list['wandnsips'] = $_POST['wandnsips']? 'yes' : 'no';
		$p_list['vips'] = $_POST['vips']? 'yes' : 'no';
		$p_list['vpnips'] = $_POST['vpnips']? 'yes' : 'no';
		$p_list['address']['item'] = $addrs;
		$p_list['descr'] = $_POST['descr'];

		if (isset($id) && isset($a_passlist[$id])) {
			$a_passlist[$id] = $p_list;
		} else {
			$a_passlist[] = $p_list;
		}

		$pconfig = $p_list;
		config_set_path('installedpackages/suricata/passlist/item', $a_passlist);
		write_config("Suricata pkg: modified PASS LIST {$p_list['name']}.");

		/* create pass list file, then sync file with configured partners */
		sync_suricata_package_config();
	} else {
		$pconfig['name'] = $_POST['name'];
		$pconfig['uuid'] = $passlist_uuid;
		$pconfig['localnets'] = $_POST['localnets']? 'yes' : 'no';
		$pconfig['wangateips'] = $_POST['wangateips']? 'yes' : 'no';
		$pconfig['wandnsips'] = $_POST['wandnsips']? 'yes' : 'no';
		$pconfig['vips'] = $_POST['vips']? 'yes' : 'no';
		$pconfig['vpnips'] = $_POST['vpnips']? 'yes' : 'no';
		$pconfig['descr']  =  mb_convert_encoding($_POST['descr'],"HTML-ENTITIES","auto");
		$pconfig['address']['item'] = $addrs;
	}
}

$is_new = !isset($a_passlist[$id]);
$pglinks = array("", "/suricata/suricata_overview.php", "/suricata/suricata_passlist.php", "", "@self");
$pgtitle = array(gettext("Services"), gettext("Suricata"), gettext("Pass lists"), htmlspecialchars($pconfig['name']), $is_new ? gettext("Add pass list") : gettext("Edit pass list"));
if ($is_new) {
	$pglinks = array("", "/suricata/suricata_overview.php", "/suricata/suricata_passlist.php", "@self");
	$pgtitle = array(gettext("Services"), gettext("Suricata"), gettext("Pass lists"), gettext("Add pass list"));
}
include_once("head.inc");

if ($input_errors)
	print_input_errors($input_errors);
if ($savemsg)
	print_info_box($savemsg);

suricata_display_primary_navigation('lists');
suricata_display_section_navigation('lists', 'passlist');

$pattern_str = array(	'network' => '[a-zA-Z0-9_:.-]+(/[0-9]+)?( [a-zA-Z0-9_:.-]+(/[0-9]+)?)*',	// Alias Name, Host Name, IP Address, FQDN, Network or IP Address Range
			'host'	  => '[\pL0-9_:.-]+(/[0-9]+)?( [a-zA-Z0-9_:.-]+(/[0-9]+)?)*'		// Alias Name, Host Name, IP Address, FQDN
);
$help = gettext("Enter IP addresses, subnets (such as 1.2.3.0/24) or host, network or URL table alias names. " .
		"For a host name, create a firewall alias first and enter the alias name; the firewall re-resolves it periodically.");

$form = new Form();

// Include the Pass List ID in a hidden form field with any $_POST
if (isset($id)) {
	$form->addGlobal(new Form_Input(
		'id',
		'id',
		'hidden',
		$id
	));
}

$section = new Form_Section('General', 'pl-general');
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

$section = new Form_Section('Automatic entries', 'pl-auto');
$section->addInput(new Form_Checkbox(
	'localnets',
	'Local networks',
	'Add locally attached networks (except WAN)',
	$pconfig['localnets'] == 'yes' ? true:false,
	'yes'
));
$section->addInput(new Form_Checkbox(
	'wangateips',
	'WAN gateways',
	'Add WAN gateways',
	$pconfig['wangateips'] == 'yes' ? true:false,
	'yes'
));
$section->addInput(new Form_Checkbox(
	'wandnsips',
	'WAN DNS servers',
	'Add WAN DNS servers',
	$pconfig['wandnsips'] == 'yes' ? true:false,
	'yes'
));
$section->addInput(new Form_Checkbox(
	'vips',
	'Virtual IPs',
	'Add virtual IP networks',
	$pconfig['vips'] == 'yes' ? true:false,
	'yes'
));
$section->addInput(new Form_Checkbox(
	'vpnips',
	'VPN addresses',
	'Add VPN addresses',
	$pconfig['vpnips'] == 'yes' ? true:false,
	'yes'
));
$form->add($section);

$section = new Form_Section('Custom addresses and aliases', 'pl-custom');

// Make somewhere to park the help text, and give it a class so we can update it later if desired
$section->addInput(new Form_StaticText(
	'',
	'<span class="helptext fs-muted">' . $help . '</span>'
));

// Iterate any defined IPs or Aliases defined for this list, otherwise
// create a single empty initial empty row.
if (count($pconfig['address']['item']) > 0) {
	$counter = 0;
	while ($counter < count($pconfig['address']['item'])) {
		$group = new Form_Group('IP or Alias');
		$group->addClass('repeatable');

		$group->add(new Form_IpAddress(
			'address' . $counter,
			'Address',
			$pconfig['address']['item'][$counter],
			'ALIASV4V6'
		));

		$group->add(new Form_Button(
			'deleterow' . $counter,
			'Delete',
			null,
			'fa-solid fa-trash-can'
		))->addClass('btn-outline-secondary btn-sm nowarn')->setAttribute('title', "Delete this entry from list");

		$section->add($group);
		$counter++;
	}
} else {
	$group = new Form_Group('IP or Alias');
	$group->addClass('repeatable');

	$group->add(new Form_IpAddress(
		'address0',
		'Address',
		'',
		'ALIASV4V6'
	));

	$group->add(new Form_Button(
		'deleterow0',
		'Delete',
		null,
		'fa-solid fa-trash-can'
	))->addClass('btn-outline-secondary btn-sm nowarn')->setAttribute('title', "Delete this entry from list");

	$section->add($group);
}
$form->add($section);

$form->addGlobal(new Form_Button(
	'addrow',
	'Add IP',
	null,
	'fa-solid fa-plus'
))->addClass('btn-success addbtn')->setAttribute('title', "Add new IP address, subnet or alias name row");

fs_form_cancel($form, '/suricata/suricata_passlist.php');
print($form);
?>

<script type="text/javascript">
//<![CDATA[
// ---------- Autocomplete --------------------------------------------------------------------
var addressarray = <?= json_encode(get_alias_list(array("host", "network", "urltable"))) ?>;

events.push(function() {

	// Hide and disable all rows >= that specified
	function hideRowsAfter(row, hide) {
		var idx = 0;

		$('.repeatable').each(function(el) {
			if (idx >= row) {
				hideRow(idx, hide);
			}

			idx++;
		});
	}

	function hideRow(row, hide) {
		if (hide) {
			$('#deleterow' + row).parent('div').parent().addClass('hidden');
		} else {
			$('#deleterow' + row).parent('div').parent().removeClass('hidden');
		}

		// We need to disable the elements so they are not submitted in the POST
		$('#address' + row).prop("disabled", hide);
		$('#deleterow' + row).prop("disabled", hide);
	}

	checkLastRow();

	// Autocomplete
	$('[id^=address]').each(function() {
		if (this.id.substring(0, 8) != "address_") {
			$(this).autocomplete({
				source: addressarray
			});
		}
	});
});
//]]>
</script>
<?php include("foot.inc"); ?>

