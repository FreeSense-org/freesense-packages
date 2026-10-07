<?php
/*
 * acme_certificates_edit.php
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
require("guiconfig.inc");
require_once("freesense-utils.inc");
require_once("acme/acme.inc");
require_once("acme/acme_utils.inc");
require_once("acme/acme_htmllist.inc");
require_once("acme/pkg_acme_tabs.inc");

if (isset($_POST['id'])) {
	$id = $_POST['id'];
} else {
	$id = $_GET['id'];
}

if (isset($_GET['dup'])) {
	$id = $_GET['dup'];
}

$id = get_certificate_id($id);
if (!is_numeric($id))
{
	//default value for new items.
	$isnewitem = true;
	$a_domains[] = array();
} else {
	$isnewitem = false;
}

global $simplefields;
$simplefields = array(
	"name","descr","status",
	"acmeaccount","keylength","addressfamily","certprofile",
	"preferredchain", "dnssleep","renewafter"
);


// <editor-fold desc="domain edit HtmlList">
$fields_domains=array();
$fields_domains[0]['name']="status";
$fields_domains[0]['columnheader']="Status";
$fields_domains[0]['colwidth']="5%";
$fields_domains[0]['type']="select";
$fields_domains[0]['size']="70px";
$fields_domains[0]['items']=&$a_enabledisable;
$fields_domains[1]['name']="name";
$fields_domains[1]['columnheader']="SAN";
$fields_domains[1]['colwidth']="20%";
$fields_domains[1]['type']="textbox";
$fields_domains[1]['size']="30";
$fields_domains[2]['name']="method";
$fields_domains[2]['columnheader']="Validation Method";
$fields_domains[2]['colwidth']="15%";
$fields_domains[2]['type']="select";
$fields_domains[2]['size']="100px";

$fields_domains_details = array();
$methods = array();
foreach($acme_domain_validation_method as $key => $action) {
	if (is_array($action['fields'])) {
		foreach($action['fields'] as $field) {
			$item = $field;
			$name = $key . $item['name'];
			$item['name'] = $name;
			//$item['customdrawcell'] = customdrawcell_actions;
			$fields_domains_details[$name] = $item;
		}
	}
	if ($action['name'] != 'notforuser') {
		$methods[$key] = array();
		$methods[$key]['name'] = $action['name'];
	}
}
$fields_domains[2]['items'] = $methods;

$domainslist = new HtmlList("table_domains", $fields_domains);
$domainslist->keyfield = "name";
$domainslist->fields_details = $fields_domains_details;
$domainslist->editmode = $isnewitem;

// </editor-fold>

// <editor-fold desc="action edit HtmlList">
$fields_actions=array();
$fields_actions[0]['name']="status";
$fields_actions[0]['columnheader']="Status";
$fields_actions[0]['colwidth']="5%";
$fields_actions[0]['type']="select";
$fields_actions[0]['size']="70px";
$fields_actions[0]['items']=&$a_enabledisable;
$fields_actions[1]['name']="command";
$fields_actions[1]['columnheader']="Command";
$fields_actions[1]['colwidth']="20%";
$fields_actions[1]['type']="textbox";
$fields_actions[1]['size']="30";
$fields_actions[2]['name']="method";
$fields_actions[2]['columnheader']="Method";
$fields_actions[2]['colwidth']="15%";
$fields_actions[2]['type']="select";
$fields_actions[2]['size']="100px";
$fields_actions[2]['items']=&$acme_newcertificateactions;

$fields_actions_details=array();
foreach($acme_newcertificateactions as $key => $action) {
	if (is_array($action['fields'])) {
		foreach($action['fields'] as $field) {
			$item = $field;
			$name = $key . $item['name'];
			$item['name'] = $name;
			//$item['customdrawcell'] = customdrawcell_actions;
			$fields_actions_details[$name] = $item;
		}
	}
}
$actionslist = new HtmlList("table_actions", $fields_actions);
$actionslist->keyfield = "name";
//$actionslist->fields_details = $fields_actions_details;
$actionslist->editmode = $isnewitem;

// </editor-fold>

function customdrawcell_actions($object, $item, $itemvalue, $editable, $itemname, $counter) {
	if ($editable) {
		$object->acme_htmllist_drawcell($item, $itemvalue, $editable, $itemname, $counter);
	} else {
		echo $itemvalue;
	}
}

if (isset($id) && config_get_path("installedpackages/acme/certificates/item/{$id}")) {
	$a_domains = config_get_path("installedpackages/acme/certificates/item/{$id}/a_domainlist/item", []);
	$a_actions = config_get_path("installedpackages/acme/certificates/item/{$id}/a_actionlist/item", []);

	$pconfig["lastrenewal"] = config_get_path("installedpackages/acme/certificates/item/{$id}/lastrenewal");
	$pconfig['keypaste'] = base64_decode(config_get_path("installedpackages/acme/certificates/item/{$id}/keypaste"));
	foreach($simplefields as $stat) {
		$pconfig[$stat] = config_get_path("installedpackages/acme/certificates/item/{$id}/{$stat}");
	}
}

if (isset($_GET['dup'])) {
	unset($id);
	$pconfig['name'] .= "-copy";
}
$changedesc = "Services: ACME: Certificates: ";
$changecount = 0;

if ($_POST) {
	$changecount++;

	unset($input_errors);
	$pconfig = $_POST;

	$reqdfields = explode(" ", "name");
	$reqdfieldsn = explode(",", "Name");

	do_input_validation($_POST, $reqdfields, $reqdfieldsn, $input_errors);

	if (preg_match("/[^a-zA-Z0-9\.\-_]/", $_POST['name'])) {
		$input_errors[] = "The field 'Name' contains invalid characters.";
	}

	// If the "Custom..." option was selected in the "Private Key" dropdown...
	if ($_POST['keylength'] == 'custom') {
		// ...then the "Custom Private Key" field is required.
		$reqdfields = explode(' ', 'keypaste');
		$reqdfieldsn = explode(',', 'Custom Private Key');
		do_input_validation($_POST, $reqdfields, $reqdfieldsn, $input_errors);

		if (isset($_POST['keypaste']) &&
		    ((strpos($_POST['keypaste'], 'BEGIN PRIVATE KEY') === false) ||
		    (strpos($_POST['keypaste'], 'END PRIVATE KEY') === false))) {
			$input_errors[] = "The Custom Private Key does not appear to be valid.";
		}
	} else {
		// ...otherwise, the "Custom Private Key" field will be ignored, so
		// clear its contents to avoid triggering update_if_changed() below.
		$_POST['keypaste'] = '';
	}

	if ($_POST['stats_enabled']) {
		$reqdfields = explode(" ", "name stats_uri");
		$reqdfieldsn = explode(",", "Name,Stats Uri");
		do_input_validation($_POST, $reqdfields, $reqdfieldsn, $input_errors);
		if ($_POST['stats_username']) {
			$reqdfields = explode(" ", "stats_password stats_realm");
			$reqdfieldsn = explode(",", "Stats Password,Stats Realm");
			do_input_validation($_POST, $reqdfields, $reqdfieldsn, $input_errors);
		}
	}

	/* Ensure that our certificate names are unique */
	for ($i=0; config_get_path("installedpackages/acme/certificates/item/{$i}") !== null; $i++) {
		if (($_POST['name'] == config_get_path("installedpackages/acme/certificates/item/{$i}/name")) && ($i != $id)) {
			$input_errors[] = "This name has already been used. Names must be unique.";
		}
	}
	$a_domains = $domainslist->acme_htmllist_get_values();
	foreach($a_domains as $server){
		$domain_name = $server['name'];
		if (!is_hostname($domain_name, true)) {
			$input_errors[] = "The field 'Domainname' does not contain a valid hostname.";
		} elseif (!is_hostname($domain_name)) {
			if (strtolower(substr($server['method'], 0, 3)) != "dns") {
				$input_errors[] = "Wildcard 'Domainname' validation requires a DNS-based method.";
			}
		}
	}
	$a_actions = $actionslist->acme_htmllist_get_values();

	$certificate = array();
	if(isset($id)) {
		$certificate = config_get_path("installedpackages/acme/certificates/item/{$id}", $certificate);
	}

//	echo "newname id:$id";
	if (!empty($certificate['name']) && ($certificate['name'] != $_POST['name'])) {
		//old $certificate['name'] can be empty if a new or cloned item is saved, nothing should be renamed then
		// name changed:
		$oldvalue = $certificate['name'];
		$newvalue = $_POST['name'];
	}

	if($certificate['name'] != "") {
		$changedesc .= " modified certificate: '{$certificate['name']}'";
	}
	getarraybyref($certificate, 'a_domainlist')['item'] = $a_domains;
	getarraybyref($certificate, 'a_actionlist')['item'] = $a_actions;

	$certificate['keypaste'] = base64_encode($_POST['keypaste']);
	global $simplefields;
	foreach($simplefields as $stat) {
		update_if_changed($stat, $certificate[$stat], $_POST[$stat]);
	}

	if (isset($id) && config_get_path("installedpackages/acme/certificates/item/{$id}")) {
		config_set_path("installedpackages/acme/certificates/item/{$id}", $certificate);
	} else {
		config_set_path('installedpackages/acme/certificates/item/', $certificate);
	}
	if (!isset($input_errors)) {
		if ($changecount > 0) {
			write_config($changedesc);
		}
		header("Location: acme_certificates.php");
		exit;
	}
}

/* the stored entry (or the one being copied) for the page title and summary card */
$saved = null;
if (!$isnewitem) {
	$saved = config_get_path("installedpackages/acme/certificates/item/" . get_certificate_id(isset($_GET['dup']) ? $_GET['dup'] : ($_POST['id'] ?? $_GET['id'])));
}
$is_copy = isset($_GET['dup']);
$a_accountkeys = config_get_path('installedpackages/acme/accountkeys/item', []);

$pgtitle = array(gettext("Services"), gettext("ACME"), gettext("Certificates"));
$pglinks = array("", "acme_certificates.php", "acme_certificates.php");
if ($saved && !$is_copy) {
	$pgtitle[] = htmlspecialchars($saved['name']);
	$pglinks[] = "";
	$pgtitle[] = gettext("Edit certificate");
} else {
	$pgtitle[] = gettext("Add certificate");
}
$pglinks[] = "@self";
include("head.inc");
display_top_tabs_active($acme_tab_array['acme'], "certificates");

/* Ensure the ACME server on the ACME Account is valid, warn if not. */
if (!empty($pconfig['acmeaccount'])) {
	$acmeserver = "";
	foreach ($a_accountkeys as $accountkey) {
		if (empty($accountkey) ||
		    !is_array($accountkey)) {
			continue;
		}
		if ($accountkey['name'] == $pconfig['acmeaccount']) {
			$acmeserver = $accountkey['acmeserver'];
			break;
		}
	}
	if (!empty($acmeserver) &&
	    !array_key_exists($acmeserver, $a_acmeserver)) {
		$input_errors[] = gettext("The ACME Server stored on the current ACME Account Key no longer exists. " .
					"This certificate will not function until the ACME Account Key is configured " .
					"with a functional ACME Server value, or another valid ACME Account Key is selected.");
	}
}

if (isset($input_errors)) {
	print_input_errors($input_errors);
}

/* Summary card: saved values only */
$summary_domains = [];
$summary_methods = [];
foreach (($saved['a_domainlist']['item'] ?? []) as $domain) {
	if (is_array($domain) && (($domain['status'] ?? '') != 'disable') && !empty($domain['name'])) {
		$summary_domains[] = $domain['name'];
		$m = $domain['method'] ?? '';
		$summary_methods[$m] = $acme_domain_validation_method[$m]['name'] ?? $m;
	}
}
$summary_expires = '';
$summary_badges = [];
if (!$saved || $is_copy) {
	$summary_badges[] = fs_badge('info', $is_copy ? gettext('Copy, not saved yet') : gettext('New'));
} else {
	$summary_badges[] = (($saved['status'] ?? '') == 'active') ? fs_badge('enabled', gettext('Active')) : fs_badge('disabled');
	$issued = lookup_cert_by_name($saved['name'])['item'] ?? null;
	if (!empty($issued['crt'])) {
		$details = openssl_x509_parse(base64_decode($issued['crt']));
		if (!empty($details['validTo_time_t'])) {
			$summary_expires = date('Y-m-d', $details['validTo_time_t']);
			if ($details['validTo_time_t'] < time()) {
				$summary_badges[] = fs_badge('expired');
			} elseif ($details['validTo_time_t'] < time() + 30 * 86400) {
				$summary_badges[] = fs_badge('warn', gettext('Expires soon'));
			}
		}
	}
}
$summary_account = $saved['acmeaccount'] ?? '';
$summary_server = '';
foreach ($a_accountkeys as $accountkey) {
	if (is_array($accountkey) && ($accountkey['name'] ?? '') === $summary_account) {
		$summary_server = trim(preg_replace('/\s*\(.*$/', '', $a_acmeserver[$accountkey['acmeserver']]['name'] ?? $accountkey['acmeserver']));
	}
}
$summary_more = count($summary_domains) > 4 ? [sprintf('+%d', count($summary_domains) - 4)] : [];
fs_summary_card([
	'icon' => 'fa-certificate',
	'title' => ($saved && !$is_copy) ? $saved['name'] : ($pconfig['name'] ?? ''),
	'placeholder' => gettext('New certificate'),
	'subtitle' => $saved['descr'] ?? '',
	'badges' => $summary_badges,
	'label' => gettext('Certificate summary'),
	'facts' => [
		[gettext('Domains'), '', 'chips' => array_merge(array_slice($summary_domains, 0, 4), $summary_more), 'empty' => gettext('None yet'),
		    'note' => implode(', ', $summary_methods)],
		[gettext('Account key'), $summary_account, 'href' => $summary_account ? 'acme_accountkeys_edit.php?id=' . urlencode($summary_account) : null,
		    'note' => $summary_server, 'empty' => gettext('Not set')],
		[gettext('Expires'), $summary_expires, 'empty' => gettext('Not issued')],
		[gettext('Last renewal'), !empty($saved['lastrenewal']) ? cert_format_date('', $saved['lastrenewal'], true) : '', 'empty' => gettext('Never')],
	],
]);

$counter=0;

if (empty($a_accountkeys)) {
	print_callout(sprintf(gettext('Create and register an %1$saccount key%2$s before adding certificates.'),
	    '<a href="acme_accountkeys_edit.php">', '</a>'), 'warning', gettext('Account key required'));
	$form = null;
} else {
	$form = new \Form;

	$section = new \Form_Section(gettext('Certificate'));

	$section->addInput(new \Form_Input(
		'name',
		'*Name',
		'text',
		$pconfig['name']
	))->setHelp('Letters, digits, dot, dash and underscore. ACME creates or updates the Certificate Manager entry with this name.');

	$section->addInput(new \Form_Input(
		'descr',
		'Description',
		'text',
		$pconfig['descr']
	));

	$activedisable = array();
	$activedisable['active'] = "Active";
	$activedisable['disabled'] = "Disabled";
	$section->addInput(new \Form_Select(
		'status',
		'Status',
		$pconfig['status'],
		$activedisable
	))->setHelp('Scheduled renewal only acts on active certificates.');

	$section->addInput(new \Form_Select(
		'acmeaccount',
		'ACME account key',
		$pconfig['acmeaccount'],
		form_name_array($a_accountkeys, true)
	))->setHelp('The %1$saccount key%2$s used to issue this certificate. It also sets the ACME server (certificate authority).',
			'<a href="acme_accountkeys.php">', '</a>');

	$form->add($section);
	$section = new \Form_Section(gettext('Domains'));

	$section->addInput(new \Form_StaticText(
		'SAN list',
		'<span class="form-text help-block">' . gettext('Names (subject alternative names) in the certificate and how the ACME server validates each one. Use the plus icon of a row to show its method settings.') . '</span>'
		. $domainslist->Draw($a_domains)
	));

	$form->add($section);
	$section = new \Form_Section(gettext('Private key and renewal'));

	$section->addInput(new \Form_Select(
		'keylength',
		'Private key',
		$pconfig['keylength'],
		form_keyvalue_array($a_keylength)
	))->setHelp('Type and strength of the private key of this certificate.');

	$section->addInput(new \Form_Textarea(
		'keypaste',
		'Custom private key',
		$pconfig['keypaste']
	))->setNoWrap()
		->setAttribute('placeholder', "-----BEGIN PRIVATE KEY-----\nBASE64-ENCODED DATA\n-----END PRIVATE KEY-----")
		->setHelp('Private key in X.509 PEM format.');

	$section->addInput(new \Form_Input(
		'renewafter',
		'Renewal threshold',
		'text', $pconfig['renewafter']
	))->setHelp('Days of remaining lifetime at which ACME renews the certificate. ' .
		'Default: 2/3 of the lifetime, or 30 days when the lifetime is unknown. Ignored when longer than the lifetime.');

	$section->addInput(new \Form_StaticText(
		'Last renewal',
		(!empty($pconfig['lastrenewal'])) ? cert_format_date('', $pconfig['lastrenewal'], true) : gettext("Never")
	));

	$form->add($section);
	$section = new \Form_Section(gettext('Post-renew actions'));

	$section->addInput(new \Form_StaticText(
		'Action list',
		'<span class="form-text help-block">' . gettext('Run after a certificate is issued or renewed, for example to restart a service so it uses the new certificate.') . '</span>' .
		'<details class="fs-acme-examples"><summary>' . gettext('Examples') . '</summary><ul>' .
		'<li>' . gettext('Restart the GUI of this firewall: Shell Command') . ' <code>/etc/rc.restart_webgui</code></li>' .
		'<li>' . gettext('Restart HAProxy on this firewall: Shell Command') . ' <code>/usr/local/etc/rc.d/haproxy.sh restart</code></li>' .
		'<li>' . gettext('Restart a captive portal zone: Restart Local Service') . ' <code>captiveportal zonename</code></li>' .
		'<li>' . gettext('Restart the GUI of an HA peer (uses the HA XMLRPC sync settings): Restart Remote Service') . ' <code>webgui</code></li>' .
		'</ul></details>' .
		$actionslist->Draw($a_actions)
	));

	$form->add($section);

	$adv_set = !empty($pconfig['certprofile']) || !empty($pconfig['preferredchain']) || !empty($pconfig['dnssleep']) ||
	    !empty($pconfig['addressfamily']);
	$section = new \Form_Section(gettext('Advanced'), 'acme-cert-advanced',
	    COLLAPSIBLE | ((!empty($input_errors) || $adv_set) ? SEC_OPEN : SEC_CLOSED));

	$section->addInput(new \Form_Input(
		'certprofile',
		'Certificate profile',
		'text',
		$pconfig['certprofile']
	))->setHelp('Alternate %1$scertificate profile%2$s when the CA offers several. Blank uses the default. Let\'s Encrypt %3$soffers%2$s for example classic (default), shortlived, tlsserver.',
		'<a href="https://github.com/acmesh-official/acme.sh/wiki/Profile-selection">', '</a>',
		'<a href="https://letsencrypt.org/docs/profiles/">');

	$section->addInput(new \Form_Input(
		'preferredchain',
		'Preferred chain',
		'text',
		$pconfig['preferredchain']
	))->setHelp('Alternate %1$strust chain%2$s when the CA offers several (case-insensitive substring match).',
		'<a href="https://github.com/acmesh-official/acme.sh/wiki/Preferred-Chain">', '</a>');

	$section->addInput(new \Form_Select(
		'addressfamily',
		'Address family',
		$pconfig['addressfamily'],
		form_keyvalue_array($a_addressfamily)
	))->setHelp('Address family to use for requests to the ACME server where possible.');

	$section->addInput(new \Form_Input(
		'dnssleep',
		'DNS sleep',
		'number',
		$pconfig['dnssleep'],
		['min' => '1', 'max' => '3600']
	))->setHelp('Seconds to wait after adding TXT records before validation. ' .
		'Blank polls public DNS servers until the records are found (recommended).');

	$form->add($section);
	fs_form_cancel($form, 'acme_certificates.php');
}
if ($form) {
	print $form;
}
?>
<style>
.fs-acme-examples { margin: .25rem 0 .5rem; font-size: var(--fs-fs-sm); }
.fs-acme-examples summary { cursor: pointer; color: var(--fs-text-muted); }
.fs-acme-examples ul { margin: .4rem 0 0; padding-left: 1.2rem; }
</style>
	<?php if (isset($id) && config_get_path("installedpackages/acme/certificates/item/{$id}")): ?>
	<input name="id" type="hidden" value="<?=$id;?>" />
	<?php endif; ?>
<script type="text/javascript">
<?php
	phparray_to_javascriptarray($fields_domains_details,"fields_details_domains",Array('/*','/*/name','/*/type'));
	phparray_to_javascriptarray($acme_domain_validation_method, "showhide_domainfields",
		Array('/*', '/*/fields', '/*/fields/*', '/*/fields/*/name'));
	$domainslist->outputjavascript();
	phparray_to_javascriptarray($fields_actions_details,"fields_details_actions",Array('/*','/*/name','/*/type'));
	phparray_to_javascriptarray($acme_newcertificateactions, "showhide_actionfields",
		Array('/*', '/*/fields', '/*/fields/*', '/*/fields/*/name'));
	$actionslist->outputjavascript();
?>

	browser_InnerText_support = (document.getElementsByTagName("body")[0].innerText !== undefined) ? true : false;

	totalrows =  <?php echo $counter; ?>;

	function table_domains_listitem_change(tableId, fieldId, rowNr, field) {
		d = document;
		if (fieldId === "toggle_details") {
			fieldId = "method";
			field = d.getElementById(tableId+fieldId+rowNr);
		}
		if (fieldId === "method") {
			var actiontype = field.value;

			var table = d.getElementById(tableId);

			for(var actionkey in showhide_domainfields) {
				var showfield = actionkey === actiontype ? '' : 'none';
				if (actiontype.startsWith('dns_') && actionkey === 'anydns') {
					showfield = '';
				}
				var fields = showhide_domainfields[actionkey]['fields'];
				for(var fieldkey in fields){
					var fieldname = fields[fieldkey]['name'];
					var rowid = "tr_edititemdetails_"+rowNr+"_"+actionkey+fieldname;
					var element = d.getElementById(rowid);
					if (element) {
						element.style.display = showfield;
					}
				}
			}
		}
	}
</script>
<script type="text/javascript">
//<![CDATA[
events.push(function() {
	$('form').submit(function(event){
		// disable all elements that dont have a value to avoid posting them as it could be sending
		// more than 5000 variables which is the php default max for less than 100 san's which acme does support
		// p.s. the jquery .find(['value'='']) would not find newly added empty items) so we use .filter(...)
		$(this).find(':input').filter(function() { return !this.value }).attr("disabled", "disabled")
		return true;
	});

	$('[id^=table_domainsmethod]').change();

	// Update visibility of Custom Private Key field,
	// based upon selection in Private Key drop-down
	function keylength_change() {
		hideInput('keypaste', $('#keylength').val() != "custom");
	}

	// Update page display state on keylength selection change
	$('#keylength').change(function () {
		keylength_change();
	});

	// Set initial page display state
	keylength_change();
});
//]]>
</script>

<?php
acme_htmllist_js("table_domains");
include("foot.inc");
