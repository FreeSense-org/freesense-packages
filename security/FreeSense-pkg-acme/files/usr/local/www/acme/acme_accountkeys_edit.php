<?php
/*
 * acme_accountkeys_edit.php
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
require_once("acme/acme.inc");
require_once("acme/acme_utils.inc");
require_once("acme/acme_htmllist.inc");
require_once("acme/pkg_acme_tabs.inc");

if ($_POST['action'] == "createkey") {
	$caname = $_POST['caname'];
	$ca = $a_acmeserver[$caname]['url'];
	echo generateAccountKey("_createkey", $ca);
	exit;
}
if ($_POST['action'] == "registerkey") {
	$caname = $_POST['caname'];
	$key = $_POST['key'];
	$email = $_POST['email'];
	$ca = $a_acmeserver[$caname]['url'];
	$eabkid = (!empty($_POST['eabkid'])) ? $_POST['eabkid'] : "";
	$eabhmac = (!empty($_POST['eabhmac'])) ? $_POST['eabhmac'] : "";
	echo "Register key at CA: {$ca}\n";
	echo (registerAcmeAccountKey("_registerkey", $ca, $key, $email, $eabkid, $eabhmac)) ? "reg-ok" : "reg-fail" ;
	exit;
}

$id = $_REQUEST['id'];

if (isset($_GET['dup'])) {
	$id = $_GET['dup'];
}

$id = get_accountkey_id($id);
if (!is_numeric($id))
{
	//default value for new items.
	$isnewitem = true;
} else {
	$isnewitem = false;
}

global $simplefields;
$simplefields = array(
	"name", "descr", "email", "eabkid", "eabhmac", "acmeserver"
);

function customdrawcell_actions($object, $item, $itemvalue, $editable, $itemname, $counter) {
	if ($editable) {
		$object->acme_htmllist_drawcell($item, $itemvalue, $editable, $itemname, $counter);
	} else {
		echo $itemvalue;
	}
}

if (isset($id) && config_get_path("installedpackages/acme/accountkeys/item/{$id}")) {
	$pconfig['accountkey'] = base64_decode(config_get_path("installedpackages/acme/accountkeys/item/{$id}/accountkey"));
	foreach($simplefields as $stat) {
		$pconfig[$stat] = config_get_path("installedpackages/acme/accountkeys/item/{$id}/{$stat}");
	}
}

if (isset($_GET['dup'])) {
	unset($id);
	$pconfig['name'] .= "-copy";
}
$changedesc = "Services: ACME: Account Keys: Edit: ";
$changecount = 0;

if ($_POST) {
	$changecount++;

	unset($input_errors);
	$pconfig = $_POST;

	$reqdfields = explode(" ", "name");
	$reqdfieldsn = explode(",", "Name");

	do_input_validation($_POST, $reqdfields, $reqdfieldsn, $input_errors);

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

	if (!empty($_POST['email'])) {
		/* Validate e-mail address */
		if (preg_match("/[\!\#\$\%\^\(\)\~\?\>\<\&\/\\\,\"\']/", $_POST['email'])) {
			$input_errors[] = gettext("The supplied e-mail address contains invalid characters.");
		}
	}

	if (!array_key_exists($_POST['acmeserver'], $a_acmeserver)) {
		$input_errors[] = gettext("The supplied ACME Server does not exist.");
	}

	/* Ensure that our account key names are unique */
	foreach (config_get_path("installedpackages/acme/accountkeys/item", []) as $i => $item) {
		if (($i != $id) && ($_POST['name'] == $item['name'])) {
			$input_errors[] = "This name has already been used. Names must be unique.";
		}
	}

	$accountkey = array();
	if(isset($id)) {
		$accountkey = config_get_path("installedpackages/acme/accountkeys/item/{$id}", $accountkey);
	}

	if (!empty($accountkey['name']) && ($accountkey['name'] != $_POST['name'])) {
		//old $accountkey['name'] can be empty if a new or cloned item is saved, nothing should be renamed then
		// name changed:
		$oldvalue = $accountkey['name'];
		$newvalue = $_POST['name'];
		$configured_certificates = config_get_path('installedpackages/acme/certificates/item', []);
		$certificates_changed = false;
		foreach ($configured_certificates as &$configured_certificate) {
			if ($configured_certificate['acmeaccount'] == $oldvalue) {
				$configured_certificate['acmeaccount'] = $newvalue;
				$certificates_changed = true;
			}
		}
		if ($certificates_changed) {
			config_set_path('installedpackages/acme/certificates/item', $configured_certificates);
		}
	}

	if($accountkey['name'] != "") {
		$changedesc .= " modified account key: '{$accountkey['name']}'";
	}

	$accountkey['accountkey'] = base64_encode($_POST['accountkey']);
	global $simplefields;
	foreach($simplefields as $stat) {
		update_if_changed($stat, $accountkey[$stat], $_POST[$stat]);
	}

	if (isset($id) && config_get_path("installedpackages/acme/accountkeys/item/{$id}")) {
		config_set_path("installedpackages/acme/accountkeys/item/{$id}", $accountkey);
	} else {
		config_set_path('installedpackages/acme/accountkeys/item/', $accountkey);
	}
	if (!isset($input_errors)) {
		if ($changecount > 0) {
			write_config($changedesc);
		}
		echo "<pre/>";
		//print_r($config['installedpackages']['acme']);
		header("Location: acme_accountkeys.php");
		exit;
	}
}

/* the stored key (or the one being copied) for the page title and summary card */
$is_copy = isset($_GET['dup']);
$saved = $isnewitem ? null : config_get_path("installedpackages/acme/accountkeys/item/" . get_accountkey_id($is_copy ? $_GET['dup'] : $_REQUEST['id']));

$pgtitle = array(gettext("Services"), gettext("ACME"), gettext("Account keys"));
$pglinks = array("", "acme_certificates.php", "acme_accountkeys.php");
if ($saved && !$is_copy) {
	$pgtitle[] = htmlspecialchars($saved['name']);
	$pglinks[] = "";
	$pgtitle[] = gettext("Edit account key");
} else {
	$pgtitle[] = gettext("Add account key");
}
$pglinks[] = "@self";
include("head.inc");
display_top_tabs_active($acme_tab_array['acme'], "accountkeys");

if (!empty($pconfig['acmeserver']) &&
    !array_key_exists($pconfig['acmeserver'], $a_acmeserver)) {
	$input_errors[] = gettext("The ACME Server stored on this key no longer exists and the " .
				"field has been reset to the default value. This key, and any " .
				"certificates using this key, will not function until this key " .
				"is configured with a functional ACME Server value.");
}

if (isset($input_errors)) {
	print_input_errors($input_errors);
}

/* Summary card: saved values only */
$summary_certs = [];
if ($saved) {
	foreach (config_get_path('installedpackages/acme/certificates/item', []) as $certificate) {
		if (is_array($certificate) && ($certificate['acmeaccount'] ?? '') === $saved['name']) {
			$summary_certs[] = $certificate['name'];
		}
	}
}
$summary_server = $saved['acmeserver'] ?? '';
$summary_sname = $a_acmeserver[$summary_server]['name'] ?? '';
fs_summary_card([
	'icon' => 'fa-key',
	'title' => ($saved && !$is_copy) ? $saved['name'] : ($pconfig['name'] ?? ''),
	'placeholder' => gettext('New account key'),
	'subtitle' => $saved['descr'] ?? '',
	'badges' => (!$saved || $is_copy) ? [fs_badge('info', $is_copy ? gettext('Copy, not saved yet') : gettext('New'))] :
	    (($summary_server !== '' && $summary_sname === '') ? [fs_badge('warn', gettext('Unknown server'))] : []),
	'label' => gettext('Account key summary'),
	'facts' => [
		[gettext('ACME server'), trim(preg_replace('/\s*\(.*$/', '', $summary_sname)) ?: $summary_server, 'note' => $summary_sname ? $summary_server : '', 'empty' => gettext('Not set')],
		[gettext('E-mail'), $saved['email'] ?? '', 'empty' => gettext('Not set')],
		[gettext('External account binding'), !empty($saved['eabkid']) ? gettext('Configured') : '', 'empty' => gettext('Not used')],
		[gettext('Used by'), '', 'chips' => array_slice($summary_certs, 0, 4), 'empty' => gettext('No certificates'),
		    'note' => (count($summary_certs) > 4) ? sprintf(gettext('and %d more'), count($summary_certs) - 4) : ''],
	],
]);

$counter=0;

$form = new \Form;
/* posted with the form; the stored name identifies the entry (get_accountkey_id) */
if ($saved && !$is_copy) {
	$form->addGlobal(new \Form_Input('id', null, 'hidden', $saved['name']));
}

$section = new \Form_Section(gettext('Account'));
$section->addInput(new \Form_Input(
	'name',
	'*Name',
	'text',
	$pconfig['name']
))->setHelp('Short name of this account key. Certificates refer to it by this name.');

$section->addInput(new \Form_Input(
	'descr',
	'Description',
	'text', $pconfig['descr']
));

$section->addInput(new \Form_Input(
	'email',
	'E-mail address',
	'text',
	$pconfig['email']
))->setHelp('The certificate authority may send important notices to this address.');

$section->addInput(new \Form_Select(
	'acmeserver',
	'ACME server',
	$pconfig['acmeserver'],
	form_keyvalue_array($a_acmeserver)
))->setHelp('The certificate authority that issues certificates for this key. ' .
	'Use a staging server until validation works, then switch to production.');

$form->add($section);
$section = new \Form_Section(gettext('Key and registration'));

$section->addInput(new \Form_Textarea(
	'accountkey',
	'Account key',
	$pconfig['accountkey']
))->setNoWrap()->setHelp('Private key that identifies and authorizes the account. Leave empty and use %1$sCreate new account key%2$s to generate one.',
	'<b>', '</b>');

$section->addInput(new \Form_StaticText(
	'Actions',
	'<div class="fs-acme-keytools">' .
	'<button type="button" id="btncreatekey" class="btn btn-sm btn-outline-secondary"><i id="btncreatekeyicon" class="fa-solid fa-plus icon-embed-btn" aria-hidden="true"></i>' . gettext('Create new account key') . '</button>' .
	'<button type="button" id="btnregisterkey" class="btn btn-sm btn-primary"><i id="btnregisterkeyicon" class="fa-solid fa-key icon-embed-btn" aria-hidden="true"></i>' . gettext('Register account key') . '</button>' .
	'<span id="acme-keytools-status" class="fs-acme-keystatus" role="status" aria-live="polite"></span>' .
	'</div>'
))->setHelp('Register a key with the selected ACME server before certificates can use it. ' .
	'Registering again is harmless. When it fails, see %1$s.',
	'<code>/tmp/acme/_registerkey/acme_issuecert.log</code>');

$form->add($section);

$eab_set = !empty($pconfig['eabkid']) || !empty($pconfig['eabhmac']);
$section = new \Form_Section(gettext('External account binding'), 'acme-key-eab',
    COLLAPSIBLE | ((!empty($input_errors) || $eab_set) ? SEC_OPEN : SEC_CLOSED));

$section->addInput(new \Form_StaticText(
	null,
	'<span class="form-text help-block">' . gettext('Only for certificate authorities that require it (for example ZeroSSL or Google). The values come from the CA and bind this key to an existing account there. Leave blank otherwise.') . '</span>'
));

$section->addInput(new \Form_Input(
	'eabkid',
	'EAB key ID',
	'text',
	$pconfig['eabkid']
));

$section->addInput(new \Form_Textarea(
	'eabhmac',
	'EAB HMAC key',
	$pconfig['eabhmac']
));

$form->add($section);
fs_form_cancel($form, 'acme_accountkeys.php');

print $form;
?>
<style>
.fs-acme-keytools { display: flex; flex-wrap: wrap; align-items: center; gap: .5rem; }
.fs-acme-keystatus { font-size: var(--fs-fs-sm); }
.fs-acme-keystatus .fa-circle-check { color: var(--fs-pass); }
.fs-acme-keystatus .fa-circle-xmark { color: var(--fs-block); }
</style>
<script type="text/javascript">
//<![CDATA[
events.push(function() {
	var status = document.getElementById('acme-keytools-status');
	var txt = {
		creating: <?=json_encode(gettext('Creating a key…'))?>,
		created: <?=json_encode(gettext('New key created. Save to keep it.'))?>,
		registering: <?=json_encode(gettext('Registering…'))?>,
		registered: <?=json_encode(gettext('Registered'))?>,
		failed: <?=json_encode(gettext('Registration failed'))?>
	};

	/* status text with an optional leading icon, built as DOM nodes */
	function setStatus(text, icon) {
		status.textContent = '';
		if (icon) {
			var i = document.createElement('i');
			i.className = 'fa-solid ' + icon + ' icon-embed-btn';
			i.setAttribute('aria-hidden', 'true');
			status.appendChild(i);
		}
		status.appendChild(document.createTextNode(text));
	}

	$('#btnregisterkey').click(function() {
		$("#btnregisterkeyicon").removeClass("fa-key fa-check fa-times").addClass("fa-gear fa-spin");
		setStatus(txt.registering);
		var key = $("#accountkey").val();
		var caname = $("#acmeserver").val();
		var email = $("#email").val();
		var eabkid = $("#eabkid").val();
		var eabhmac = $("#eabhmac").val();
		$.ajax({
			type: "post",
			data: { action: "registerkey", caname: caname, key: key, email: email, eabkid: eabkid, eabhmac: eabhmac },
			success: function(data) {
				if (data.toLowerCase().indexOf("reg-ok") > -1 ) {
					$("#btnregisterkeyicon").removeClass("fa-gear fa-spin").addClass("fa-key");
					setStatus(txt.registered, 'fa-circle-check');
				} else {
					$("#btnregisterkeyicon").removeClass("fa-gear fa-spin").addClass("fa-key");
					setStatus(txt.failed, 'fa-circle-xmark');
				}
			},
			error: function() {
				$("#btnregisterkeyicon").removeClass("fa-gear fa-spin").addClass("fa-key");
				setStatus(txt.failed, 'fa-circle-xmark');
			}
		});
	});

	$('#btncreatekey').click(function() {
		$("#btncreatekeyicon").removeClass("fa-plus fa-check").addClass("fa-gear fa-spin");
		setStatus(txt.creating);
		var caname = $("#acmeserver").val();
		$.ajax({
			type: "post",
			data: { action: "createkey", caname: caname },
			success: function(data) {
				$("#accountkey").val(data);
				$("#btncreatekeyicon").removeClass("fa-gear fa-spin").addClass("fa-plus");
				setStatus(txt.created, 'fa-circle-check');
			}
		});
	});
});
//]]>
</script>
<?php
include("foot.inc");
