<?php
/* FreeSense Web Gateway 2.0: identity providers. */
require_once('guiconfig.inc'); require_once('webgateway.inc');
$wg_config=webgateway_config(); $pconfig=$wg_config; $input_errors=[]; $savemsg=null;
if($_POST){$pconfig=array_merge($wg_config,$_POST); if(webgateway_save_candidate($pconfig,gettext('Web Gateway identity settings changed'),$input_errors)){ $savemsg=gettext('Identity provider saved and applied to Squid.'); $wg_config=$pconfig=webgateway_config(); }}
$servers=webgateway_auth_servers();
$pgtitle=[gettext('Services'),gettext('Web Gateway'),gettext('Identity')];
$pglinks=['', '/webgateway/webgateway.php', '@self'];
include('head.inc'); webgateway_display_tabs('identity'); if($input_errors)print_input_errors($input_errors);if($savemsg)print_info_box($savemsg,'success');

print_callout(htmlspecialchars(gettext('Authentication is available only on explicit proxy listeners. Transparent interception uses source network and interface policy because browsers cannot authenticate reliably during interception.')), 'info');

$form = new Form(gettext('Save and apply'));

$section = new Form_Section(gettext('Identity provider'), 'wg-identity-provider');
$section->addInput(new Form_StaticText(gettext('Provider'), webgateway_choice_cards('auth_mode', 'radio', [
	'none' => ['icon' => 'fa-network-wired', 'title' => gettext('Source network'), 'help' => gettext('No login challenge. Identify clients by source address.')],
	'local' => ['icon' => 'fa-users', 'title' => gettext('Local users'), 'help' => gettext('Enabled users in the FreeSense local database.')],
	'ldap' => ['icon' => 'fa-building-shield', 'title' => gettext('LDAP / Active Directory'), 'help' => gettext('Basic proxy authentication against an LDAPS/StartTLS server.')],
	'radius' => ['icon' => 'fa-tower-broadcast', 'title' => gettext('RADIUS'), 'help' => gettext('Basic proxy authentication through a configured RADIUS server.')],
	'kerberos' => ['icon' => 'fa-key', 'title' => gettext('Kerberos / Negotiate'), 'help' => gettext('Browser single sign-on using a service principal and keytab.')],
], $pconfig['auth_mode'], gettext('Identity provider'))));
$form->add($section);

$section = new Form_Section(gettext('Authentication server'), 'wg-identity-server');
$section->addInput(new Form_Select('auth_server', gettext('Server'), $pconfig['auth_server'], ['' => gettext('Select for LDAP or RADIUS')] + $servers))
	->setHelp($servers ? gettext('LDAP and RADIUS servers from System > User Manager > Authentication Servers.')
	    : gettext('No LDAP or RADIUS server is configured yet.'));
$section->addInput(new Form_StaticText(gettext('Servers'),
    '<div class="wg-buttons"><a class="btn btn-sm btn-outline-secondary" href="/system_authservers.php"><i class="fa-solid fa-gear icon-embed-btn" aria-hidden="true"></i>'
    . htmlspecialchars(gettext('Manage authentication servers')) . '</a>'
    . '<a class="btn btn-sm btn-outline-secondary" href="/diag_authentication.php"><i class="fa-solid fa-vial icon-embed-btn" aria-hidden="true"></i>'
    . htmlspecialchars(gettext('Test authentication')) . '</a></div>'));
$form->add($section);

$section = new Form_Section(gettext('Login challenge'), 'wg-identity-challenge');
$section->addInput(new Form_Input('auth_realm', gettext('Realm'), 'text', $pconfig['auth_realm']))
	->setHelp(gettext('Shown to clients in the browser login prompt.'));
$section->addInput(new Form_Input('auth_ttl', gettext('Credential TTL'), 'number', $pconfig['auth_ttl'], ['min' => 1, 'max' => 1440]))
	->setHelp(gettext('Minutes before a client must authenticate again (1-1440).'));
$form->add($section);

$section = new Form_Section(gettext('Kerberos / Negotiate'), 'wg-identity-kerberos');
$section->addInput(new Form_Input('kerberos_principal', gettext('Service principal'), 'text', $pconfig['kerberos_principal']))
	->addClass('fs-mono')
	->setAttribute('placeholder', 'HTTP/proxy.example.com@EXAMPLE.COM');
$section->addInput(new Form_Input('kerberos_keytab', gettext('Keytab path'), 'text', $pconfig['kerberos_keytab']))
	->addClass('fs-mono')
	->setHelp(gettext('The keytab must be readable only by root and the Squid runtime account. NTLM/SMB fallback is intentionally unsupported.'));
$form->add($section);

print($form);
?>
<script>
(function () {
	/* Show only the sections the selected provider uses; hidden fields still post. */
	var show = {
		'wg-identity-server': ['ldap', 'radius'],
		'wg-identity-challenge': ['local', 'ldap', 'radius', 'kerberos'],
		'wg-identity-kerberos': ['kerberos']
	};
	function update() {
		var checked = document.querySelector('input[name="auth_mode"]:checked');
		var mode = checked ? checked.value : 'none';
		Object.keys(show).forEach(function (id) {
			var el = document.getElementById(id);
			if (el) {
				el.classList.toggle('d-none', show[id].indexOf(mode) < 0);
			}
		});
	}
	document.querySelectorAll('input[name="auth_mode"]').forEach(function (r) {
		r.addEventListener('change', update);
	});
	update();
})();
</script>
<?php include('foot.inc'); ?>
