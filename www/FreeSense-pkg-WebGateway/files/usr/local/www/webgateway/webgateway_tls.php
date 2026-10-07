<?php
/* FreeSense Web Gateway 2.0: TLS inspection. */
require_once('guiconfig.inc');
require_once('webgateway.inc');
$wg_config = webgateway_config();
$pconfig = $wg_config;
$input_errors = [];
$savemsg = null;
if ($_POST) {
	$pconfig = array_merge($wg_config, $_POST);
	$pconfig['tls_ack'] = isset($_POST['tls_ack']) ? 'on' : '';
	foreach (['inspect_domains','splice_domains'] as $field) {
		$normalized = webgateway_normalize_domains($_POST[$field . '_text'] ?? '', $input_errors);
		$pconfig[$field] = webgateway_encode_list($normalized);
	}
	$validation_errors = [];
	if (!$input_errors && webgateway_save_candidate($pconfig, gettext('Web Gateway TLS policy changed'), $validation_errors)) {
		$savemsg = gettext('TLS handling policy saved and applied to Squid.');
		$wg_config = $pconfig = webgateway_config();
	} else {
		$input_errors = array_merge($input_errors, $validation_errors);
	}
}
$cas = webgateway_internal_cas();
$pgtitle = [gettext('Services'), gettext('Web Gateway'), gettext('TLS inspection')];
$pglinks = ['', '/webgateway/webgateway.php', '@self'];
include('head.inc');
webgateway_display_tabs('tls');
if ($input_errors) print_input_errors($input_errors);
if ($savemsg) print_info_box($savemsg, 'success');

print_callout(htmlspecialchars(gettext('Use it only on managed devices after reviewing applicable privacy and employment law. Certificate-pinned and mutual-TLS applications must remain spliced.')),
    'warning', gettext('TLS inspection changes the trust boundary'));

$form = new Form(gettext('Save and apply'));

$section = new Form_Section(gettext('HTTPS handling'), 'wg-tls-mode');
$section->addInput(new Form_StaticText(gettext('Mode'), webgateway_choice_cards('tls_mode', 'radio', [
	'tunnel' => ['icon' => 'fa-shield-halved', 'title' => gettext('Tunnel only'),
	    'help' => gettext('Default. CONNECT traffic stays end-to-end encrypted; policy can use host, SNI and IP only.')],
	'selective' => ['icon' => 'fa-filter', 'title' => gettext('Selective inspection'),
	    'help' => gettext('Inspect only destinations in the inspection list; splice everything else.')],
	'full' => ['icon' => 'fa-magnifying-glass', 'title' => gettext('Full inspection'),
	    'help' => gettext('Inspect by default while honoring the built-in and administrator bypass lists.')],
], $pconfig['tls_mode'], gettext('HTTPS handling mode'))));
$form->add($section);

$section = new Form_Section(gettext('Inspection certificate authority'), 'wg-tls-ca');
$section->addInput(new Form_Select('caref', gettext('Signing CA'), $pconfig['caref'], ['' => gettext('None (tunnel only)')] + $cas))
	->setHelp($cas ? gettext('An internal CA with a private key. Deploy its public certificate to managed clients before turning inspection on.')
	    : gettext('No internal CA with a private key exists. Create a dedicated Web Gateway CA in Certificate Manager before enabling inspection.'));
$buttons = '<div class="wg-buttons"><a class="btn btn-sm btn-outline-secondary" href="/system_camanager.php"><i class="fa-solid fa-certificate icon-embed-btn" aria-hidden="true"></i>'
    . htmlspecialchars(gettext('Certificate Manager')) . '</a>';
if ($pconfig['caref']) {
	$buttons .= '<a class="btn btn-sm btn-outline-secondary" href="/system_camanager.php?act=export_cert&amp;id=' . htmlspecialchars(urlencode($pconfig['caref'])) . '">'
	    . '<i class="fa-solid fa-download icon-embed-btn" aria-hidden="true"></i>' . htmlspecialchars(gettext('Export CA certificate')) . '</a>';
}
$section->addInput(new Form_StaticText(gettext('Certificates'), $buttons . '</div>'));
$section->addInput(new Form_Checkbox('tls_ack', gettext('Acknowledgement'),
    gettext('I understand the legal, privacy, client-trust and application-compatibility impact of decrypting TLS traffic.'), $pconfig['tls_ack'] === 'on', 'on'))
	->setHelp(gettext('Required for selective and full inspection.'));
$form->add($section);

$section = new Form_Section(gettext('Bump and splice lists'), 'wg-tls-lists');
$section->addInput(new Form_Textarea('inspect_domains_text', gettext('Inspect in selective mode'), webgateway_decode_list($pconfig['inspect_domains'])))
	->setRows(8)
	->addClass('fs-mono')
	->setAttribute('placeholder', '.example.com')
	->setHelp(gettext('One destination domain per line. A leading dot includes subdomains.'));
$section->addInput(new Form_Textarea('splice_domains_text', gettext('Always splice'), webgateway_decode_list($pconfig['splice_domains'])))
	->setRows(8)
	->addClass('fs-mono')
	->setAttribute('placeholder', '.bank.example')
	->setHelp(gettext('Never inspected. Added to the built-in pinned, update, authentication and PKI bypass set.'));
$form->add($section);

print($form);

print_callout(htmlspecialchars(gettext('ECH or unknown-SNI traffic is spliced by default. Transparent HTTPS inspection can block QUIC under Listeners so clients retry over TCP.')), 'info');
include('foot.inc');
