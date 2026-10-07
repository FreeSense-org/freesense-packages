<?php
/* FreeSense Web Gateway 2.0: listeners and interception. */
require_once('guiconfig.inc');
require_once('webgateway.inc');
$wg_config = webgateway_config();
$pconfig = $wg_config;
$input_errors = [];
$savemsg = null;
if ($_POST) {
	$pconfig = array_merge($wg_config, $_POST);
	foreach (['enable', 'ha_sync'] as $field) {
		$pconfig[$field] = isset($_POST[$field]) ? 'on' : '';
	}
	$pconfig['interfaces'] = array_values(array_filter((array)($_POST['interfaces'] ?? [])));
	$pconfig['listener_modes'] = array_values(array_filter((array)($_POST['listener_modes'] ?? [])));
	$source_errors = [];
	$dest_errors = [];
	$client_errors = [];
	$validation_errors = [];
	$pconfig['additional_client_networks'] = webgateway_encode_list(webgateway_normalize_networks($_POST['additional_client_networks_text'] ?? '', $client_errors));
	$pconfig['exempt_sources'] = webgateway_encode_list(webgateway_normalize_networks($_POST['exempt_sources_text'] ?? '', $source_errors));
	$pconfig['exempt_destinations'] = webgateway_encode_list(webgateway_normalize_networks($_POST['exempt_destinations_text'] ?? '', $dest_errors));
	$input_errors = array_merge($client_errors, $source_errors, $dest_errors);
	if (empty($input_errors) && webgateway_save_candidate($pconfig, gettext('Web Gateway listeners changed'), $validation_errors)) {
		$savemsg = gettext('Listeners and interception rules saved and applied to Squid.');
		$wg_config = $pconfig = webgateway_config();
	} else {
		$input_errors = array_merge($input_errors, $validation_errors);
	}
}
$available = webgateway_client_interfaces();
$pgtitle = [gettext('Services'), gettext('Web Gateway'), gettext('Listeners')];
$pglinks = ['', '/webgateway/webgateway.php', '@self'];
include('head.inc');
webgateway_display_tabs('listeners');
if ($input_errors) print_input_errors($input_errors);
if ($savemsg) print_info_box($savemsg, 'success');

$form = new Form(gettext('Save and apply'));

/* Service */
$section = new Form_Section(gettext('Gateway service'), 'wg-service');
$section->addInput(new Form_Checkbox('enable', gettext('Enable'), gettext('Enable FreeSense Web Gateway'), $pconfig['enable'] === 'on', 'on'))
	->setHelp(gettext('The gateway starts with the saved settings. Interception rules exist only while it is enabled and healthy.'));
$section->addInput(new Form_Checkbox('ha_sync', gettext('HA sync'), gettext('Synchronize Web Gateway configuration to the HA peer'), $pconfig['ha_sync'] === 'on', 'on'))
	->setHelp(gettext('Compiled feeds are rebuilt locally. CA private keys follow the system certificate synchronization policy and are never copied by this package.'));
$form->add($section);

/* Clients */
$section = new Form_Section(gettext('Clients'), 'wg-clients');
if ($available) {
	$cards = [];
	foreach ($available as $id => $description) {
		$cards[$id] = ['title' => $description, 'meta' => $id, 'icon' => 'fa-network-wired'];
	}
	$section->addInput(new Form_StaticText(gettext('Client interfaces'),
	    webgateway_choice_cards('interfaces[]', 'checkbox', $cards, $pconfig['interfaces'], gettext('Client interfaces')) .
	    '<span class="form-text help-block">' . htmlspecialchars(gettext('Clients on these interfaces may use the gateway. WAN and gateway-facing interfaces are never offered.')) . '</span>'));
} else {
	$section->addInput(new Form_StaticText(gettext('Client interfaces'),
	    '<span class="fs-muted">' . htmlspecialchars(gettext('No eligible internal interfaces were detected. WAN and gateway-facing interfaces are never offered here.')) . '</span>'));
}
$section->addInput(new Form_Textarea('additional_client_networks_text', gettext('Additional client networks'), webgateway_decode_list($pconfig['additional_client_networks'])))
	->setRows(4)
	->addClass('fs-mono')
	->setAttribute('placeholder', "10.0.0.0/8\n172.16.0.0/12\n192.168.0.0/16")
	->setHelp(gettext('Routed or VPN client networks that may use the explicit proxy, one per line. Directly connected networks come from the selected interfaces. Firewall pass rules are still required.'));
$form->add($section);

/* Listener modes */
$section = new Form_Section(gettext('Listener modes'), 'wg-modes');
foreach ([
	['explicit', gettext('Explicit proxy'), gettext('Managed clients or a PAC file use the proxy directly.'), 'port'],
	['intercept_http', gettext('Transparent HTTP'), gettext('PF redirects TCP/80 from the selected interfaces.'), 'http_intercept_port'],
	['intercept_https', gettext('Transparent HTTPS'), gettext('Requires selective or full TLS inspection and a trusted CA.'), 'https_intercept_port'],
] as [$mode, $title, $help, $port]) {
	$group = new Form_Group($title);
	$group->add(new Form_Checkbox('listener_modes[]', $title, gettext('Enabled'), in_array($mode, $pconfig['listener_modes'], true), $mode))
		->setAttribute('id', $mode)
		->setWidth(4)
		->setHelp($help);
	$group->add(new Form_Input($port, gettext('Local port'), 'number', $pconfig[$port], ['min' => 1, 'max' => 65535]))
		->addClass('fs-mono')
		->setWidth(3)
		->setHelp(gettext('Local port'));
	$section->add($group);
}
$form->add($section);

/* Interception safety */
$section = new Form_Section(gettext('Interception safety'), 'wg-safety');
$section->addInput(new Form_Select('quic_policy', gettext('HTTP/3 and QUIC'), $pconfig['quic_policy'], [
	'allow' => gettext('Allow UDP/443 (not inspected)'),
	'block' => gettext('Block UDP/443 to force TCP fallback'),
]))->setHelp(gettext('Blocking applies to transparent HTTPS interception only.'));
$section->addInput(new Form_Select('failure_policy', gettext('Proxy failure'), $pconfig['failure_policy'], [
	'open' => gettext('Fail open: remove redirects if proxy is unhealthy'),
	'closed' => gettext('Fail closed: keep policy enforcement'),
]));
$section->addInput(new Form_StaticText(gettext('PAC file'),
    '<a class="btn btn-sm btn-outline-secondary" href="/webgateway/webgateway_pac.php"><i class="fa-solid fa-download icon-embed-btn" aria-hidden="true"></i>' .
    htmlspecialchars(gettext('Download explicit-proxy PAC file')) . '</a>' .
    '<span class="form-text help-block">' . htmlspecialchars(gettext('Deploy it with device management or host it on your own WPAD endpoint. FreeSense does not expose an unauthenticated discovery service on the management GUI.')) . '</span>'));
$form->add($section);

/* Exemptions */
$has_exemptions = (webgateway_decode_list($pconfig['exempt_sources']) !== '') || (webgateway_decode_list($pconfig['exempt_destinations']) !== '');
$section = new Form_Section(gettext('Exemptions'), 'wg-exemptions', COLLAPSIBLE | ((!empty($input_errors) || $has_exemptions) ? SEC_OPEN : SEC_CLOSED));
$section->addInput(new Form_Textarea('exempt_sources_text', gettext('Source addresses'), webgateway_decode_list($pconfig['exempt_sources'])))
	->setRows(5)
	->addClass('fs-mono')
	->setHelp(gettext('Addresses or networks, one per line, that are never redirected to the proxy.'));
$section->addInput(new Form_Textarea('exempt_destinations_text', gettext('Destination addresses'), webgateway_decode_list($pconfig['exempt_destinations'])))
	->setRows(5)
	->addClass('fs-mono')
	->setHelp(gettext('Management access, firewall-owned addresses and local control traffic are bypassed automatically; add application-specific exceptions here.'));
$form->add($section);

print($form);
include('foot.inc');
