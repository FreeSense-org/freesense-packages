<?php
/* FreeSense Web Gateway 2.0: ICAP and malware scanning. */
require_once('guiconfig.inc'); require_once('webgateway.inc');
$wg_config=webgateway_config();$pconfig=$wg_config;$input_errors=[];$savemsg=null;
if($_POST){$pconfig=array_merge($wg_config,$_POST);foreach(['icap_enable','local_av_enable'] as $f)$pconfig[$f]=isset($_POST[$f])?'on':'';if(webgateway_save_candidate($pconfig,gettext('Web Gateway threat protection changed'),$input_errors)){$savemsg=gettext('Threat protection saved and applied to Squid.');$wg_config=$pconfig=webgateway_config();}}
$local_available=is_executable('/usr/local/bin/c-icap')&&is_executable('/usr/local/sbin/clamd')&&is_file('/usr/local/lib/c_icap/squidclamav.so');
$pgtitle=[gettext('Services'),gettext('Web Gateway'),gettext('Threat protection')];
$pglinks=['', '/webgateway/webgateway.php', '@self'];
include('head.inc');webgateway_display_tabs('threat');if($input_errors)print_input_errors($input_errors);if($savemsg)print_info_box($savemsg,'success');

$form = new Form(gettext('Save and apply'));

$section = new Form_Section(gettext('External ICAP'), 'wg-threat-icap');
$section->addInput(new Form_Checkbox('icap_enable', gettext('Enable'), gettext('Enable external ICAP adaptation'), $pconfig['icap_enable'] === 'on', 'on'))
	->setHelp(gettext('Send requests and responses to an external scanner or DLP service.'));
$section->addInput(new Form_Input('icap_req_url', gettext('REQMOD service URL'), 'text', $pconfig['icap_req_url']))
	->addClass('fs-mono')
	->setAttribute('placeholder', 'icaps://scanner.example:1344/request');
$section->addInput(new Form_Input('icap_resp_url', gettext('RESPMOD service URL'), 'text', $pconfig['icap_resp_url']))
	->addClass('fs-mono')
	->setAttribute('placeholder', 'icaps://scanner.example:1344/response');
$section->addInput(new Form_Select('icap_failure', gettext('If the service fails'), $pconfig['icap_failure'], [
	'bypass' => gettext('Bypass and alert'),
	'closed' => gettext('Block eligible traffic'),
]));
$form->add($section);

$section = new Form_Section(gettext('Local malware scanner'), 'wg-threat-av');
$section->addInput(new Form_StaticText(gettext('Companion'),
    ($local_available ? fs_badge('enabled', gettext('AV companion installed')) : fs_badge('neutral', gettext('AV companion not installed')))
    . '<span class="form-text help-block">' . htmlspecialchars($local_available
        ? gettext('ClamAV, c-icap and squidclamav from FreeSense-pkg-WebGateway-AV are available.')
        : gettext('Install FreeSense-pkg-WebGateway-AV from the Package Manager to scan locally.')) . '</span>'));
$av = new Form_Checkbox('local_av_enable', gettext('Scanning'), gettext('Scan requests and responses with ClamAV/c-icap'), $pconfig['local_av_enable'] === 'on', 'on');
if (!$local_available) {
	$av->setDisabled();
}
$section->addInput($av);
$section->addInput(new Form_Input('av_max_mb', gettext('Maximum scanned object'), 'number', $pconfig['av_max_mb'], ['min' => 1, 'max' => 4096]))
	->setHelp(gettext('MiB. Written into the local squidclamav configuration when Save and apply succeeds.'));
$section->addInput(new Form_Select('av_failure', gettext('If the scanner fails'), $pconfig['av_failure'], [
	'closed' => gettext('Block (recommended)'),
	'bypass' => gettext('Bypass and alert'),
]))->setHelp(gettext('HTTPS response bodies reach scanners only for inspected destinations.'));
$form->add($section);

print($form);
include('foot.inc');
