<?php
/* FreeSense Web Gateway 2.0: cache, shaping and upstream proxy. */
require_once('guiconfig.inc');require_once('webgateway.inc');
$wg_config=webgateway_config();$pconfig=$wg_config;$input_errors=[];$savemsg=null;
if($_POST){$pconfig=array_merge($wg_config,$_POST);foreach(['upstream_enable','upstream_never_direct','privacy_headers','access_log','log_anonymize'] as $f)$pconfig[$f]=isset($_POST[$f])?'on':'';$pconfig['custom_options']=webgateway_encode_list($_POST['custom_options_text']??'');if(webgateway_save_candidate($pconfig,gettext('Web Gateway cache and upstream settings changed'),$input_errors)){$savemsg=gettext('Cache, shaping and upstream settings saved and applied to Squid.');$wg_config=$pconfig=webgateway_config();}}
$pgtitle=[gettext('Services'),gettext('Web Gateway'),gettext('Cache & upstreams')];
$pglinks=['', '/webgateway/webgateway.php', '@self'];
include('head.inc');webgateway_display_tabs('cache');if($input_errors)print_input_errors($input_errors);if($savemsg)print_info_box($savemsg,'success');

$form = new Form(gettext('Save and apply'));

$section = new Form_Section(gettext('Cache'), 'wg-cache');
$section->addInput(new Form_Select('cache_profile', gettext('Profile'), $pconfig['cache_profile'], [
	'disabled' => gettext('Disabled (recommended default)'),
	'metadata' => gettext('Metadata / small objects'),
	'downloads' => gettext('Download-oriented'),
]));
$group = new Form_Group(gettext('Sizes'));
$group->add(new Form_Input('memory_cache_mb', gettext('Memory'), 'number', $pconfig['memory_cache_mb'], ['min' => 16, 'max' => 65536]))
	->setHelp(gettext('Memory (MiB)'));
$group->add(new Form_Input('cache_size_mb', gettext('Disk'), 'number', $pconfig['cache_size_mb'], ['min' => 64, 'max' => 1048576]))
	->setHelp(gettext('Disk (MiB)'));
$group->add(new Form_Input('max_object_mb', gettext('Maximum object'), 'number', $pconfig['max_object_mb'], ['min' => 1, 'max' => 10240]))
	->setHelp(gettext('Maximum object (MiB)'));
$section->add($group);
$form->add($section);

$section = new Form_Section(gettext('Bandwidth'), 'wg-bandwidth');
$section->addInput(new Form_Select('bandwidth_profile', gettext('Profile'), $pconfig['bandwidth_profile'], [
	'unlimited' => gettext('Unlimited'),
	'low_latency' => gettext('Low-latency fairness'),
	'balanced' => gettext('Balanced'),
	'bulk' => gettext('Bulk transfer'),
]))->setHelp(gettext('Profiles compile to Squid delay pools.'));
$form->add($section);

$section = new Form_Section(gettext('Privacy and logs'), 'wg-privacy');
$section->addInput(new Form_Checkbox('privacy_headers', gettext('Forwarding headers'), gettext('Remove proxy-identifying forwarding headers'), $pconfig['privacy_headers'] === 'on', 'on'));
$section->addInput(new Form_Checkbox('access_log', gettext('Access log'), gettext('Keep the policy-aware access log'), $pconfig['access_log'] === 'on', 'on'));
$section->addInput(new Form_Checkbox('log_anonymize', gettext('Reports'), gettext('Anonymize client identity in reports by default'), $pconfig['log_anonymize'] === 'on', 'on'));
$form->add($section);

$section = new Form_Section(gettext('Parent proxy'), 'wg-upstream');
$section->addInput(new Form_Checkbox('upstream_enable', gettext('Enable'), gettext('Forward through a parent proxy'), $pconfig['upstream_enable'] === 'on', 'on'));
$group = new Form_Group(gettext('Server'));
$group->add(new Form_Input('upstream_host', gettext('Host'), 'text', $pconfig['upstream_host']))
	->addClass('fs-mono')
	->setWidth(6)
	->setHelp(gettext('Host'));
$group->add(new Form_Input('upstream_port', gettext('Port'), 'number', $pconfig['upstream_port'], ['min' => 1, 'max' => 65535]))
	->addClass('fs-mono')
	->setWidth(2)
	->setHelp(gettext('Port'));
$section->add($group);
$group = new Form_Group(gettext('Credentials'));
$group->add(new Form_Input('upstream_user', gettext('Username'), 'text', $pconfig['upstream_user'], ['autocomplete' => 'off']))
	->setWidth(4)
	->setHelp(gettext('Username'));
$group->add(new Form_Input('upstream_password', gettext('Password'), 'password', $pconfig['upstream_password'], ['autocomplete' => 'new-password']))
	->setWidth(4)
	->setHelp(gettext('Password'));
$section->add($group);
$section->addInput(new Form_Checkbox('upstream_never_direct', gettext('Fallback'), gettext('Never connect directly if the parent is unavailable'), $pconfig['upstream_never_direct'] === 'on', 'on'));
$form->add($section);

$custom = webgateway_decode_list($pconfig['custom_options']);
$section = new Form_Section(gettext('Expert Squid directives'), 'wg-expert', COLLAPSIBLE | ((!empty($input_errors) || $custom !== '') ? SEC_OPEN : SEC_CLOSED));
$section->addInput(new Form_Textarea('custom_options_text', gettext('Directives'), $custom))
	->setRows(6)
	->addClass('fs-mono')
	->setHelp(gettext('Parser-tested include. FreeSense blocks directives that can replace listeners, includes, runtime identity, PID handling or terminal access policy.'));
$form->add($section);

print($form);
include('foot.inc');
