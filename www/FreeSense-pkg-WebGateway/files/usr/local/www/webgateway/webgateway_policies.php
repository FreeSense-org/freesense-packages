<?php
/* FreeSense Web Gateway 2.0: native policy compiler. */
require_once('guiconfig.inc'); require_once('webgateway.inc');
$wg_config = webgateway_config(); $pconfig = $wg_config; $input_errors=[]; $savemsg=null; $simulation=null; $sim_host='';
if ($_POST && isset($_POST['simulate'])) {
	$host = strtolower(trim((string)($_POST['sim_host'] ?? '')));
	$sim_host = $host;
	if (!is_hostname($host)) $input_errors[] = gettext('Enter a valid hostname to simulate.');
	else {
		$match = function($domain, $rule) { $rule=ltrim($rule,'.'); return $domain===$rule || str_ends_with($domain,'.'.$rule); };
		$action = $wg_config['policy_mode']==='allowlist' ? 'block' : 'allow'; $rule=gettext('Default policy');
		foreach (webgateway_lines($wg_config['blocked_domains']) as $domain) if ($match($host,$domain)) { $action='block'; $rule=$domain; break; }
		foreach (webgateway_feed_domains() as $domain) if ($match($host,$domain)) { $action='block'; $rule=gettext('Threat feed').': '.$domain; break; }
		foreach (webgateway_lines($wg_config['allowed_domains']) as $domain) if ($match($host,$domain)) { $action='allow'; $rule=$domain; break; }
		$tls = $wg_config['tls_mode']==='full'?'inspect':($wg_config['tls_mode']==='selective'?'splice':'tunnel');
		foreach (webgateway_lines($wg_config['inspect_domains']) as $domain) if ($match($host,$domain)) $tls='inspect';
		foreach (webgateway_lines($wg_config['splice_domains']) as $domain) if ($match($host,$domain)) $tls='splice';
		$simulation=['action'=>$action,'rule'=>$rule,'tls'=>$tls];
	}
} elseif ($_POST) {
	$pconfig=array_merge($wg_config,$_POST);
	$pconfig['youtube_restrict']=isset($_POST['youtube_restrict'])?'on':'';
	foreach (['allowed_domains','blocked_domains'] as $field) {
		$normalized=webgateway_normalize_domains($_POST[$field.'_text']??'', $input_errors); $pconfig[$field]=webgateway_encode_list($normalized);
	}
	$pconfig['blocked_regex']=webgateway_encode_list($_POST['blocked_regex_text']??'');
	$pconfig['blocked_user_agents']=webgateway_encode_list($_POST['blocked_user_agents_text']??'');
	$pconfig['blocked_mime_types']=webgateway_encode_list($_POST['blocked_mime_types_text']??'');
	$pconfig['schedules']=webgateway_encode_list($_POST['schedules_text']??'');
	$validation_errors=[];
	if (!$input_errors && webgateway_save_candidate($pconfig,gettext('Web Gateway native policy changed'),$validation_errors)) { $savemsg=gettext('Policy compiled, validated and applied to Squid.'); $wg_config=$pconfig=webgateway_config(); }
	else $input_errors=array_merge($input_errors,$validation_errors);
}

$pgtitle=[gettext('Services'),gettext('Web Gateway'),gettext('Policies')];
$pglinks=['', '/webgateway/webgateway.php', '@self'];
fs_page_action(gettext('Simulate a decision'), '#', 'fa-flask', 'secondary', ['data-fs-modal' => '#wg-simulate']);
include('head.inc'); webgateway_display_tabs('policies');
if($input_errors)print_input_errors($input_errors); if($savemsg)print_info_box($savemsg,'success');

if ($simulation) {
	$tls_labels = ['inspect' => gettext('Inspected'), 'splice' => gettext('Spliced (not inspected)'), 'tunnel' => gettext('Tunneled (not inspected)')];
	fs_summary_card([
		'icon' => 'fa-flask',
		'title' => $sim_host,
		'subtitle' => gettext('Simulated decision for the saved policy'),
		'label' => gettext('Simulation result'),
		'badges' => [($simulation['action'] === 'allow') ? fs_badge('pass', gettext('Allowed')) : fs_badge('block', gettext('Blocked'))],
		'facts' => [
			[gettext('Matched rule'), $simulation['rule'], 'mono' => ($simulation['rule'] !== gettext('Default policy'))],
			[gettext('Default policy'), ($wg_config['policy_mode'] === 'allowlist') ? gettext('Restricted allowlist') : gettext('Standard access')],
			[gettext('HTTPS'), $tls_labels[$simulation['tls']] ?? $simulation['tls']],
		],
	]);
}

$form = new Form(gettext('Save and apply'));

$section = new Form_Section(gettext('Default access policy'), 'wg-policy-mode');
$section->addInput(new Form_StaticText(gettext('Policy'), webgateway_choice_cards('policy_mode', 'radio', [
	'standard' => ['icon' => 'fa-globe', 'title' => gettext('Standard access'), 'help' => gettext('Allow traffic unless a policy or feed blocks it.')],
	'allowlist' => ['icon' => 'fa-lock', 'title' => gettext('Restricted allowlist'), 'help' => gettext('Deny traffic unless the destination is explicitly allowed.')],
], $pconfig['policy_mode'], gettext('Default access policy'))));
$form->add($section);

$section = new Form_Section(gettext('Destinations'), 'wg-policy-destinations');
$section->addInput(new Form_Textarea('allowed_domains_text', gettext('Always allowed'), webgateway_decode_list($pconfig['allowed_domains'])))
	->setRows(8)
	->addClass('fs-mono')
	->setAttribute('placeholder', '.trusted.example.org')
	->setHelp(gettext('One domain per line. A leading dot includes subdomains. Allow rules take precedence.'));
$section->addInput(new Form_Textarea('blocked_domains_text', gettext('Blocked'), webgateway_decode_list($pconfig['blocked_domains'])))
	->setRows(8)
	->addClass('fs-mono')
	->setAttribute('placeholder', '.tracking.example')
	->setHelp(gettext('Enforced for HTTP and CONNECT/SNI without decrypting TLS. Active threat feeds are merged automatically.'));
$form->add($section);

$section = new Form_Section(gettext('URL and content rules'), 'wg-policy-content');
$section->addInput(new Form_Textarea('blocked_regex_text', gettext('Blocked URL expressions'), webgateway_decode_list($pconfig['blocked_regex'])))
	->setRows(4)
	->addClass('fs-mono')
	->setAttribute('placeholder', '\.(exe|scr)(\?|$)')
	->setHelp(gettext('Regular expressions matched against the full URL, one per line.'));
$section->addInput(new Form_Textarea('blocked_user_agents_text', gettext('Blocked user agents'), webgateway_decode_list($pconfig['blocked_user_agents'])))
	->setRows(3)
	->addClass('fs-mono')
	->setHelp(gettext('Regular expressions matched against the User-Agent header.'));
$section->addInput(new Form_Textarea('blocked_mime_types_text', gettext('Blocked response types'), webgateway_decode_list($pconfig['blocked_mime_types'])))
	->setRows(3)
	->addClass('fs-mono')
	->setAttribute('placeholder', 'application/x-msdownload')
	->setHelp(gettext('Regular expressions matched against the response MIME type.'));
$group = new Form_Group(gettext('Transfer limits'));
$group->add(new Form_Input('max_upload_mb', gettext('Maximum upload'), 'number', $pconfig['max_upload_mb'], ['min' => 0, 'max' => 102400]))
	->setHelp(gettext('Maximum upload (MiB, 0 unlimited)'));
$group->add(new Form_Input('max_download_mb', gettext('Maximum download'), 'number', $pconfig['max_download_mb'], ['min' => 0, 'max' => 102400]))
	->setHelp(gettext('Maximum download (MiB, 0 unlimited)'));
$group->setHelp(gettext('Full URL, MIME, upload/download and response-scanning rules see HTTPS content only when that destination is inspected.'));
$section->add($group);
$form->add($section);

$section = new Form_Section(gettext('Media and schedules'), 'wg-policy-media');
$section->addInput(new Form_Checkbox('youtube_restrict', gettext('YouTube'), gettext('Enable YouTube Restricted Mode policy'), $pconfig['youtube_restrict'] === 'on', 'on'))
	->setHelp(gettext('The restriction header applies to plaintext HTTP and to HTTPS destinations that are inspected.'));
$section->addInput(new Form_Textarea('schedules_text', gettext('Blocked schedules'), webgateway_decode_list($pconfig['schedules'])))
	->setRows(4)
	->addClass('fs-mono')
	->setAttribute('placeholder', 'weekend|SA|00:00-23:59')
	->setHelp(gettext('Format: name|days|HH:MM-HH:MM, one per line. Matching traffic is blocked before the default access policy.'));
$form->add($section);

print($form);

fs_modal_form_begin('wg-simulate', gettext('Simulate a decision'), '', [], ($input_errors && isset($_POST['simulate'])) ? ['sim_host' => $sim_host] : null);
?>
	<div class="mb-3">
		<label class="form-label" for="sim_host"><?=gettext('Destination hostname')?></label>
		<input class="form-control fs-mono" id="sim_host" name="sim_host" placeholder="www.example.com" autocomplete="off" required>
		<div class="form-text"><?=gettext('Evaluates the saved allow, block, feed and TLS lists. Nothing is sent to the destination.')?></div>
	</div>
<?php
fs_modal_form_end(gettext('Simulate'), 'simulate', '1', 'fa-flask');
include('foot.inc');
