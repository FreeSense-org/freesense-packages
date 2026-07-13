<?php
/* FreeSense Web Gateway 2.0: native policy compiler. */
require_once('guiconfig.inc'); require_once('webgateway.inc');
$wg_config = webgateway_config(); $pconfig = $wg_config; $input_errors=[]; $savemsg=null; $simulation=null;
if ($_POST && isset($_POST['simulate'])) {
	$host = strtolower(trim((string)($_POST['sim_host'] ?? '')));
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
	if (!$input_errors && webgateway_save_candidate($pconfig,gettext('Web Gateway native policy changed'),$validation_errors)) { $savemsg=gettext('Policy compiled, validated and applied.'); $wg_config=$pconfig=webgateway_config(); }
	else $input_errors=array_merge($input_errors,$validation_errors??[]);
}
$pgtitle=[gettext('Services'),gettext('Web Gateway'),gettext('Policies')]; include('head.inc'); webgateway_display_tabs('policies');
if($input_errors)print_input_errors($input_errors); if($savemsg)print_info_box($savemsg,'success');
?>
<form method="post">
<div class="card mb-3"><div class="card-header"><h2 class="h5 mb-0"><i class="fa-solid fa-list-check me-2"></i><?=gettext('Default access policy')?></h2></div><div class="card-body"><div class="row g-3">
	<?php foreach ([['standard',gettext('Standard access'),gettext('Allow traffic unless a policy or feed blocks it.')],['allowlist',gettext('Restricted allowlist'),gettext('Deny traffic unless the destination is explicitly allowed.')]] as [$value,$title,$text]): ?><div class="col-lg-6"><label class="card h-100"><div class="card-body d-flex gap-3"><input class="form-check-input" type="radio" name="policy_mode" value="<?=$value?>" <?=$pconfig['policy_mode']===$value?'checked':''?>><div><strong><?=$title?></strong><div class="text-muted"><?=$text?></div></div></div></label></div><?php endforeach; ?>
</div></div></div>
<div class="row g-3 mb-3"><div class="col-lg-6"><div class="card h-100 border-success"><div class="card-header"><h2 class="h5 mb-0 text-success"><i class="fa-solid fa-circle-check me-2"></i><?=gettext('Always allowed')?></h2></div><div class="card-body"><textarea class="form-control font-monospace" name="allowed_domains_text" rows="13" placeholder="updates.example.com&#10;.trusted.example.org"><?=htmlspecialchars(webgateway_decode_list($pconfig['allowed_domains']))?></textarea><div class="form-text"><?=gettext('One domain per line. A leading dot includes subdomains. Allow rules take precedence.')?></div></div></div></div>
<div class="col-lg-6"><div class="card h-100 border-danger"><div class="card-header"><h2 class="h5 mb-0 text-danger"><i class="fa-solid fa-ban me-2"></i><?=gettext('Blocked destinations')?></h2></div><div class="card-body"><textarea class="form-control font-monospace" name="blocked_domains_text" rows="13" placeholder="example.invalid&#10;.tracking.example"><?=htmlspecialchars(webgateway_decode_list($pconfig['blocked_domains']))?></textarea><div class="form-text"><?=gettext('Enforced for HTTP and CONNECT/SNI without decrypting TLS. Active threat feeds are merged automatically.')?></div></div></div></div></div>
<div class="row g-3 mb-3"><div class="col-lg-6"><div class="card h-100"><div class="card-header"><h2 class="h5 mb-0"><?=gettext('URL and content rules')?></h2></div><div class="card-body"><label class="form-label"><?=gettext('Blocked URL regular expressions')?></label><textarea class="form-control font-monospace mb-3" name="blocked_regex_text" rows="5" placeholder="/malware/&#10;\\.(exe|scr)(\\?|$)"><?=htmlspecialchars(webgateway_decode_list($pconfig['blocked_regex']))?></textarea><div class="row g-3"><div class="col-md-6"><label class="form-label"><?=gettext('Blocked user-agent expressions')?></label><textarea class="form-control font-monospace" name="blocked_user_agents_text" rows="4"><?=htmlspecialchars(webgateway_decode_list($pconfig['blocked_user_agents']))?></textarea></div><div class="col-md-6"><label class="form-label"><?=gettext('Blocked response MIME expressions')?></label><textarea class="form-control font-monospace" name="blocked_mime_types_text" rows="4" placeholder="application/x-msdownload"><?=htmlspecialchars(webgateway_decode_list($pconfig['blocked_mime_types']))?></textarea></div><div class="col-md-6"><label class="form-label"><?=gettext('Maximum upload (MiB, 0 unlimited)')?></label><input class="form-control" type="number" min="0" max="102400" name="max_upload_mb" value="<?=htmlspecialchars($pconfig['max_upload_mb'])?>"></div><div class="col-md-6"><label class="form-label"><?=gettext('Maximum download (MiB, 0 unlimited)')?></label><input class="form-control" type="number" min="0" max="102400" name="max_download_mb" value="<?=htmlspecialchars($pconfig['max_download_mb'])?>"></div></div><div class="alert alert-warning mt-3 mb-0"><i class="fa-solid fa-lock me-2"></i><?=gettext('Full URL, MIME, upload/download and response-scanning rules see HTTPS content only when that destination is inspected.')?></div></div></div></div>
<div class="col-lg-6"><div class="card h-100"><div class="card-header"><h2 class="h5 mb-0"><?=gettext('Media and schedules')?></h2></div><div class="card-body"><div class="form-check form-switch"><input class="form-check-input" type="checkbox" name="youtube_restrict" id="youtube_restrict" <?=$pconfig['youtube_restrict']==='on'?'checked':''?>><label class="form-check-label" for="youtube_restrict"><?=gettext('Enable YouTube Restricted Mode policy')?></label></div><div class="form-text"><?=gettext('The restriction header applies to plaintext HTTP and HTTPS destinations that are actively inspected.')?></div><hr><label class="form-label"><?=gettext('Blocked schedules')?></label><textarea class="form-control font-monospace" name="schedules_text" rows="5" placeholder="after_hours|SMTWHFA|00:00-06:00&#10;weekend|SA|00:00-23:59"><?=htmlspecialchars(webgateway_decode_list($pconfig['schedules']))?></textarea><div class="form-text"><?=gettext('Format: name|days|HH:MM-HH:MM. Matching traffic is blocked before the default access policy.')?></div></div></div></div></div>
<button class="btn btn-primary" type="submit"><i class="fa-solid fa-floppy-disk icon-embed-btn"></i><?=gettext('Compile and apply policy')?></button>
</form>
<div class="card mt-3"><div class="card-header"><h2 class="h5 mb-0"><i class="fa-solid fa-flask me-2"></i><?=gettext('Policy simulator')?></h2></div><div class="card-body"><form method="post" class="row g-3 align-items-end"><div class="col-md-8"><label class="form-label" for="sim_host"><?=gettext('Destination hostname')?></label><input class="form-control" id="sim_host" name="sim_host" placeholder="www.example.com" value="<?=htmlspecialchars($_POST['sim_host']??'')?>"></div><div class="col-md-4"><button class="btn btn-outline-info w-100" type="submit" name="simulate" value="1"><?=gettext('Simulate decision')?></button></div></form><?php if($simulation): ?><div class="alert alert-<?=$simulation['action']==='allow'?'success':'danger'?> mt-3 mb-0"><strong><?=strtoupper($simulation['action'])?></strong> · <?=gettext('Rule:')?> <?=htmlspecialchars($simulation['rule'])?> · <?=gettext('TLS:')?> <?=htmlspecialchars($simulation['tls'])?></div><?php endif; ?></div></div>
<?php include('foot.inc'); ?>
