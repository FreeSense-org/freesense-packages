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
		$savemsg = gettext('Listeners and interception rules saved and applied transactionally.');
		$wg_config = $pconfig = webgateway_config();
	} else {
		$input_errors = array_merge($input_errors, $validation_errors);
	}
}
$available = webgateway_client_interfaces();
$pgtitle = [gettext('Services'), gettext('Web Gateway'), gettext('Listeners')];
include('head.inc');
webgateway_display_tabs('listeners');
if ($input_errors) print_input_errors($input_errors);
if ($savemsg) print_info_box($savemsg, 'success');
?>
<form method="post">
<div class="card mb-3"><div class="card-header"><h2 class="h5 mb-0"><i class="fa-solid fa-power-off me-2"></i><?=gettext('Gateway service')?></h2></div><div class="card-body">
	<div class="form-check form-switch"><input class="form-check-input" type="checkbox" id="enable" name="enable" <?=$pconfig['enable']==='on'?'checked':''?>><label class="form-check-label fw-semibold" for="enable"><?=gettext('Enable FreeSense Web Gateway')?></label></div>
	<div class="form-check form-switch mt-3"><input class="form-check-input" type="checkbox" id="ha_sync" name="ha_sync" <?=$pconfig['ha_sync']==='on'?'checked':''?>><label class="form-check-label" for="ha_sync"><?=gettext('Synchronize Web Gateway configuration to the HA peer')?></label><div class="form-text"><?=gettext('Compiled feeds are rebuilt locally. CA private keys follow the system certificate synchronization policy and are never copied by this package.')?></div></div>
</div></div>
<div class="card mb-3"><div class="card-header"><h2 class="h5 mb-0"><i class="fa-solid fa-network-wired me-2"></i><?=gettext('Client interfaces')?></h2></div><div class="card-body">
	<?php if (!$available): ?><div class="alert alert-warning mb-0"><?=gettext('No eligible internal interfaces were detected. WAN and gateway-facing interfaces are never offered here.')?></div>
	<?php else: ?><div class="row g-3"><?php foreach ($available as $id => $description): ?><div class="col-md-6 col-xl-4"><label class="card h-100"><div class="card-body d-flex gap-3"><input class="form-check-input" type="checkbox" name="interfaces[]" value="<?=htmlspecialchars($id)?>" <?=in_array($id,$pconfig['interfaces'],true)?'checked':''?>><div><strong><?=htmlspecialchars($description)?></strong><div class="text-muted font-monospace"><?=htmlspecialchars($id)?></div></div></div></label></div><?php endforeach; ?></div><?php endif; ?>
	<div class="mt-3"><label class="form-label" for="additional_client_networks_text"><?=gettext('Additional allowed client networks')?></label><textarea class="form-control font-monospace" id="additional_client_networks_text" name="additional_client_networks_text" rows="4" placeholder="10.0.0.0/8&#10;172.16.0.0/12&#10;192.168.0.0/16"><?=htmlspecialchars(webgateway_decode_list($pconfig['additional_client_networks']))?></textarea><div class="form-text"><?=gettext('Add routed or VPN client networks that may use the explicit proxy. Directly connected networks are derived from the selected interfaces. Firewall pass rules are still required.')?></div></div>
</div></div>
<div class="card mb-3"><div class="card-header"><h2 class="h5 mb-0"><i class="fa-solid fa-arrows-turn-to-dots me-2"></i><?=gettext('Listener modes')?></h2></div><div class="card-body">
	<div class="row g-3">
	<?php foreach ([
		['explicit', gettext('Explicit proxy'), gettext('Managed clients or PAC use the proxy directly.'), 'port', 3128],
		['intercept_http', gettext('Transparent HTTP'), gettext('PF redirects TCP/80 from selected interfaces.'), 'http_intercept_port', 3129],
		['intercept_https', gettext('Transparent HTTPS'), gettext('Requires selective or full TLS inspection and a trusted CA.'), 'https_intercept_port', 3130],
	] as [$mode,$title,$help,$port,$default]): ?>
	<div class="col-lg-4"><div class="card h-100"><div class="card-body"><div class="form-check form-switch mb-3"><input class="form-check-input" type="checkbox" name="listener_modes[]" id="<?=$mode?>" value="<?=$mode?>" <?=in_array($mode,$pconfig['listener_modes'],true)?'checked':''?>><label class="form-check-label fw-semibold" for="<?=$mode?>"><?=$title?></label></div><p class="text-muted small"><?=$help?></p><label class="form-label" for="<?=$port?>"><?=gettext('Local port')?></label><input class="form-control" type="number" min="1" max="65535" id="<?=$port?>" name="<?=$port?>" value="<?=htmlspecialchars($pconfig[$port])?>"></div></div></div>
	<?php endforeach; ?>
	</div>
</div></div>
<div class="row g-3 mb-3"><div class="col-lg-6"><div class="card h-100"><div class="card-header"><h2 class="h5 mb-0"><?=gettext('Interception safety')?></h2></div><div class="card-body">
	<label class="form-label" for="quic_policy"><?=gettext('HTTP/3 and QUIC')?></label><select class="form-select mb-3" id="quic_policy" name="quic_policy"><option value="allow" <?=$pconfig['quic_policy']==='allow'?'selected':''?>><?=gettext('Allow UDP/443 (not inspected)')?></option><option value="block" <?=$pconfig['quic_policy']==='block'?'selected':''?>><?=gettext('Block UDP/443 to force TCP fallback')?></option></select>
	<label class="form-label" for="failure_policy"><?=gettext('Proxy failure')?></label><select class="form-select" id="failure_policy" name="failure_policy"><option value="open" <?=$pconfig['failure_policy']==='open'?'selected':''?>><?=gettext('Fail open: remove redirects if proxy is unhealthy')?></option><option value="closed" <?=$pconfig['failure_policy']==='closed'?'selected':''?>><?=gettext('Fail closed: keep policy enforcement')?></option></select>
	<a class="btn btn-outline-info mt-3" href="/webgateway/webgateway_pac.php"><i class="fa-solid fa-download icon-embed-btn"></i><?=gettext('Download explicit-proxy PAC file')?></a><div class="form-text"><?=gettext('Deploy this file with device management or host it on your organization’s real WPAD endpoint. FreeSense does not expose an unauthenticated discovery service on the management GUI.')?></div>
</div></div></div><div class="col-lg-6"><div class="card h-100"><div class="card-header"><h2 class="h5 mb-0"><?=gettext('Explicit exemptions')?></h2></div><div class="card-body"><div class="row g-3"><div class="col-md-6"><label class="form-label"><?=gettext('Source addresses/networks')?></label><textarea class="form-control font-monospace" name="exempt_sources_text" rows="7"><?=htmlspecialchars(webgateway_decode_list($pconfig['exempt_sources']))?></textarea></div><div class="col-md-6"><label class="form-label"><?=gettext('Destination addresses/networks')?></label><textarea class="form-control font-monospace" name="exempt_destinations_text" rows="7"><?=htmlspecialchars(webgateway_decode_list($pconfig['exempt_destinations']))?></textarea></div></div><div class="form-text"><?=gettext('Management access, firewall-owned addresses and local control traffic are bypassed automatically; add application-specific exceptions here.')?></div></div></div></div></div>
<button class="btn btn-primary" type="submit"><i class="fa-solid fa-floppy-disk icon-embed-btn"></i><?=gettext('Save and apply listeners')?></button>
</form>
<?php include('foot.inc'); ?>
