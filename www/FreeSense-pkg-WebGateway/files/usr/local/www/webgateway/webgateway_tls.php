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
	if (!$input_errors && webgateway_save_candidate($pconfig, gettext('Web Gateway TLS policy changed'), $validation_errors)) {
		$savemsg = gettext('TLS handling policy saved and applied.');
		$wg_config = $pconfig = webgateway_config();
	} else {
		$input_errors = array_merge($input_errors, $validation_errors ?? []);
	}
}
$cas = webgateway_internal_cas();
$pgtitle = [gettext('Services'), gettext('Web Gateway'), gettext('TLS Inspection')];
include('head.inc'); webgateway_display_tabs('tls');
if ($input_errors) print_input_errors($input_errors); if ($savemsg) print_info_box($savemsg, 'success');
?>
<form method="post">
<div class="alert alert-warning"><div class="d-flex gap-3"><i class="fa-solid fa-triangle-exclamation fa-2x"></i><div><strong><?=gettext('TLS inspection changes the trust boundary.')?></strong><br><?=gettext('Use it only on managed devices after reviewing applicable privacy and employment law. Certificate-pinned and mutual-TLS applications must remain spliced.')?></div></div></div>
<div class="card mb-3"><div class="card-header"><h2 class="h5 mb-0"><i class="fa-solid fa-lock me-2"></i><?=gettext('HTTPS handling mode')?></h2></div><div class="card-body"><div class="row g-3">
	<?php foreach ([
		['tunnel','shield-halved',gettext('Tunnel only'),gettext('Default. CONNECT traffic remains end-to-end encrypted; policy can use host, SNI and IP only.')],
		['selective','filter-circle-dollar',gettext('Selective inspection'),gettext('Inspect only destinations in the inspection list; splice everything else.')],
		['full','magnifying-glass-chart',gettext('Full inspection'),gettext('Inspect by default while honoring the built-in and administrator bypass lists.')],
	] as [$value,$icon,$title,$text]): ?>
	<div class="col-lg-4"><label class="card h-100 <?=($pconfig['tls_mode']===$value)?'border-primary':''?>"><div class="card-body"><div class="d-flex gap-3"><input class="form-check-input" type="radio" name="tls_mode" value="<?=$value?>" <?=($pconfig['tls_mode']===$value)?'checked':''?>><i class="fa-solid fa-<?=$icon?> fa-2x text-primary"></i><div><strong><?=$title?></strong><p class="text-muted small mb-0 mt-1"><?=$text?></p></div></div></div></label></div>
	<?php endforeach; ?>
</div></div></div>
<div class="row g-3 mb-3"><div class="col-lg-5"><div class="card h-100"><div class="card-header"><h2 class="h5 mb-0"><i class="fa-solid fa-certificate me-2"></i><?=gettext('Inspection certificate authority')?></h2></div><div class="card-body">
	<label class="form-label" for="caref"><?=gettext('Signing CA')?></label><select class="form-select mb-3" id="caref" name="caref"><option value=""><?=gettext('None—tunnel only')?></option><?php foreach ($cas as $ref=>$name): ?><option value="<?=htmlspecialchars($ref)?>" <?=$pconfig['caref']===$ref?'selected':''?>><?=htmlspecialchars($name)?></option><?php endforeach; ?></select>
	<?php if (!$cas): ?><div class="alert alert-info"><?=gettext('No internal CA with a private key exists. Create a dedicated Web Gateway CA in Certificate Manager before enabling inspection.')?></div><?php endif; ?>
	<div class="d-flex flex-wrap gap-2"><a class="btn btn-outline-primary" href="/system_camanager.php"><i class="fa-solid fa-plus icon-embed-btn"></i><?=gettext('Certificate Manager')?></a><?php if ($pconfig['caref']): ?><a class="btn btn-outline-info" href="/system_camanager.php?act=export_cert&id=<?=urlencode($pconfig['caref'])?>"><i class="fa-solid fa-download icon-embed-btn"></i><?=gettext('Export CA')?></a><?php endif; ?></div>
	<div class="form-check mt-4"><input class="form-check-input" type="checkbox" id="tls_ack" name="tls_ack" <?=$pconfig['tls_ack']==='on'?'checked':''?>><label class="form-check-label" for="tls_ack"><?=gettext('I understand the legal, privacy, client-trust and application-compatibility impact of decrypting TLS traffic.')?></label></div>
</div></div></div><div class="col-lg-7"><div class="card h-100"><div class="card-header"><h2 class="h5 mb-0"><i class="fa-solid fa-code-branch me-2"></i><?=gettext('Bump and splice policy')?></h2></div><div class="card-body"><div class="row g-3"><div class="col-md-6"><label class="form-label"><?=gettext('Inspect in selective mode')?></label><textarea class="form-control font-monospace" name="inspect_domains_text" rows="10" placeholder=".example.com"><?=htmlspecialchars(webgateway_decode_list($pconfig['inspect_domains']))?></textarea><div class="form-text"><?=gettext('One destination domain per line.')?></div></div><div class="col-md-6"><label class="form-label"><?=gettext('Always splice / never inspect')?></label><textarea class="form-control font-monospace" name="splice_domains_text" rows="10" placeholder=".bank.example"><?=htmlspecialchars(webgateway_decode_list($pconfig['splice_domains']))?></textarea><div class="form-text"><?=gettext('Added to the built-in pinned, update, authentication and PKI bypass set.')?></div></div></div></div></div></div></div>
<div class="alert alert-info"><i class="fa-solid fa-eye-slash me-2"></i><?=gettext('ECH or unknown-SNI traffic is spliced by default. Transparent HTTPS inspection can optionally block QUIC under Listeners so clients retry over TCP.')?></div>
<button class="btn btn-primary" type="submit"><i class="fa-solid fa-floppy-disk icon-embed-btn"></i><?=gettext('Save TLS policy')?></button>
</form>
<?php include('foot.inc'); ?>
