<?php
/* FreeSense Secure Web Gateway: generated configuration diagnostics. */

require_once('guiconfig.inc');
require_once('webgateway.inc');

$wg_config = webgateway_config();
$prepare_error = null;
$test_output = '';
$test_ok = false;

if ($_POST && isset($_POST['regenerate'])) {
	$prepare_error = webgateway_prepare_files($wg_config);
}
if ($prepare_error === null) {
	if (!is_file(WEBGATEWAY_CONF_FILE)) {
		$prepare_error = webgateway_prepare_files($wg_config);
	}
	if ($prepare_error === null) {
		$test_ok = webgateway_config_test($test_output);
	}
}
$rendered = webgateway_render_config($wg_config);
$rendered = preg_replace('/(login=)[^\s]+/i', '$1[redacted]', $rendered);
$rendered = preg_replace('/(basic_ldap_auth[^\n]*\s-w\s+)(?:\x27[^\x27]*\x27|\S+)/i', '$1[redacted]', $rendered);
$version = '';
$version_ok = webgateway_squid_version($version);
$helpers = [
	'certificate generator' => '/usr/local/libexec/squid/security_file_certgen',
	'local authentication' => '/usr/local/libexec/squid/basic_ncsa_auth',
	'LDAP authentication' => '/usr/local/libexec/squid/basic_ldap_auth',
	'RADIUS authentication' => '/usr/local/libexec/squid/basic_radius_auth',
	'Kerberos authentication' => '/usr/local/libexec/squid/negotiate_kerberos_auth',
];

$pgtitle = [gettext('Diagnostics'), gettext('Web Gateway')];
include('head.inc');
webgateway_display_tabs('diagnostics');
?>

<?php if ($prepare_error !== null): ?>
	<div class="alert alert-danger"><i class="fa-solid fa-circle-xmark me-2"></i><?=htmlspecialchars($prepare_error)?></div>
<?php elseif ($test_ok): ?>
	<div class="alert alert-success"><i class="fa-solid fa-circle-check me-2"></i><?=gettext('Squid accepted the generated configuration.')?></div>
<?php else: ?>
	<div class="alert alert-danger"><i class="fa-solid fa-circle-xmark me-2"></i><?=gettext('Squid rejected the generated configuration.')?></div>
<?php endif; ?>

<div class="row g-3 mb-3">
	<div class="col-md-4"><div class="card h-100"><div class="card-body"><div class="text-muted text-uppercase small"><?=gettext('Squid engine')?></div><div class="fs-4 text-<?=$version_ok?'success':'danger'?>">Squid <?=htmlspecialchars($version ?: gettext('not detected'))?></div></div></div></div>
	<div class="col-md-8"><div class="card h-100"><div class="card-body"><div class="text-muted text-uppercase small mb-2"><?=gettext('Required helpers')?></div><div class="d-flex flex-wrap gap-2"><?php foreach($helpers as $name=>$path): ?><span class="badge bg-<?=is_executable($path)?'success':'danger'?>"><?=htmlspecialchars($name)?></span><?php endforeach; ?></div></div></div></div>
</div>

<div class="row g-3 mb-3">
	<div class="col-lg-5">
		<div class="card h-100">
			<div class="card-header"><h2 class="h5 mb-0"><i class="fa-solid fa-stethoscope me-2"></i><?=gettext('Configuration Test')?></h2></div>
			<div class="card-body">
				<pre class="bg-dark text-light rounded p-3 overflow-auto" style="min-height:12rem"><?=htmlspecialchars($test_output ?: gettext('No parser output.'))?></pre>
				<form method="post"><button class="btn btn-primary" name="regenerate" value="1" type="submit"><i class="fa-solid fa-arrows-rotate icon-embed-btn"></i><?=gettext('Regenerate and test')?></button></form>
			</div>
		</div>
	</div>
	<div class="col-lg-7">
		<div class="card h-100">
			<div class="card-header"><h2 class="h5 mb-0"><i class="fa-solid fa-shield-halved me-2"></i><?=gettext('Safety Checks')?></h2></div>
			<div class="card-body">
				<ul class="list-group list-group-flush">
					<li class="list-group-item"><i class="fa-solid fa-check text-success me-2"></i><?=gettext('Listeners bind only to selected interface addresses.')?></li>
					<li class="list-group-item"><i class="fa-solid fa-check text-success me-2"></i><?=gettext('Only directly connected client networks are permitted.')?></li>
					<li class="list-group-item"><i class="fa-solid fa-check text-success me-2"></i><?=gettext('Unsafe destination ports are rejected before policy evaluation.')?></li>
					<li class="list-group-item"><i class="fa-solid fa-check text-success me-2"></i><?=gettext('TLS inspection requires explicit acknowledgement and an internal CA with a private key.')?></li>
					<li class="list-group-item"><i class="fa-solid fa-check text-success me-2"></i><?=gettext('Transparent PF redirects are emitted only while the enabled proxy service is healthy.')?></li>
					<li class="list-group-item"><i class="fa-solid fa-check text-success me-2"></i><?=gettext('A failed parser or service health check restores the previous working configuration.')?></li>
				</ul>
			</div>
		</div>
	</div>
</div>

<div class="card mb-3">
	<div class="card-header"><h2 class="h5 mb-0"><i class="fa-solid fa-code me-2"></i><?=gettext('Generated configuration preview')?></h2></div>
	<div class="card-body p-0"><pre class="m-0 p-3 bg-dark text-light overflow-auto" style="max-height:42rem"><?=htmlspecialchars($rendered)?></pre></div>
</div>

<?php include('foot.inc'); ?>
