<?php
/* FreeSense Secure Web Gateway: generated configuration diagnostics. */

require_once('guiconfig.inc');
require_once('webgateway.inc');

$wg_config = webgateway_config();
$prepare_error = null;
$test_output = '';
$test_ok = false;

/* Files are only (re)generated on an explicit POST; opening the tab never writes. */
if ($_POST && isset($_POST['regenerate'])) {
	$prepare_error = webgateway_prepare_files($wg_config);
}
$files_missing = ($prepare_error === null) && !is_file(WEBGATEWAY_CONF_FILE);
if (($prepare_error === null) && !$files_missing) {
	$test_ok = webgateway_config_test($test_output);
}
$rendered = webgateway_render_config($wg_config);
$rendered = preg_replace('/(login=)[^\s]+/i', '$1[redacted]', $rendered);
$rendered = preg_replace('/(basic_ldap_auth[^\n]*\s-w\s+)(?:\x27[^\x27]*\x27|\S+)/i', '$1[redacted]', $rendered);
$version = '';
$version_ok = webgateway_squid_version($version);
$helpers = [
	gettext('Certificate generator') => '/usr/local/libexec/squid/security_file_certgen',
	gettext('Local authentication') => '/usr/local/libexec/squid/basic_ncsa_auth',
	gettext('LDAP authentication') => '/usr/local/libexec/squid/basic_ldap_auth',
	gettext('RADIUS authentication') => '/usr/local/libexec/squid/basic_radius_auth',
	gettext('Kerberos authentication') => '/usr/local/libexec/squid/negotiate_kerberos_auth',
];
$helpers_ok = count(array_filter($helpers, 'is_executable'));

$pgtitle = [gettext('Diagnostics'), gettext('Web Gateway')];
include('head.inc');
webgateway_display_tabs('diagnostics');
?>
<div class="fs-tiles">
<?php
if ($files_missing) {
	fs_tile(gettext('Configuration test'), gettext('Not run'), 'warn', gettext('The generated configuration files are missing.'));
} elseif ($prepare_error !== null) {
	fs_tile(gettext('Configuration test'), gettext('Not run'), 'error', gettext('The configuration could not be generated.'));
} else {
	fs_tile(gettext('Configuration test'), $test_ok ? gettext('Accepted') : gettext('Rejected'), $test_ok ? 'pass' : 'error',
	    $test_ok ? gettext('Squid accepted the generated configuration.') : gettext('Squid rejected the generated configuration.'));
}
fs_tile(gettext('Squid engine'), $version ?: gettext('Not detected'), $version_ok ? 'pass' : 'error', sprintf(gettext('Version %d.x required'), WEBGATEWAY_MAJOR));
fs_tile(gettext('Required helpers'), sprintf(gettext('%1$d of %2$d'), $helpers_ok, count($helpers)), ($helpers_ok === count($helpers)) ? 'pass' : 'warn');
?>
</div>
<?php
if ($prepare_error !== null) {
	print_callout(htmlspecialchars($prepare_error), 'danger', gettext('Configuration could not be generated'));
}
if ($files_missing):
?>
<div class="panel panel-default wg-missing">
	<div class="panel-heading"><h2 class="panel-title"><?=gettext('Config files missing')?></h2></div>
	<div class="panel-body">
		<p class="wg-diag-text"><?=sprintf(gettext('The generated Squid configuration (%s) does not exist yet. Regenerate it from the saved settings to test it; the running service is not reloaded.'), '<code>' . htmlspecialchars(WEBGATEWAY_CONF_FILE) . '</code>')?></p>
		<form method="post" class="wg-missing-form">
			<button class="btn btn-primary" name="regenerate" value="1" type="submit"
				data-fs-confirm="<?=htmlspecialchars(gettext('Regenerate the Web Gateway configuration?'))?>"
				data-fs-confirm-detail="<?=htmlspecialchars(gettext('The Squid configuration files are written from the saved settings and parsed with Squid. The running service is not reloaded.'))?>"
				data-fs-confirm-action="<?=htmlspecialchars(gettext('Regenerate configuration'))?>"><i class="fa-solid fa-arrows-rotate icon-embed-btn" aria-hidden="true"></i><?=gettext('Regenerate configuration')?></button>
		</form>
	</div>
</div>
<?php endif; ?>
<div class="fs-tool">
<?php if (!$files_missing): ?>
	<form method="post" class="fs-tool-form">
		<div class="panel panel-default">
			<div class="panel-heading"><h2 class="panel-title"><?=gettext('Configuration test')?></h2></div>
			<div class="panel-body">
				<p class="fs-muted wg-diag-text"><?=gettext('Regenerates the Squid configuration from the saved settings and parses it with Squid. The running service is not reloaded.')?></p>
				<div>
					<div class="form-label"><?=gettext('Helpers')?></div>
					<div class="fs-chips">
<?php foreach ($helpers as $name => $path): $ok = is_executable($path); ?>
						<span class="fs-chip <?=$ok ? 'is-on' : 'is-warn'?>" title="<?=htmlspecialchars($path)?>"><?=htmlspecialchars($name)?><?php if (!$ok): ?> <i class="fa-solid fa-triangle-exclamation" aria-hidden="true"></i><span class="visually-hidden"><?=gettext('missing')?></span><?php endif; ?></span>
<?php endforeach; ?>
					</div>
				</div>
			</div>
			<div class="panel-footer"><button class="btn btn-primary" name="regenerate" value="1" type="submit" data-fs-busy="true"><i class="fa-solid fa-arrows-rotate icon-embed-btn" aria-hidden="true"></i><?=gettext('Regenerate and test with Squid')?></button></div>
		</div>
	</form>
<?php endif; ?>
	<div class="panel panel-default">
		<div class="panel-heading">
			<h2 class="panel-title"><?=gettext('Parser output')?></h2>
<?php if ($test_output !== ''): ?>
			<button type="button" class="btn btn-sm btn-outline-secondary" data-fs-copy="#wg-test-output"><i class="fa-regular fa-copy icon-embed-btn" aria-hidden="true"></i><?=gettext('Copy')?></button>
<?php endif; ?>
		</div>
<?php if ($test_output !== ''): ?>
		<pre class="fs-console" id="wg-test-output"><?=htmlspecialchars($test_output)?></pre>
<?php else: ?>
		<div class="fs-tool-empty"><i class="fa-solid fa-<?=$test_ok ? 'circle-check' : 'stethoscope'?>" aria-hidden="true"></i><span><?=$test_ok ? gettext('Squid reported no warnings.') : gettext('No parser output.')?></span></div>
<?php endif; ?>
	</div>
</div>

<div class="panel panel-default">
	<div class="panel-heading"><h2 class="panel-title"><?=gettext('Safety checks')?></h2></div>
	<div class="panel-body wg-pad">
		<ul class="wg-checks">
<?php foreach ([
	gettext('Listeners bind only to selected interface addresses.'),
	gettext('Client access is limited to selected interface networks plus any additional routed client networks.'),
	gettext('Unsafe destination ports are rejected before policy evaluation.'),
	gettext('TLS inspection requires explicit acknowledgement and an internal CA with a private key.'),
	gettext('Transparent PF redirects are emitted only while the enabled proxy service is healthy.'),
	gettext('A failed parser or service health check restores the previous working configuration.'),
	gettext('Save and apply actions stage configuration, parse it with Squid, then reload transactionally.'),
] as $check): ?>
			<li><i class="fa-solid fa-check" aria-hidden="true"></i><?=htmlspecialchars($check)?></li>
<?php endforeach; ?>
		</ul>
	</div>
</div>

<div class="panel panel-default">
	<div class="panel-heading">
		<h2 class="panel-title"><?=gettext('Generated configuration')?></h2>
		<button type="button" class="btn btn-sm btn-outline-secondary" data-fs-copy="#wg-config"><i class="fa-regular fa-copy icon-embed-btn" aria-hidden="true"></i><?=gettext('Copy')?></button>
	</div>
	<pre class="fs-console" id="wg-config"><?=htmlspecialchars($rendered)?></pre>
</div>
<style>
.wg-diag-text { font-size: var(--fs-fs-sm); margin: 0; }
.wg-missing .panel-body { display: grid; justify-items: start; gap: var(--fs-sp-3); padding: var(--fs-sp-3) var(--fs-sp-4); }
.wg-missing-form { margin: 0; }
.wg-pad { padding: var(--fs-sp-3) var(--fs-sp-4); }
.wg-checks { list-style: none; margin: 0; padding: 0; display: grid; gap: var(--fs-sp-2); }
.wg-checks li { display: flex; gap: var(--fs-sp-2); align-items: baseline; }
.wg-checks i { color: var(--fs-pass); }
</style>
<?php include('foot.inc'); ?>
