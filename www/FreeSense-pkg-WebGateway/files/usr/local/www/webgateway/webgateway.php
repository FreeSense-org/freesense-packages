<?php
/* FreeSense Web Gateway 2.0: overview. */
require_once('guiconfig.inc');
require_once('webgateway.inc');

$wg_config = webgateway_config();
$running = webgateway_is_running();
$version = '';
$version_ok = webgateway_squid_version($version);
$feed_status = [];
if (is_readable(WEBGATEWAY_STATE_DIR . '/feeds/status.json')) {
	$feed_status = json_decode(file_get_contents(WEBGATEWAY_STATE_DIR . '/feeds/status.json'), true) ?: [];
}
$pgtitle = [gettext('Services'), gettext('Web Gateway')];
include('head.inc');
webgateway_display_tabs('overview');
?>
<div class="d-flex flex-wrap justify-content-between align-items-center gap-3 mb-3">
	<div>
		<h2 class="h3 mb-1"><?=gettext('Secure Web Gateway')?></h2>
		<p class="text-muted mb-0"><?=gettext('Outbound web policy, TLS inspection, identity, threat scanning and caching—managed as one transactional service.')?></p>
	</div>
	<div class="d-flex gap-2">
		<a class="btn btn-primary" href="/webgateway/webgateway_listeners.php"><i class="fa-solid fa-sliders icon-embed-btn"></i><?=gettext('Configure gateway')?></a>
		<a class="btn btn-outline-info" href="/webgateway/webgateway_diagnostics.php"><i class="fa-solid fa-stethoscope icon-embed-btn"></i><?=gettext('Run diagnostics')?></a>
	</div>
</div>

<div class="row g-3 mb-3">
	<?php
	$cards = [
		[gettext('Service'), $running ? gettext('Running') : gettext('Stopped'), $running ? 'success' : 'danger', $running ? 'circle-check' : 'circle-stop'],
		[gettext('HTTPS'), ['tunnel' => gettext('Tunnel only'), 'selective' => gettext('Selective inspection'), 'full' => gettext('Full inspection')][$wg_config['tls_mode']], $wg_config['tls_mode'] === 'tunnel' ? 'info' : 'warning', 'lock'],
		[gettext('Identity'), $wg_config['auth_mode'] === 'none' ? gettext('Source network') : strtoupper($wg_config['auth_mode']), 'primary', 'user-shield'],
		[gettext('Threat feeds'), !empty($feed_status) ? sprintf(gettext('%d active entries'), $feed_status['entries'] ?? 0) : gettext('Not compiled'), !empty($feed_status) ? 'success' : 'secondary', 'shield-virus'],
	];
	foreach ($cards as [$label, $value, $color, $icon]): ?>
	<div class="col-sm-6 col-xl-3"><div class="card h-100"><div class="card-body">
		<div class="text-uppercase text-muted small fw-semibold mb-2"><?=htmlspecialchars($label)?></div>
		<div class="fs-5 text-<?=$color?>"><i class="fa-solid fa-<?=$icon?> me-2"></i><?=htmlspecialchars($value)?></div>
	</div></div></div>
	<?php endforeach; ?>
</div>

<?php if (!$version_ok): ?>
<div class="alert alert-danger"><i class="fa-solid fa-triangle-exclamation me-2"></i><?=sprintf(gettext('Web Gateway 2.0 requires Squid 7.x. Detected: %s'), htmlspecialchars($version ?: gettext('not installed'))) ?></div>
<?php elseif ($wg_config['tls_mode'] === 'tunnel'): ?>
<div class="alert alert-info"><i class="fa-solid fa-shield-halved me-2"></i><strong><?=gettext('Private by default.')?></strong> <?=gettext('HTTPS is tunneled end-to-end. Enable selective or full inspection only after deploying a trusted inspection CA to managed clients.')?></div>
<?php else: ?>
<div class="alert alert-warning"><i class="fa-solid fa-certificate me-2"></i><strong><?=gettext('TLS inspection is active.')?></strong> <?=gettext('Review bypass destinations, CA expiry, privacy requirements and application compatibility regularly.')?></div>
<?php endif; ?>

<div class="row g-3">
	<div class="col-lg-8"><div class="card h-100">
		<div class="card-header"><h2 class="h5 mb-0"><i class="fa-solid fa-layer-group me-2"></i><?=gettext('Protection layers')?></h2></div>
		<div class="card-body"><div class="row g-3">
			<?php foreach ([
				['network-wired', gettext('Listeners'), gettext('Explicit and transparent IPv4/IPv6 listeners with automatic PF safety controls.'), '/webgateway/webgateway_listeners.php'],
				['list-check', gettext('Native policy'), gettext('Domain, URL, regex, user and schedule-aware rules compiled directly into Squid ACLs.'), '/webgateway/webgateway_policies.php'],
				['fingerprint', gettext('Identity'), gettext('Local users, LDAP/AD, RADIUS and Kerberos/Negotiate for explicit proxy clients.'), '/webgateway/webgateway_identity.php'],
				['shield-virus', gettext('Threat protection'), gettext('External ICAP or optional local ClamAV/c-icap scanning with explicit failure policy.'), '/webgateway/webgateway_threat.php'],
			] as [$icon, $title, $text, $url]): ?>
			<div class="col-md-6"><a class="card h-100 text-decoration-none" href="<?=$url?>"><div class="card-body">
				<div class="d-flex gap-3"><i class="fa-solid fa-<?=$icon?> fa-2x text-primary"></i><div><h3 class="h6 mb-1"><?=$title?></h3><p class="text-muted mb-0"><?=$text?></p></div></div>
			</div></a></div>
			<?php endforeach; ?>
		</div></div>
	</div></div>
	<div class="col-lg-4"><div class="card h-100">
		<div class="card-header"><h2 class="h5 mb-0"><i class="fa-solid fa-route me-2"></i><?=gettext('Reverse proxy')?></h2></div>
		<div class="card-body d-flex flex-column"><p><?=gettext('Web Gateway protects outbound client traffic. Publish inbound applications with HAProxy, which has purpose-built TLS termination, load balancing and health checks.')?></p><div class="mt-auto"><a class="btn btn-outline-primary" href="/haproxy/haproxy_listeners.php"><i class="fa-solid fa-arrow-up-right-from-square icon-embed-btn"></i><?=gettext('Open HAProxy')?></a></div></div>
	</div></div>
</div>
<?php include('foot.inc'); ?>
