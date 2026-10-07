<?php
/* FreeSense Web Gateway 2.0: overview. */
require_once('guiconfig.inc');
require_once('webgateway.inc');

$wg_config = webgateway_config();
$running = webgateway_is_running();
$version = '';
$version_ok = webgateway_squid_version($version);
$feed_status = webgateway_feed_status();
$on = function ($field) use ($wg_config) {
	return ($wg_config[$field] ?? '') === 'on';
};
$count = function ($field) use ($wg_config) {
	return count(webgateway_lines($wg_config[$field] ?? ''));
};

$pgtitle = [gettext('Services'), gettext('Web Gateway')];
fs_page_action(gettext('Configure listeners'), '/webgateway/webgateway_listeners.php', 'fa-sliders');
fs_page_action(gettext('Status'), '/webgateway/webgateway_status.php', 'fa-chart-line', 'secondary');
fs_page_action(gettext('Diagnostics'), '/webgateway/webgateway_diagnostics.php', 'fa-stethoscope', 'secondary');
include('head.inc');
webgateway_display_tabs('overview');

if (!$version_ok) {
	print_callout(htmlspecialchars(sprintf(gettext('Web Gateway 2.0 requires Squid 7.x. Detected: %s'), $version ?: gettext('not installed'))), 'danger', gettext('Unsupported Squid version'));
} elseif ($wg_config['tls_mode'] === 'tunnel') {
	print_callout(htmlspecialchars(gettext('HTTPS is tunneled end-to-end. Enable selective or full inspection only after deploying a trusted inspection CA to managed clients.')), 'info', gettext('Private by default'));
} else {
	print_callout(htmlspecialchars(gettext('Review bypass destinations, CA expiry, privacy requirements and application compatibility regularly.')), 'warning', gettext('TLS inspection is active'));
}
?>
<div class="fs-tiles">
<?php
fs_tile(gettext('Service'), $running ? gettext('Running') : gettext('Stopped'), $running ? 'up' : ($on('enable') ? 'down' : 'disabled'),
    $on('enable') ? gettext('Enabled') : gettext('Disabled under Listeners'));
fs_tile(gettext('HTTPS'), webgateway_tls_mode_label($wg_config['tls_mode']), ($wg_config['tls_mode'] === 'tunnel') ? null : 'warn');
fs_tile(gettext('Identity'), webgateway_auth_mode_label($wg_config['auth_mode']));
fs_tile(gettext('Threat feeds'), !empty($feed_status) ? number_format($feed_status['entries'] ?? 0) : gettext('Not compiled'), null,
    !empty($feed_status) ? gettext('Active entries') : null);
?>
</div>
<?php
$chip = function ($text, $class = '') {
	return '<span class="fs-chip' . ($class !== '' ? ' ' . $class : '') . '">' . htmlspecialchars($text) . '</span>';
};
$state_on = function ($enabled) {
	return $enabled ? fs_badge('enabled') : fs_badge('disabled');
};

$modes = array_map('webgateway_listener_mode_label', (array)$wg_config['listener_modes']);
$interfaces = array_map('strtoupper', (array)$wg_config['interfaces']);
$local_av = is_executable('/usr/local/bin/c-icap') && is_executable('/usr/local/sbin/clamd') && is_file('/usr/local/lib/c_icap/squidclamav.so');

$rows = [
	[
		'fa-network-wired', gettext('Listeners'), '/webgateway/webgateway_listeners.php', $state_on($on('enable')),
		implode('', array_map(function ($m) use ($chip) { return $chip($m, 'fs-chip--strong'); }, $modes))
		    . ($interfaces ? implode('', array_map(function ($i) use ($chip) { return $chip($i, 'fs-chip--mono'); }, $interfaces)) : $chip(gettext('No interfaces'), 'is-off')),
		gettext('Explicit and transparent IPv4/IPv6 listeners with automatic PF safety controls.'),
	],
	[
		'fa-lock', gettext('TLS inspection'), '/webgateway/webgateway_tls.php',
		($wg_config['tls_mode'] === 'tunnel') ? fs_badge('info', gettext('Tunnel only')) : fs_badge('warn', webgateway_tls_mode_label($wg_config['tls_mode'])),
		$chip(($wg_config['caref'] !== '') ? gettext('CA selected') : gettext('No CA'), ($wg_config['caref'] !== '') ? 'is-on' : 'is-off')
		    . $chip(sprintf(gettext('%d inspect'), $count('inspect_domains')))
		    . $chip(sprintf(gettext('%d splice'), $count('splice_domains'))),
		gettext('Tunnel, selective or full inspection with built-in bypass lists.'),
	],
	[
		'fa-list-check', gettext('Policies'), '/webgateway/webgateway_policies.php',
		fs_badge('info', ($wg_config['policy_mode'] === 'allowlist') ? gettext('Allowlist') : gettext('Standard')),
		$chip(sprintf(gettext('%d allowed'), $count('allowed_domains')))
		    . $chip(sprintf(gettext('%d blocked'), $count('blocked_domains')))
		    . $chip(sprintf(gettext('%d URL expressions'), $count('blocked_regex')))
		    . $chip(sprintf(gettext('%d schedules'), $count('schedules')))
		    . ($on('youtube_restrict') ? $chip(gettext('YouTube restricted'), 'is-on') : ''),
		gettext('Domain, URL, regex, user-agent and schedule rules compiled directly into Squid ACLs.'),
	],
	[
		'fa-fingerprint', gettext('Identity'), '/webgateway/webgateway_identity.php',
		($wg_config['auth_mode'] === 'none') ? fs_badge('neutral', gettext('No login')) : fs_badge('enabled', gettext('Login required')),
		$chip(webgateway_auth_mode_label($wg_config['auth_mode']))
		    . (($wg_config['auth_server'] !== '' && in_array($wg_config['auth_mode'], ['ldap', 'radius'], true)) ? $chip($wg_config['auth_server'], 'fs-chip--mono') : ''),
		gettext('Local users, LDAP/AD, RADIUS and Kerberos/Negotiate for explicit proxy clients.'),
	],
	[
		'fa-shield-virus', gettext('Threat protection'), '/webgateway/webgateway_threat.php',
		$state_on($on('icap_enable') || ($local_av && $on('local_av_enable'))),
		$chip(gettext('External ICAP'), $on('icap_enable') ? 'is-on' : 'is-off')
		    . $chip(gettext('Local ClamAV'), ($local_av && $on('local_av_enable')) ? 'is-on' : 'is-off'),
		gettext('External ICAP or optional local ClamAV/c-icap scanning with explicit failure policy.'),
	],
	[
		'fa-cloud-arrow-down', gettext('Feeds'), '/webgateway/webgateway_feeds.php', $state_on($on('feeds_enable')),
		$chip(sprintf(gettext('%d sources'), $count('feed_urls')))
		    . $chip(!empty($feed_status) ? sprintf(gettext('%s entries'), number_format($feed_status['entries'] ?? 0)) : gettext('Not compiled')),
		gettext('HTTPS domain and hosts feeds, staged and activated atomically.'),
	],
	[
		'fa-database', gettext('Cache & upstreams'), '/webgateway/webgateway_cache.php',
		($wg_config['cache_profile'] === 'disabled') ? fs_badge('disabled', gettext('No cache')) : fs_badge('enabled', gettext('Caching')),
		$chip(sprintf(gettext('Bandwidth: %s'), ['unlimited' => gettext('unlimited'), 'low_latency' => gettext('low latency'), 'balanced' => gettext('balanced'), 'bulk' => gettext('bulk')][$wg_config['bandwidth_profile']] ?? $wg_config['bandwidth_profile']))
		    . $chip(gettext('Parent proxy'), $on('upstream_enable') ? 'is-on' : 'is-off')
		    . $chip(gettext('Access log'), $on('access_log') ? 'is-on' : 'is-off'),
		gettext('Cache profiles, delay-pool shaping and authenticated parent proxies.'),
	],
];
?>
<div class="panel panel-default fs-table">
<?php fs_table_toolbar(['title' => gettext('Protection layers'), 'search' => false, 'noun' => gettext('layers'), 'noun_one' => gettext('layer')]); ?>
	<div class="panel-body table-responsive">
	<table class="table table-hover">
		<thead><tr>
			<th><?=gettext('Layer')?></th>
			<th class="fs-col-status"><?=gettext('State')?></th>
			<th><?=gettext('Configuration')?></th>
			<th class="fs-col-actions"><span class="visually-hidden"><?=gettext('Actions')?></span></th>
		</tr></thead>
		<tbody>
<?php foreach ($rows as [$icon, $title, $url, $badge, $chips, $help]): ?>
			<tr>
				<td>
					<a class="wg-layer" href="<?=htmlspecialchars($url)?>"><i class="fa-solid <?=htmlspecialchars($icon)?>" aria-hidden="true"></i><?=htmlspecialchars($title)?></a>
					<div class="fs-muted wg-layer-help"><?=htmlspecialchars($help)?></div>
				</td>
				<td><?=$badge?></td>
				<td><div class="fs-chips"><?=$chips?></div></td>
				<td><?=fs_row_actions([['edit', $url, $title]])?></td>
			</tr>
<?php endforeach; ?>
		</tbody>
	</table>
	</div>
</div>
<?php
print_callout(htmlspecialchars(gettext('Web Gateway protects outbound client traffic. Publish inbound applications with HAProxy, which has purpose-built TLS termination, load balancing and health checks.'))
    . ' <a href="/haproxy/haproxy_listeners.php">' . htmlspecialchars(gettext('Open HAProxy')) . '</a>', 'info', gettext('Reverse proxy'));
?>
<style>
.wg-layer { display: inline-flex; gap: var(--fs-sp-2); align-items: center; font-weight: 600; }
.wg-layer > i { color: var(--fs-text-muted); width: 1.25rem; text-align: center; }
.wg-layer-help { font-size: var(--fs-fs-sm); padding-left: calc(1.25rem + var(--fs-sp-2)); }
@media (max-width: 575.98px) { .wg-layer-help { display: none; } .wg-layer { white-space: nowrap; } }
</style>
<?php include('foot.inc'); ?>
