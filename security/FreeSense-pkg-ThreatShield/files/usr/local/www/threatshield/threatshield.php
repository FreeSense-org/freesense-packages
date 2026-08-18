<?php
/*
 * threatshield.php
 * FreeSense Threat Shield - General Settings & Upstream DNS
 */

##|+PRIV
##|*IDENT=page-services-threatshield
##|*NAME=Services: Threat Shield
##|*DESCR=Configure FreeSense Threat Shield DNS and Threat Protection
##|*MATCH=threatshield/threatshield.php*
##|-PRIV

require_once('guiconfig.inc');
require_once('/usr/local/pkg/threatshield.inc');

$input_errors = [];
$savemsg = null;
$ts_config = threatshield_config();

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['save'])) {
	$pconfig = $_POST;

	$ts_config['enable'] = isset($pconfig['enable']) ? 'on' : 'off';
	$ts_config['listen_port'] = (int)($pconfig['listen_port'] ?? 53);
	$ts_config['dns_coordination_mode'] = in_array($pconfig['dns_coordination_mode'] ?? '', ['primary', 'proxy', 'standalone'], true) ? $pconfig['dns_coordination_mode'] : 'primary';
	$ts_config['upstream_mode'] = in_array($pconfig['upstream_mode'] ?? '', ['parallel', 'fastest_addr', 'load_balance'], true) ? $pconfig['upstream_mode'] : 'parallel';
	$ts_config['enable_dnssec'] = isset($pconfig['enable_dnssec']) ? 'on' : 'off';
	$ts_config['enable_safesearch'] = isset($pconfig['enable_safesearch']) ? 'on' : 'off';
	$ts_config['enable_parental'] = isset($pconfig['enable_parental']) ? 'on' : 'off';
	$ts_config['catch_rogue_dns'] = isset($pconfig['catch_rogue_dns']) ? 'on' : 'off';
	$ts_config['upstreams'] = trim($pconfig['upstreams'] ?? '');
	$ts_config['bootstrap_dns'] = trim($pconfig['bootstrap_dns'] ?? '');
	$ts_config['fallback_dns'] = trim($pconfig['fallback_dns'] ?? '');
	$ts_config['ratelimit'] = (int)($pconfig['ratelimit'] ?? 0);
	$ts_config['querylog_retention'] = (int)($pconfig['querylog_retention'] ?? 90);

	if ($ts_config['listen_port'] < 1 || $ts_config['listen_port'] > 65535) {
		$input_errors[] = gettext('A valid DNS listening port (1-65535) must be specified.');
	}

	if (empty($input_errors)) {
		config_set_path(THREATSHIELD_CONFIG_PATH, threatshield_config_for_storage($ts_config));
		write_config(gettext('Updated FreeSense Threat Shield settings.'));
		threatshield_sync_config();
		$savemsg = gettext('Threat Shield settings saved and applied successfully.');
	}
}

$pgtitle = [gettext('Services'), gettext('Threat Shield'), gettext('General Settings')];
$pglinks = ['', '@self', '@self'];

include('head.inc');

if ($input_errors) {
	print_input_errors($input_errors);
}
if ($savemsg) {
	print_info_box($savemsg, 'success');
}

threatshield_display_tabs('general');
?>

<div class="d-flex flex-wrap justify-content-between align-items-center gap-3 mb-3">
	<div>
		<h2 class="h3 mb-1"><i class="fa-solid fa-shield-halved text-primary me-2"></i><?=gettext('General Settings & DNS Engine')?></h2>
		<p class="text-muted mb-0"><?=gettext('Configure listening parameters, DNS port migration, and upstream encrypted servers.')?></p>
	</div>
	<div class="d-flex gap-2">
		<a class="btn btn-outline-primary" href="/threatshield/threatshield_status.php"><i class="fa-solid fa-chart-pie me-2"></i><?=gettext('Live Dashboard')?></a>
		<a class="btn btn-outline-secondary" href="/threatshield/threatshield_querylog.php"><i class="fa-solid fa-list-check me-2"></i><?=gettext('Query Inspector')?></a>
	</div>
</div>

<form method="post" action="threatshield.php">
	<div class="card mb-3 shadow-sm">
		<div class="card-header bg-light">
			<h2 class="h5 mb-0"><i class="fa-solid fa-power-off text-primary me-2"></i><?=gettext('Core Engine Configuration')?></h2>
		</div>
		<div class="card-body">
			<div class="form-check form-switch mb-3">
				<input class="form-check-input" type="checkbox" name="enable" id="enable" <?=$ts_config['enable'] === 'on' ? 'checked' : ''?>>
				<label class="form-check-label fw-semibold" for="enable">
					<?=gettext('Enable FreeSense Threat Shield')?>
				</label>
				<div class="form-text"><?=gettext('Activates DNS filtering, encrypted upstream DNS, and threat protection.')?></div>
			</div>

			<div class="mb-3">
				<label for="dns_coordination_mode" class="form-label fw-semibold"><?=gettext('DNS Port Coordination Mode')?></label>
				<select class="form-select" name="dns_coordination_mode" id="dns_coordination_mode">
					<option value="primary" <?=$ts_config['dns_coordination_mode'] === 'primary' ? 'selected' : ''?>>
						<?=gettext('Primary DNS (Recommended): Threat Shield on Port 53, Unbound shifted to 127.0.0.1:5353 for local DHCP PTR')?>
					</option>
					<option value="proxy" <?=$ts_config['dns_coordination_mode'] === 'proxy' ? 'selected' : ''?>>
						<?=gettext('Proxy Mode: Unbound remains on Port 53, forwards to Threat Shield on 127.0.0.1:5354')?>
					</option>
					<option value="standalone" <?=$ts_config['dns_coordination_mode'] === 'standalone' ? 'selected' : ''?>>
						<?=gettext('Standalone Mode: Threat Shield manages all resolution on Port 53 (Unbound disabled)')?>
					</option>
				</select>
			</div>

			<div class="row g-3">
				<div class="col-md-6">
					<label for="listen_port" class="form-label fw-semibold"><?=gettext('DNS Listening Port')?></label>
					<input type="number" class="form-control" name="listen_port" id="listen_port" value="<?=htmlspecialchars((string)$ts_config['listen_port'])?>">
					<div class="form-text"><?=gettext('Default is port 53 for standard network DNS.')?></div>
				</div>
				<div class="col-md-6">
					<label for="upstream_mode" class="form-label fw-semibold"><?=gettext('Upstream Query Mode')?></label>
					<select class="form-select" name="upstream_mode" id="upstream_mode">
						<option value="parallel" <?=$ts_config['upstream_mode'] === 'parallel' ? 'selected' : ''?>><?=gettext('Parallel Queries (Query all upstreams simultaneously, use fastest)')?></option>
						<option value="fastest_addr" <?=$ts_config['upstream_mode'] === 'fastest_addr' ? 'selected' : ''?>><?=gettext('Fastest IP (Benchmark and use fastest responding IP)')?></option>
						<option value="load_balance" <?=$ts_config['upstream_mode'] === 'load_balance' ? 'selected' : ''?>><?=gettext('Load Balancing (Round-robin across upstreams)')?></option>
					</select>
					<div class="form-text"><?=gettext('Parallel mode provides the lowest latency and maximum redundancy.')?></div>
				</div>
			</div>
		</div>
	</div>

	<div class="card mb-3 shadow-sm">
		<div class="card-header bg-light">
			<h2 class="h5 mb-0"><i class="fa-solid fa-lock text-primary me-2"></i><?=gettext('Encrypted Upstream DNS Servers')?></h2>
		</div>
		<div class="card-body">
			<div class="mb-3">
				<label for="upstreams" class="form-label fw-semibold"><?=gettext('Upstream Resolvers (DoH, DoT, DoQ, or Plain UDP/TCP)')?></label>
				<textarea class="form-control font-monospace" name="upstreams" id="upstreams" rows="4"><?=htmlspecialchars((string)$ts_config['upstreams'])?></textarea>
				<div class="form-text"><?=gettext('Enter one upstream DNS server per line. Supports DNS-over-HTTPS (https://...), DNS-over-TLS (tls://...), DNS-over-QUIC (quic://...), and standard IP addresses.')?></div>
			</div>

			<div class="row g-3">
				<div class="col-md-6">
					<label for="bootstrap_dns" class="form-label fw-semibold"><?=gettext('Bootstrap DNS Servers')?></label>
					<textarea class="form-control font-monospace" name="bootstrap_dns" id="bootstrap_dns" rows="2"><?=htmlspecialchars((string)$ts_config['bootstrap_dns'])?></textarea>
					<div class="form-text"><?=gettext('IP addresses used to resolve encrypted DoH/DoT hostnames.')?></div>
				</div>
				<div class="col-md-6">
					<label for="fallback_dns" class="form-label fw-semibold"><?=gettext('Fallback DNS Servers')?></label>
					<textarea class="form-control font-monospace" name="fallback_dns" id="fallback_dns" rows="2"><?=htmlspecialchars((string)$ts_config['fallback_dns'])?></textarea>
					<div class="form-text"><?=gettext('Used if all configured primary upstreams fail to respond.')?></div>
				</div>
			</div>
		</div>
	</div>

	<div class="card mb-3 shadow-sm">
		<div class="card-header bg-light">
			<h2 class="h5 mb-0"><i class="fa-solid fa-shield-virus text-primary me-2"></i><?=gettext('Security & Protection Features')?></h2>
		</div>
		<div class="card-body">
			<div class="form-check form-switch mb-3">
				<input class="form-check-input" type="checkbox" name="enable_dnssec" id="enable_dnssec" <?=$ts_config['enable_dnssec'] === 'on' ? 'checked' : ''?>>
				<label class="form-check-label fw-semibold" for="enable_dnssec"><?=gettext('Enable DNSSEC Validation')?></label>
				<div class="form-text"><?=gettext('Cryptographically verifies DNS query responses to prevent DNS spoofing and cache poisoning.')?></div>
			</div>

			<div class="form-check form-switch mb-3">
				<input class="form-check-input" type="checkbox" name="enable_safesearch" id="enable_safesearch" <?=$ts_config['enable_safesearch'] === 'on' ? 'checked' : ''?>>
				<label class="form-check-label fw-semibold" for="enable_safesearch"><?=gettext('Enforce SafeSearch')?></label>
				<div class="form-text"><?=gettext('Forces strict safe search on Google, Bing, DuckDuckGo, and YouTube.')?></div>
			</div>

			<div class="form-check form-switch mb-3">
				<input class="form-check-input" type="checkbox" name="enable_parental" id="enable_parental" <?=$ts_config['enable_parental'] === 'on' ? 'checked' : ''?>>
				<label class="form-check-label fw-semibold" for="enable_parental"><?=gettext('Parental Control')?></label>
				<div class="form-text"><?=gettext('Blocks domains hosting adult content and explicit material.')?></div>
			</div>

			<div class="form-check form-switch mb-2">
				<input class="form-check-input" type="checkbox" name="catch_rogue_dns" id="catch_rogue_dns" <?=$ts_config['catch_rogue_dns'] === 'on' ? 'checked' : ''?>>
				<label class="form-check-label fw-semibold" for="catch_rogue_dns"><?=gettext('Transparent Rogue DNS Redirection (PF NAT Intercept)')?></label>
				<div class="form-text"><?=gettext('Intercepts and redirects hardcoded DNS requests (e.g., smart TVs querying 8.8.8.8) into Threat Shield.')?></div>
			</div>
		</div>
	</div>

	<div class="d-flex gap-2 mb-4">
		<button type="submit" name="save" class="btn btn-primary"><i class="fa-solid fa-floppy-disk me-2"></i><?=gettext('Save & Apply')?></button>
		<a href="threatshield.php" class="btn btn-outline-secondary"><?=gettext('Cancel')?></a>
	</div>
</form>

<?php include('foot.inc'); ?>
