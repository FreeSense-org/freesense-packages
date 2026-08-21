<?php
/*
 * threatshield_clients.php
 * FreeSense Threat Shield - Client Profiles & Blocked Services
 */

##|+PRIV
##|*IDENT=page-services-threatshield
##|*NAME=Services: Threat Shield Clients
##|*DESCR=Configure per-client DNS security policies and blocked services
##|*MATCH=threatshield/threatshield_clients.php*
##|-PRIV

require_once('guiconfig.inc');
require_once('/usr/local/pkg/threatshield.inc');

$savemsg = null;
$ts_config = threatshield_config();

$services_catalog = [
	'tiktok' => ['name' => 'TikTok', 'category' => 'Social Media', 'icon' => 'video'],
	'discord' => ['name' => 'Discord', 'category' => 'Chat & Voice', 'icon' => 'comments'],
	'youtube' => ['name' => 'YouTube', 'category' => 'Video Streaming', 'icon' => 'play'],
	'facebook' => ['name' => 'Facebook & Messenger', 'category' => 'Social Media', 'icon' => 'users'],
	'instagram' => ['name' => 'Instagram', 'category' => 'Social Media', 'icon' => 'camera'],
	'roblox' => ['name' => 'Roblox', 'category' => 'Online Gaming', 'icon' => 'gamepad'],
	'steam' => ['name' => 'Steam', 'category' => 'Online Gaming', 'icon' => 'gamepad'],
	'netflix' => ['name' => 'Netflix', 'category' => 'Video Streaming', 'icon' => 'tv'],
	'twitter' => ['name' => 'X (Twitter)', 'category' => 'Social Media', 'icon' => 'hashtag'],
	'twitch' => ['name' => 'Twitch', 'category' => 'Live Streaming', 'icon' => 'tv'],
	'reddit' => ['name' => 'Reddit', 'category' => 'Social Media', 'icon' => 'comments'],
	'epic_games' => ['name' => 'Epic Games', 'category' => 'Online Gaming', 'icon' => 'gamepad'],
	'snapchat' => ['name' => 'Snapchat', 'category' => 'Social Media', 'icon' => 'camera'],
	'telegram' => ['name' => 'Telegram', 'category' => 'Chat & Voice', 'icon' => 'paper-plane']
];

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['save_services'])) {
	$ts_config['blocked_services'] = array_map('strval', (array)($_POST['blocked_services'] ?? []));
	config_set_path(THREATSHIELD_CONFIG_PATH, threatshield_config_for_storage($ts_config));
	write_config(gettext('Updated Threat Shield blocked services.'));
	threatshield_sync_config();
	$savemsg = gettext('Blocked services updated and applied.');
}

$blocked_set = array_flip($ts_config['blocked_services'] ?? []);
$dhcp_hosts = threatshield_get_dhcp_hostnames();

$pgtitle = [gettext('Services'), gettext('Threat Shield'), gettext('Client Profiles & Services')];
$pglinks = ['', '@self', '@self'];

include('head.inc');

if ($savemsg) {
	print_info_box($savemsg, 'success');
}

threatshield_display_tabs('clients');
?>

<div class="d-flex flex-wrap justify-content-between align-items-center gap-3 mb-3">
	<div>
		<h2 class="h3 mb-1"><i class="fa-solid fa-users-gear text-primary me-2"></i><?=gettext('Client Profiles & App Blocking')?></h2>
		<p class="text-muted mb-0"><?=gettext('Enforce 1-click network-wide app blocking and review discovered LAN client mappings.')?></p>
	</div>
</div>

<form method="post" action="threatshield_clients.php">
	<div class="card shadow-sm mb-4">
		<div class="card-header bg-light">
			<h2 class="h5 mb-0"><i class="fa-solid fa-ban text-danger me-2"></i><?=gettext('1-Click Application & Service Blocking (Network-Wide)')?></h2>
		</div>
		<div class="card-body">
			<div class="text-muted small mb-3">
				<?=gettext('Select applications to block across your entire network. Threat Shield blocks corresponding DNS lookups and CDN endpoints automatically.')?>
			</div>
			<div class="row row-cols-1 row-cols-sm-2 row-cols-md-3 row-cols-lg-4 g-3">
				<?php foreach ($services_catalog as $key => $info): ?>
					<div class="col">
						<div class="card h-100 border p-3">
							<div class="form-check form-switch">
								<input class="form-check-input" type="checkbox" name="blocked_services[]" value="<?=$key?>" id="svc_<?=$key?>" <?=isset($blocked_set[$key]) ? 'checked' : ''?>>
								<label class="form-check-label fw-semibold" for="svc_<?=$key?>">
									<i class="fa-solid fa-<?=$info['icon']?> text-primary me-1"></i> <?=htmlspecialchars($info['name'])?>
								</label>
								<div class="small text-muted mt-1"><?=htmlspecialchars($info['category'])?></div>
							</div>
						</div>
					</div>
				<?php endforeach; ?>
			</div>
		</div>
		<div class="card-footer bg-light">
			<button type="submit" name="save_services" value="1" class="btn btn-primary"><i class="fa-solid fa-floppy-disk me-2"></i><?=gettext('Save Blocked Services')?></button>
		</div>
	</div>
</form>

<div class="card shadow-sm mb-4">
	<div class="card-header bg-light">
		<h2 class="h5 mb-0"><i class="fa-solid fa-laptop text-primary me-2"></i><?=gettext('Active LAN Clients & DHCP Hostnames')?></h2>
	</div>
	<div class="card-body p-0">
		<div class="table-responsive">
			<table class="table table-striped table-hover align-middle mb-0">
				<thead>
					<tr>
						<th><?=gettext('IP Address')?></th>
						<th><?=gettext('Hostname / Device Name')?></th>
						<th><?=gettext('Enforced Policy')?></th>
					</tr>
				</thead>
				<tbody>
					<?php if (empty($dhcp_hosts)): ?>
						<tr><td colspan="3" class="text-center text-muted py-3"><?=gettext('No active DHCP lease mappings detected.')?></td></tr>
					<?php else: ?>
						<?php foreach ($dhcp_hosts as $ip => $host): ?>
							<tr>
								<td class="font-monospace fw-bold"><?=$ip?></td>
								<td><span class="badge bg-secondary"><?=htmlspecialchars((string)$host)?></span></td>
								<td><span class="badge bg-success"><i class="fa-solid fa-shield-halved me-1"></i><?=gettext('Threat Shield Protection Active')?></span></td>
							</tr>
						<?php endforeach; ?>
					<?php endif; ?>
				</tbody>
			</table>
		</div>
	</div>
</div>

<?php include('foot.inc'); ?>
