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

$input_errors = [];
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
	$ts_config['blocked_services'] = array_values(array_intersect(array_map('strval', (array)($_POST['blocked_services'] ?? [])), $services_catalog ? array_keys($services_catalog) : []));
	if (threatshield_save_and_apply($ts_config, gettext('Updated Threat Shield blocked services.'), $input_errors)) $savemsg = gettext('Blocked services updated and applied.');
} elseif ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['add_profile'])) {
	$name = trim((string)($_POST['profile_name'] ?? ''));
	$ids = array_values(array_filter(array_map('trim', preg_split('/[\s,]+/', (string)($_POST['profile_ids'] ?? '')))));
	if ($name === '' || empty($ids) || count($ids) > 20) {
		$input_errors[] = gettext('A profile needs a name and one or more client IP addresses or hostnames.');
	} else {
		$ts_config['clients'][] = ['name' => $name, 'ids' => $ids, 'filtering' => in_array($_POST['profile_filtering'] ?? '', ['on','off','inherit'], true) ? $_POST['profile_filtering'] : 'inherit', 'blocked_services' => array_values(array_intersect(array_map('strval', (array)($_POST['profile_services'] ?? [])), array_keys($services_catalog)))];
		if (threatshield_save_and_apply($ts_config, gettext('Added a Threat Shield client profile.'), $input_errors)) $savemsg = gettext('Client profile added and applied.');
	}
} elseif ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['delete_profile'])) {
	$index = (int)$_POST['delete_profile'];
	if (isset($ts_config['clients'][$index])) {
		array_splice($ts_config['clients'], $index, 1);
		if (threatshield_save_and_apply($ts_config, gettext('Deleted a Threat Shield client profile.'), $input_errors)) $savemsg = gettext('Client profile deleted.');
	}
}

$blocked_set = array_flip($ts_config['blocked_services'] ?? []);
$dhcp_hosts = threatshield_get_dhcp_hostnames();

$pgtitle = [gettext('Services'), gettext('Threat Shield'), gettext('Client Profiles & Services')];
$pglinks = ['', '@self', '@self'];

include('head.inc');

if ($input_errors) print_input_errors($input_errors);

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
		<div class="card-header">
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
		<div class="card-footer">
			<button type="submit" name="save_services" value="1" class="btn btn-primary"><i class="fa-solid fa-floppy-disk me-2"></i><?=gettext('Save Blocked Services')?></button>
		</div>
	</div>
</form>

<div class="card shadow-sm mb-4">
	<div class="card-header"><h2 class="h5 mb-0"><?=gettext('Per-Client Profiles')?></h2></div>
	<div class="card-body">
		<p class="text-muted small"><?=gettext('Use stable client IP addresses or DHCP hostnames. Profiles override the global filtering and service settings for matching clients.')?></p>
		<?php foreach (threatshield_normalize_list($ts_config['clients']) as $idx => $profile): ?>
			<div class="border rounded p-2 mb-2 d-flex justify-content-between align-items-center"><span><strong><?=htmlspecialchars((string)($profile['name'] ?? 'Profile'))?></strong> — <?=htmlspecialchars(implode(', ', threatshield_normalize_list($profile['ids'] ?? [])))?></span><form method="post"><button class="btn btn-sm btn-outline-danger" name="delete_profile" value="<?=$idx?>"><?=gettext('Delete')?></button></form></div>
		<?php endforeach; ?>
		<form method="post" class="row g-3 mt-1">
			<div class="col-md-4"><label class="form-label"><?=gettext('Profile name')?></label><input class="form-control" name="profile_name" required></div>
			<div class="col-md-4"><label class="form-label"><?=gettext('Client IPs / hostnames')?></label><input class="form-control" name="profile_ids" placeholder="192.168.1.20, child-tablet" required></div>
			<div class="col-md-2"><label class="form-label"><?=gettext('Filtering')?></label><select class="form-select" name="profile_filtering"><option value="inherit"><?=gettext('Inherit global')?></option><option value="on"><?=gettext('Force on')?></option><option value="off"><?=gettext('Force off')?></option></select></div>
			<div class="col-md-2 d-flex align-items-end"><button class="btn btn-outline-primary w-100" name="add_profile" value="1"><?=gettext('Add profile')?></button></div>
			<div class="col-12"><label class="form-label"><?=gettext('Profile blocked services')?></label><?php foreach ($services_catalog as $key => $info): ?><label class="form-check form-check-inline"><input class="form-check-input" type="checkbox" name="profile_services[]" value="<?=$key?>"> <?=htmlspecialchars($info['name'])?></label><?php endforeach; ?></div>
		</form>
	</div>
</div>

<div class="card shadow-sm mb-4">
	<div class="card-header">
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
