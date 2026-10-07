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
$profiles = threatshield_normalize_list($ts_config['clients']);

/* which profile (if any) matches a client by address or host name */
$profile_for = function ($ip, $host) use ($profiles) {
	foreach ($profiles as $p) {
		$ids = array_map('strtolower', array_map('strval', threatshield_normalize_list($p['ids'] ?? [])));
		if (in_array(strtolower($ip), $ids, true) || ($host !== '' && in_array(strtolower($host), $ids, true))) {
			return (string)($p['name'] ?? '');
		}
	}
	return null;
};
$filtering_labels = ['inherit' => gettext('Global setting'), 'on' => gettext('Always on'), 'off' => gettext('Off')];

$pgtitle = [gettext('Services'), gettext('Threat Shield'), gettext('Clients')];
$pglinks = ['', '/threatshield/threatshield_status.php', '@self'];

fs_page_action(gettext('Add profile'), '#', 'fa-plus', 'primary', ['data-fs-modal' => '#profile-add']);

include('head.inc');

if ($input_errors) print_input_errors($input_errors);

if ($savemsg) {
	print_info_box($savemsg, 'success');
}

threatshield_display_tabs('clients');
?>

<div class="panel panel-default fs-table">
<?php fs_table_toolbar([
	'title' => gettext('Client profiles'),
	'search' => gettext('Search profiles…'),
	'noun' => gettext('profiles'),
	'noun_one' => gettext('profile'),
]); ?>
	<div class="panel-body table-responsive">
		<table class="table table-hover">
			<thead>
				<tr>
					<th data-fs-search><?=gettext('Name')?></th>
					<th data-fs-search><?=gettext('Clients')?></th>
					<th><?=gettext('Filtering')?></th>
					<th data-fs-search><?=gettext('Blocked services')?></th>
					<th class="fs-col-actions"><span class="visually-hidden"><?=gettext('Actions')?></span></th>
				</tr>
			</thead>
			<tbody>
<?php
foreach ($profiles as $idx => $profile):
	$pname = (string)($profile['name'] ?? gettext('Profile'));
	$filtering = (string)($profile['filtering'] ?? 'inherit');
	$svcs = threatshield_normalize_list($profile['blocked_services'] ?? []);
?>
				<tr>
					<td><strong><?=htmlspecialchars($pname)?></strong></td>
					<td><span class="fs-chips"><?php foreach (threatshield_normalize_list($profile['ids'] ?? []) as $id): ?><span class="fs-chip fs-chip--mono"><?=htmlspecialchars((string)$id)?></span><?php endforeach; ?></span></td>
					<td><?=($filtering === 'on') ? fs_badge('enabled', $filtering_labels['on']) : (($filtering === 'off') ? fs_badge('disabled', $filtering_labels['off']) : fs_badge('neutral', $filtering_labels['inherit']))?></td>
					<td>
<?php	if (empty($svcs)): ?>
						<span class="fs-muted"><?=gettext('None')?></span>
<?php	else: ?>
						<span class="fs-chips"><?php foreach ($svcs as $svc): ?><span class="fs-chip"><?=htmlspecialchars($services_catalog[$svc]['name'] ?? (string)$svc)?></span><?php endforeach; ?></span>
<?php	endif; ?>
					</td>
					<td class="fs-col-actions"><?=fs_row_actions([
						['delete', 'threatshield_clients.php?delete_profile=' . (int)$idx, $pname, [
							'thing' => gettext('profile'),
							'detail' => gettext('Its clients fall back to the global filtering and service settings.'),
						]],
					])?></td>
				</tr>
<?php
endforeach;
if (empty($profiles)) {
	fs_empty_row(5, gettext('No client profiles yet. Every client uses the global settings.'));
}
?>
			</tbody>
		</table>
	</div>
	<div class="panel-footer small fs-muted">
		<i class="fa-solid fa-circle-info" aria-hidden="true"></i>
		<?=gettext('Profiles override the global filtering and blocked services for matching clients. Use fixed IP addresses or DHCP host names.')?>
	</div>
</div>

<form method="post" action="threatshield_clients.php" id="ts-services-form">
<div class="panel panel-default">
	<div class="panel-heading"><h2 class="panel-title"><?=gettext('Blocked services for the whole network')?> <span class="fs-count" id="ts-svc-count"><?=count(array_intersect_key($blocked_set, $services_catalog))?></span></h2></div>
	<div class="panel-body ts-services-body">
		<p class="fs-muted"><?=gettext('Turn on a service to block its domains and content networks for every client without a profile.')?></p>
		<div class="ts-services">
<?php foreach ($services_catalog as $key => $info): ?>
			<label class="ts-service" for="svc_<?=$key?>">
				<span class="ts-service-icon"><i class="fa-solid fa-<?=$info['icon']?>" aria-hidden="true"></i></span>
				<span class="ts-service-text">
					<span class="ts-service-name"><?=htmlspecialchars($info['name'])?></span>
					<span class="fs-muted small"><?=htmlspecialchars(gettext($info['category']))?></span>
				</span>
				<span class="form-check form-switch">
					<input class="form-check-input" type="checkbox" role="switch" name="blocked_services[]" value="<?=$key?>" id="svc_<?=$key?>"<?=isset($blocked_set[$key]) ? ' checked' : ''?>>
				</span>
			</label>
<?php endforeach; ?>
		</div>
	</div>
</div>
<div class="fs-actionbar fs-actionbar--plain">
	<button type="submit" name="save_services" value="1" class="btn btn-primary"><i class="fa-solid fa-floppy-disk icon-embed-btn" aria-hidden="true"></i><?=gettext('Save blocked services')?></button>
	<span class="ts-dirty fs-muted small" hidden><i class="fa-solid fa-circle-exclamation" aria-hidden="true"></i><?=gettext('Changes are not saved yet.')?></span>
</div>
</form>

<div class="panel panel-default fs-table">
<?php fs_table_toolbar([
	'title' => gettext('Known LAN clients'),
	'search' => gettext('Search clients…'),
	'noun' => gettext('clients'),
	'noun_one' => gettext('client'),
	'filters' => ['policy' => [gettext('All policies'), 'profile' => gettext('With profile'), 'global' => gettext('Global settings')]],
]); ?>
	<div class="panel-body table-responsive">
		<table class="table table-hover" data-sortable>
			<thead>
				<tr>
					<th data-fs-search><?=gettext('IP address')?></th>
					<th data-fs-search><?=gettext('Host name')?></th>
					<th data-fs-search><?=gettext('Policy')?></th>
				</tr>
			</thead>
			<tbody>
<?php
foreach ($dhcp_hosts as $ip => $host):
	$match = $profile_for((string)$ip, (string)$host);
?>
				<tr data-fs-filter-policy="<?=($match !== null) ? 'profile' : 'global'?>">
					<td class="fs-mono"><?=htmlspecialchars((string)$ip)?></td>
					<td><?=htmlspecialchars((string)$host)?></td>
					<td><?=($match !== null) ? fs_badge('info', sprintf(gettext('Profile: %s'), $match)) : fs_badge('neutral', gettext('Global settings'))?></td>
				</tr>
<?php
endforeach;
if (empty($dhcp_hosts)) {
	fs_empty_row(3, gettext('No DHCP leases or static mappings with a host name found.'));
}
?>
			</tbody>
		</table>
	</div>
	<div class="panel-footer small fs-muted">
		<i class="fa-solid fa-circle-info" aria-hidden="true"></i>
		<?=gettext('Taken from DHCP leases and static mappings that have a host name.')?>
	</div>
</div>

<?php
fs_modal_form_begin('profile-add', gettext('Add client profile'), 'threatshield_clients.php', [], ($input_errors && isset($_POST['add_profile']))
    ? ['profile_name' => (string)($_POST['profile_name'] ?? ''), 'profile_ids' => (string)($_POST['profile_ids'] ?? ''),
       'profile_filtering' => (string)($_POST['profile_filtering'] ?? 'inherit')]
    : null);
?>
	<div class="mb-3">
		<label class="form-label" for="profile_name"><?=gettext('Name')?></label>
		<input class="form-control" id="profile_name" name="profile_name" placeholder="<?=gettext('Kids tablets')?>" required>
	</div>
	<div class="mb-3">
		<label class="form-label" for="profile_ids"><?=gettext('Clients')?></label>
		<input class="form-control fs-mono" id="profile_ids" name="profile_ids" placeholder="192.168.1.20, child-tablet" required>
		<div class="form-text"><?=gettext('Up to 20 IP addresses or host names, separated by commas or spaces.')?></div>
	</div>
	<div class="mb-3">
		<label class="form-label" for="profile_filtering"><?=gettext('Filtering')?></label>
		<select class="form-select" id="profile_filtering" name="profile_filtering">
			<option value="inherit"><?=gettext('Use the global setting')?></option>
			<option value="on"><?=gettext('Always on')?></option>
			<option value="off"><?=gettext('Off')?></option>
		</select>
	</div>
	<fieldset class="mb-0">
		<legend class="form-label"><?=gettext('Blocked services')?></legend>
		<div class="ts-profile-services">
<?php foreach ($services_catalog as $key => $info): ?>
			<label class="form-check">
				<input class="form-check-input" type="checkbox" name="profile_services[]" value="<?=$key?>"> <?=htmlspecialchars($info['name'])?>
			</label>
<?php endforeach; ?>
		</div>
	</fieldset>
<?php
fs_modal_form_end(gettext('Add profile'), 'add_profile', '1', 'fa-plus');
?>

<style>
.ts-services-body { padding: var(--fs-sp-3) var(--fs-sp-4) var(--fs-sp-4); }
.ts-services { display: grid; grid-template-columns: repeat(auto-fill, minmax(14rem, 1fr)); gap: var(--fs-sp-2); }
.ts-service { display: flex; align-items: center; gap: var(--fs-sp-3); margin: 0; padding: var(--fs-sp-2) var(--fs-sp-3);
	border: 1px solid var(--fs-border); border-radius: var(--fs-r-md); cursor: pointer; font-weight: 400; }
.ts-service:hover { background: var(--fs-surface-raised); }
.ts-service:has(input:checked) { border-color: color-mix(in srgb, var(--fs-block) 50%, transparent); background: color-mix(in srgb, var(--fs-block) 8%, transparent); }
.ts-service-icon { display: inline-flex; align-items: center; justify-content: center; flex: none; width: 2rem; height: 2rem;
	border-radius: var(--fs-r-sm); background: var(--fs-surface-raised); color: var(--fs-text-muted); }
.ts-service-text { display: flex; flex-direction: column; min-width: 0; flex: 1 1 auto; }
.ts-service-name { font-weight: 600; color: var(--fs-text-strong); }
.ts-service .form-switch { margin: 0; min-height: 0; }
.ts-profile-services { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 0 var(--fs-sp-3); }
.ts-profile-services .form-check { margin: 0; font-weight: 400; }
.ts-dirty { display: inline-flex; align-items: center; gap: .4rem; margin-left: var(--fs-sp-3); }
.ts-dirty > i { color: var(--fs-coral); }
@media (max-width: 575px) { .ts-services { grid-template-columns: minmax(0, 1fr); } }
</style>
<script>
//<![CDATA[
events.push(function () {
	var form = document.getElementById('ts-services-form');
	form.addEventListener('change', function () {
		form.querySelector('.ts-dirty').hidden = false;
		document.getElementById('ts-svc-count').textContent = form.querySelectorAll('input[name="blocked_services[]"]:checked').length;
	});
});
//]]>
</script>

<?php include('foot.inc'); ?>
