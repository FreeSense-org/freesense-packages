<?php
/*
 * threatshield_clients.php
 * FreeSense Threat Shield - client profiles, blocked services and schedules
 *
 * Copyright (c) 2025-2026 The FreeSense Project.
 * Licensed under the Apache License, Version 2.0.
 */

##|+PRIV
##|*IDENT=page-services-threatshield
##|*NAME=Services: Threat Shield Clients
##|*DESCR=Configure per-client DNS security policies and blocked services
##|*MATCH=threatshield/threatshield_clients.php*
##|-PRIV

require_once('guiconfig.inc');
require_once('/usr/local/pkg/threatshield.inc');
require_once('/usr/local/pkg/threatshield/threatshield_ui.inc');

$cfg = threatshield_config();
$view = fs_view_param(['profiles', 'services', 'known'], 'profiles');
$self = 'threatshield_clients.php?view=' . $view;
$catalog = threatshield_services_info();
$day_labels = ['mon' => gettext('Monday'), 'tue' => gettext('Tuesday'), 'wed' => gettext('Wednesday'), 'thu' => gettext('Thursday'),
    'fri' => gettext('Friday'), 'sat' => gettext('Saturday'), 'sun' => gettext('Sunday')];
$filtering_labels = ['inherit' => gettext('Use the global settings'), 'on' => gettext('Always filter'), 'off' => gettext('No filtering')];
$profiles = threatshield_normalize_list($cfg['clients'] ?? []);
$edit = $_GET['edit'] ?? ($_POST['profile_index'] ?? null);
$input_errors = [];

/* schedule fields posted as sched_<day>_on/start/end */
$read_schedule = function (): array {
	$days = [];
	foreach (threatshield_schedule_days() as $d) {
		if (!isset($_POST["sched_{$d}_on"])) continue;
		$days[] = ['day' => $d, 'start' => trim((string)($_POST["sched_{$d}_start"] ?? '')), 'end' => trim((string)($_POST["sched_{$d}_end"] ?? ''))];
	}
	return $days;
};

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
	$changed = false;
	$message = '';
	if (isset($_POST['save_profile'])) {
		$index = ($edit === 'new' || $edit === null || !isset($profiles[(int)$edit])) ? null : (int)$edit;
		$ids = array_values(array_filter(array_map('trim', preg_split('/[\s,]+/', (string)($_POST['profile_ids'] ?? '')))));
		$p = [
			'name' => trim((string)($_POST['profile_name'] ?? '')),
			'ids' => $ids,
			'filtering' => array_key_exists($_POST['profile_filtering'] ?? '', $filtering_labels) ? $_POST['profile_filtering'] : 'inherit',
			'blocked_services' => array_values(array_intersect(array_map('strval', (array)($_POST['services'] ?? [])), array_keys($catalog))),
			'schedule_enable' => isset($_POST['schedule_enable']) ? 'on' : 'off',
			'schedule_tz' => trim((string)($_POST['schedule_tz'] ?? 'Local')) ?: 'Local',
			'schedule_days' => $read_schedule(),
		];
		if ($p['name'] === '' || empty($ids) || count($ids) > 20) {
			$input_errors[] = gettext('A profile needs a name and 1 to 20 client IP addresses, networks or host names.');
		} else {
			if ($index === null) $profiles[] = $p; else $profiles[$index] = $p;
			$cfg['clients'] = $profiles;
			$errors = [];
			if (threatshield_save_and_apply($cfg, gettext('Threat Shield: saved a client profile'), $errors)) {
				threatshield_flash('ok', sprintf(gettext('Profile "%s" saved.'), $p['name']));
				threatshield_redirect('threatshield_clients.php?view=profiles');
			}
			$input_errors = $errors;
		}
	} elseif (isset($_POST['delete_profile'])) {
		$i = (int)$_POST['delete_profile'];
		if (isset($profiles[$i])) {
			$message = sprintf(gettext('Profile "%s" deleted.'), (string)($profiles[$i]['name'] ?? ''));
			array_splice($profiles, $i, 1);
			$cfg['clients'] = $profiles;
			$changed = true;
		}
	} elseif (isset($_POST['save_services'])) {
		$cfg['blocked_services'] = array_values(array_intersect(array_map('strval', (array)($_POST['services'] ?? [])), array_keys($catalog)));
		$cfg['services_schedule_enable'] = isset($_POST['schedule_enable']) ? 'on' : 'off';
		$cfg['services_schedule_tz'] = trim((string)($_POST['schedule_tz'] ?? 'Local')) ?: 'Local';
		$cfg['services_schedule_days'] = $read_schedule();
		$changed = true;
		$message = gettext('Blocked services saved.');
	}
	if ($changed) threatshield_apply($cfg, gettext('Threat Shield: updated clients and services'), $message);
	if (empty($input_errors)) threatshield_redirect($self);
}

/* services grid with search, grouped by category; $selected = ids */
$services_grid = function (array $selected) use ($catalog): void {
	$groups = [];
	foreach ($catalog as $id => [$name, $group, $icon]) $groups[$group][$id] = [$name, $icon];
	ksort($groups);
?>
	<div class="ts-svc-tools">
		<div class="fs-search"><i class="fa-solid fa-magnifying-glass" aria-hidden="true"></i>
			<input type="search" class="form-control" data-ts-svc-search placeholder="<?=gettext('Search services…')?>" aria-label="<?=gettext('Search services')?>"></div>
		<label class="form-check"><input class="form-check-input" type="checkbox" data-ts-svc-only> <?=gettext('Blocked only')?></label>
		<span class="fs-muted small" data-ts-svc-count></span>
	</div>
<?php	foreach ($groups as $group => $items): ?>
	<fieldset class="ts-svc-group">
		<legend><?=htmlspecialchars(gettext($group))?></legend>
		<div class="ts-services">
<?php		foreach ($items as $id => [$name, $icon]): ?>
			<label class="ts-service" data-ts-svc="<?=htmlspecialchars(strtolower($name . ' ' . $id))?>">
				<span class="ts-service-icon"><i class="fa-solid fa-<?=htmlspecialchars($icon)?>" aria-hidden="true"></i></span>
				<span class="ts-service-name"><?=htmlspecialchars($name)?></span>
				<span class="form-check form-switch"><input class="form-check-input" type="checkbox" role="switch" name="services[]" value="<?=htmlspecialchars($id)?>"<?=in_array($id, $selected, true) ? ' checked' : ''?>></span>
			</label>
<?php		endforeach; ?>
		</div>
	</fieldset>
<?php	endforeach;
};

/* the unblock schedule: one row per day */
$schedule_editor = function (bool $enabled, string $tz, array $days, string $help) use ($day_labels): void {
	$by_day = [];
	foreach ($days as $d) if (is_array($d)) $by_day[(string)($d['day'] ?? '')] = $d;
?>
	<label class="form-check mb-2"><input class="form-check-input" type="checkbox" name="schedule_enable" data-ts-sched-toggle<?=$enabled ? ' checked' : ''?>> <?=htmlspecialchars($help)?></label>
	<div class="ts-sched" data-ts-sched<?=$enabled ? '' : ' hidden'?>>
<?php	foreach ($day_labels as $d => $label):
		$row = $by_day[$d] ?? null;
?>
		<div class="ts-sched-row">
			<label class="form-check"><input class="form-check-input" type="checkbox" name="sched_<?=$d?>_on"<?=($row !== null) ? ' checked' : ''?>> <?=htmlspecialchars($label)?></label>
			<input type="time" class="form-control form-control-sm" name="sched_<?=$d?>_start" value="<?=htmlspecialchars((string)($row['start'] ?? '16:00'))?>" aria-label="<?=htmlspecialchars(sprintf(gettext('%s from'), $label))?>">
			<span class="fs-muted">–</span>
			<input type="text" class="form-control form-control-sm fs-mono" name="sched_<?=$d?>_end" value="<?=htmlspecialchars((string)($row['end'] ?? '20:00'))?>" pattern="([01]\d|2[0-3]):[0-5]\d|24:00" aria-label="<?=htmlspecialchars(sprintf(gettext('%s until'), $label))?>">
		</div>
<?php	endforeach; ?>
		<div class="ts-sched-tz">
			<label class="form-label" for="schedule_tz"><?=gettext('Time zone')?></label>
			<input type="text" class="form-control form-control-sm fs-mono" id="schedule_tz" name="schedule_tz" value="<?=htmlspecialchars($tz)?>" placeholder="Local">
			<span class="form-text"><?=gettext('"Local" uses the firewall time zone, or an IANA name such as Europe/Copenhagen. Use 24:00 for the end of the day.')?></span>
		</div>
	</div>
<?php
};

$pgtitle = [gettext('Services'), gettext('Threat Shield'), gettext('Clients & services')];
$pglinks = ['', '/threatshield/threatshield_status.php', 'threatshield_clients.php'];
$editing = ($edit !== null);
if ($editing) {
	$pgtitle[] = ($edit === 'new') ? gettext('Add profile') : gettext('Edit profile');
	$pglinks[] = '@self';
} elseif ($view === 'profiles') {
	fs_page_action(gettext('Add profile'), 'threatshield_clients.php?view=profiles&edit=new', 'fa-plus');
}

include('head.inc');
threatshield_print_messages($input_errors);
threatshield_display_tabs('clients');

if ($editing):
	$p = ($edit !== 'new' && isset($profiles[(int)$edit])) ? $profiles[(int)$edit] : ['name' => '', 'ids' => [], 'filtering' => 'inherit', 'blocked_services' => []];
	if (!empty($input_errors) && isset($_POST['save_profile'])) {
		$p = ['name' => $_POST['profile_name'] ?? '', 'ids' => preg_split('/[\s,]+/', (string)($_POST['profile_ids'] ?? '')), 'filtering' => $_POST['profile_filtering'] ?? 'inherit',
		    'blocked_services' => (array)($_POST['services'] ?? []), 'schedule_enable' => isset($_POST['schedule_enable']) ? 'on' : 'off',
		    'schedule_tz' => $_POST['schedule_tz'] ?? 'Local', 'schedule_days' => $read_schedule()];
	}
?>
<form method="post" action="threatshield_clients.php?view=profiles&amp;edit=<?=htmlspecialchars(rawurlencode((string)$edit))?>">
<input type="hidden" name="profile_index" value="<?=htmlspecialchars((string)$edit)?>">
<div class="panel panel-default">
	<div class="panel-heading"><h2 class="panel-title"><?=gettext('Profile')?></h2></div>
	<div class="panel-body ts-pad">
		<div class="mb-3"><label class="form-label" for="profile_name"><?=gettext('Name')?></label>
			<input class="form-control" id="profile_name" name="profile_name" value="<?=htmlspecialchars((string)$p['name'])?>" placeholder="<?=gettext('Kids tablets')?>" required></div>
		<div class="mb-3"><label class="form-label" for="profile_ids"><?=gettext('Clients')?></label>
			<input class="form-control fs-mono" id="profile_ids" name="profile_ids" value="<?=htmlspecialchars(implode(', ', array_map('strval', threatshield_normalize_list($p['ids'] ?? []))))?>" placeholder="192.168.1.20, 192.168.1.32/28, child-tablet" required>
			<div class="form-text"><?=gettext('Up to 20 IP addresses, networks or DHCP host names, separated by commas or spaces.')?></div></div>
		<div class="mb-0"><label class="form-label" for="profile_filtering"><?=gettext('Filtering')?></label>
			<select class="form-select" id="profile_filtering" name="profile_filtering">
<?php	foreach ($filtering_labels as $k => $label): ?>
				<option value="<?=$k?>"<?=(($p['filtering'] ?? 'inherit') === $k) ? ' selected' : ''?>><?=htmlspecialchars($label)?></option>
<?php	endforeach; ?>
			</select>
			<div class="form-text"><?=gettext('"Always filter" keeps the global safe browsing, parental control and SafeSearch settings. "No filtering" exempts these clients from every block list.')?></div></div>
	</div>
</div>
<div class="panel panel-default">
	<div class="panel-heading"><h2 class="panel-title"><?=gettext('Blocked services for this profile')?></h2></div>
	<div class="panel-body ts-pad">
		<p class="fs-muted"><?=gettext('With none selected and no schedule, the network-wide services apply.')?></p>
<?php	$services_grid(array_map('strval', threatshield_normalize_list($p['blocked_services'] ?? []))); ?>
	</div>
</div>
<div class="panel panel-default">
	<div class="panel-heading"><h2 class="panel-title"><?=gettext('Unblock schedule')?></h2></div>
	<div class="panel-body ts-pad">
<?php	$schedule_editor(($p['schedule_enable'] ?? 'off') === 'on', (string)($p['schedule_tz'] ?? 'Local'), threatshield_normalize_list($p['schedule_days'] ?? []),
	    gettext('Allow the blocked services during set hours, for example gaming from 18:00 to 20:00')); ?>
	</div>
</div>
<div class="fs-actionbar">
	<button type="submit" name="save_profile" value="1" class="btn btn-primary"><i class="fa-solid fa-floppy-disk icon-embed-btn" aria-hidden="true"></i><?=gettext('Save')?></button>
	<a class="btn btn-outline-secondary" href="threatshield_clients.php?view=profiles"><?=gettext('Cancel')?></a>
</div>
</form>
<?php
else:
	fs_view_switch(['profiles' => gettext('Profiles'), 'services' => gettext('Blocked services'), 'known' => gettext('Known clients')], $view);
	$dhcp_hosts = threatshield_get_dhcp_hostnames();

	if ($view === 'profiles'):
?>
<div class="panel panel-default fs-table">
<?php fs_table_toolbar(['title' => gettext('Client profiles'), 'search' => gettext('Search profiles…'), 'noun' => gettext('profiles'), 'noun_one' => gettext('profile')]); ?>
	<div class="panel-body table-responsive">
		<table class="table table-hover table-rowdblclickedit">
			<thead>
				<tr>
					<th data-fs-search><?=gettext('Name')?></th>
					<th data-fs-search><?=gettext('Clients')?></th>
					<th><?=gettext('Filtering')?></th>
					<th data-fs-search><?=gettext('Blocked services')?></th>
					<th><?=gettext('Schedule')?></th>
					<th class="fs-col-actions"><span class="visually-hidden"><?=gettext('Actions')?></span></th>
				</tr>
			</thead>
			<tbody>
<?php	foreach ($profiles as $i => $p):
		$pname = (string)($p['name'] ?? gettext('Profile'));
		$filtering = (string)($p['filtering'] ?? 'inherit');
		$svcs = threatshield_normalize_list($p['blocked_services'] ?? []);
		$days = threatshield_normalize_list($p['schedule_days'] ?? []);
?>
				<tr>
					<td><a href="threatshield_clients.php?view=profiles&amp;edit=<?=(int)$i?>"><strong><?=htmlspecialchars($pname)?></strong></a></td>
					<td><span class="fs-chips"><?php foreach (threatshield_normalize_list($p['ids'] ?? []) as $id): ?><span class="fs-chip fs-chip--mono"><?=htmlspecialchars((string)$id)?></span><?php endforeach; ?></span></td>
					<td><?=($filtering === 'on') ? fs_badge('enabled', gettext('Always')) : (($filtering === 'off') ? fs_badge('disabled', gettext('Off')) : fs_badge('neutral', gettext('Global')))?></td>
					<td><?=empty($svcs) ? '<span class="fs-muted">' . gettext('Network-wide') . '</span>' : htmlspecialchars(implode(', ', array_map(fn($s) => $catalog[$s][0] ?? $s, array_slice($svcs, 0, 5))) . ((count($svcs) > 5) ? ' +' . (count($svcs) - 5) : ''))?></td>
					<td><?=(($p['schedule_enable'] ?? 'off') === 'on' && !empty($days)) ? htmlspecialchars(sprintf(gettext('%d days'), count($days))) : '<span class="fs-muted">' . gettext('None') . '</span>'?></td>
					<td class="fs-col-actions"><?=fs_row_actions([
						['edit', 'threatshield_clients.php?view=profiles&edit=' . (int)$i, $pname],
						['delete', $self . '&delete_profile=' . (int)$i, $pname, ['thing' => gettext('profile'), 'detail' => gettext('Its clients fall back to the global filtering and service settings.')]],
					])?></td>
				</tr>
<?php	endforeach;
	if (empty($profiles)) fs_empty_row(6, gettext('No client profiles yet. Every client uses the global settings.'), 'threatshield_clients.php?view=profiles&edit=new', gettext('Add profile'));
?>
			</tbody>
		</table>
	</div>
	<div class="panel-footer small fs-muted">
		<i class="fa-solid fa-circle-info" aria-hidden="true"></i>
		<?=gettext('Profiles override filtering and blocked services for matching clients. Use fixed addresses or DHCP host names.')?>
	</div>
</div>
<?php
	elseif ($view === 'services'):
?>
<form method="post" action="<?=htmlspecialchars($self)?>">
<div class="panel panel-default">
	<div class="panel-heading"><h2 class="panel-title"><?=gettext('Blocked for the whole network')?> <span class="fs-count" data-ts-svc-total><?=count(threatshield_normalize_list($cfg['blocked_services'] ?? []))?></span></h2></div>
	<div class="panel-body ts-pad">
		<p class="fs-muted"><?=gettext('Blocks the domains of these services for every client without its own profile.')?></p>
<?php	$services_grid(array_map('strval', threatshield_normalize_list($cfg['blocked_services'] ?? []))); ?>
	</div>
</div>
<div class="panel panel-default">
	<div class="panel-heading"><h2 class="panel-title"><?=gettext('Unblock schedule')?></h2></div>
	<div class="panel-body ts-pad">
<?php	$schedule_editor(($cfg['services_schedule_enable'] ?? 'off') === 'on', (string)($cfg['services_schedule_tz'] ?? 'Local'), threatshield_normalize_list($cfg['services_schedule_days'] ?? []),
	    gettext('Allow the blocked services during set hours, for example social media during lunch')); ?>
	</div>
</div>
<div class="fs-actionbar fs-actionbar--plain">
	<button type="submit" name="save_services" value="1" class="btn btn-primary"><i class="fa-solid fa-floppy-disk icon-embed-btn" aria-hidden="true"></i><?=gettext('Save')?></button>
</div>
</form>
<?php
	else:
		$profile_for = function ($ip, $host) use ($profiles) {
			foreach ($profiles as $p) {
				$ids = array_map('strtolower', array_map('strval', threatshield_normalize_list($p['ids'] ?? [])));
				if (in_array(strtolower($ip), $ids, true) || ($host !== '' && in_array(strtolower($host), $ids, true))) return (string)($p['name'] ?? '');
				foreach ($ids as $id) {
					if (strpos($id, '/') !== false && threatshield_cidr_contains($id, $ip)) return (string)($p['name'] ?? '');
				}
			}
			return null;
		};
?>
<div class="panel panel-default fs-table">
<?php fs_table_toolbar(['title' => gettext('Known LAN clients'), 'search' => gettext('Search clients…'), 'noun' => gettext('clients'), 'noun_one' => gettext('client'),
	'filters' => ['policy' => [gettext('All policies'), 'profile' => gettext('With profile'), 'global' => gettext('Global settings')]]]); ?>
	<div class="panel-body table-responsive">
		<table class="table table-hover" data-sortable>
			<thead><tr><th data-fs-search><?=gettext('IP address')?></th><th data-fs-search><?=gettext('Host name')?></th><th data-fs-search><?=gettext('Policy')?></th></tr></thead>
			<tbody>
<?php		foreach ($dhcp_hosts as $ip => $host):
			$match = $profile_for((string)$ip, (string)$host);
?>
				<tr data-fs-filter-policy="<?=($match !== null) ? 'profile' : 'global'?>">
					<td class="fs-mono"><?=htmlspecialchars((string)$ip)?></td>
					<td><?=htmlspecialchars((string)$host)?></td>
					<td><?=($match !== null) ? fs_badge('info', sprintf(gettext('Profile: %s'), $match)) : fs_badge('neutral', gettext('Global settings'))?></td>
				</tr>
<?php		endforeach;
		if (empty($dhcp_hosts)) fs_empty_row(3, gettext('No DHCP leases or static mappings with a host name found.'));
?>
			</tbody>
		</table>
	</div>
</div>
<?php
	endif;
endif;
threatshield_ui_styles();
?>
<style>
.ts-pad { padding: var(--fs-sp-3) var(--fs-sp-4) var(--fs-sp-4); }
.ts-svc-tools { display: flex; flex-wrap: wrap; align-items: center; gap: var(--fs-sp-3); margin-bottom: var(--fs-sp-3); }
.ts-svc-tools .fs-search { flex: 0 1 20rem; }
.ts-svc-tools .form-check { margin: 0; font-weight: 400; }
.ts-svc-group { margin-bottom: var(--fs-sp-3); }
.ts-svc-group legend { font-size: var(--fs-fs-sm); font-weight: 600; color: var(--fs-text-muted); margin-bottom: var(--fs-sp-2); }
.ts-services { display: grid; grid-template-columns: repeat(auto-fill, minmax(13rem, 1fr)); gap: var(--fs-sp-2); }
.ts-service { display: flex; align-items: center; gap: var(--fs-sp-2); margin: 0; padding: var(--fs-sp-1) var(--fs-sp-2);
	border: 1px solid var(--fs-border); border-radius: var(--fs-r-md); cursor: pointer; font-weight: 400; }
.ts-service:hover { background: var(--fs-surface-raised); }
.ts-service:has(input:checked) { border-color: color-mix(in srgb, var(--fs-block) 50%, transparent); background: color-mix(in srgb, var(--fs-block) 8%, transparent); }
.ts-service-icon { display: inline-flex; align-items: center; justify-content: center; flex: none; width: 1.75rem; height: 1.75rem;
	border-radius: var(--fs-r-sm); background: var(--fs-surface-raised); color: var(--fs-text-muted); font-size: .8rem; }
.ts-service-name { flex: 1 1 auto; min-width: 0; font-weight: 600; color: var(--fs-text-strong); }
.ts-service .form-switch { margin: 0; min-height: 0; }
.ts-sched { display: flex; flex-direction: column; gap: var(--fs-sp-1); }
.ts-sched-row { display: grid; grid-template-columns: 9rem 8rem auto 6rem; align-items: center; gap: var(--fs-sp-2); }
.ts-sched-row .form-check { margin: 0; font-weight: 400; }
.ts-sched-tz { max-width: 26rem; margin-top: var(--fs-sp-2); }
@media (max-width: 575px) { .ts-services { grid-template-columns: minmax(0, 1fr); } .ts-sched-row { grid-template-columns: 1fr 1fr; } }
</style>
<script>
//<![CDATA[
events.push(function () {
	var search = document.querySelector('[data-ts-svc-search]');
	var only = document.querySelector('[data-ts-svc-only]');
	var count = document.querySelector('[data-ts-svc-count]');
	function filter() {
		var q = search ? search.value.trim().toLowerCase() : '';
		var shown = 0;
		document.querySelectorAll('.ts-svc-group').forEach(function (group) {
			var visible = 0;
			group.querySelectorAll('[data-ts-svc]').forEach(function (item) {
				var on = item.querySelector('input').checked;
				var show = (q === '' || item.getAttribute('data-ts-svc').indexOf(q) !== -1) && (!only || !only.checked || on);
				item.hidden = !show;
				if (show) {
					visible++;
				}
			});
			group.hidden = (visible === 0);
			shown += visible;
		});
		var checked = document.querySelectorAll('input[name="services[]"]:checked').length;
		if (count) {
			count.textContent = checked + ' <?=gettext('blocked')?>';
		}
		var total = document.querySelector('[data-ts-svc-total]');
		if (total) {
			total.textContent = checked;
		}
	}
	if (search) {
		search.addEventListener('input', filter);
		if (only) {
			only.addEventListener('change', filter);
		}
		document.addEventListener('change', function (e) {
			if (e.target.name === 'services[]') {
				filter();
			}
		});
		filter();
	}
	var toggle = document.querySelector('[data-ts-sched-toggle]');
	if (toggle) {
		toggle.addEventListener('change', function () {
			document.querySelector('[data-ts-sched]').hidden = !toggle.checked;
		});
	}
});
//]]>
</script>
<?php include('foot.inc'); ?>
