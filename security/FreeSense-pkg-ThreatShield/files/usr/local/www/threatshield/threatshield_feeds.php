<?php
/*
 * threatshield_feeds.php
 * FreeSense Threat Shield - DNS block lists, allowlist lists and IP lists
 *
 * Copyright (c) 2025-2026 The FreeSense Project.
 * Licensed under the Apache License, Version 2.0.
 */

##|+PRIV
##|*IDENT=page-services-threatshield
##|*NAME=Services: Threat Shield Feeds
##|*DESCR=Manage Threat Shield DNS and IP lists and their updates
##|*MATCH=threatshield/threatshield_feeds.php*
##|-PRIV

require_once('guiconfig.inc');
require_once('/usr/local/pkg/threatshield.inc');
require_once('/usr/local/pkg/threatshield/threatshield_ui.inc');

$cfg = threatshield_config();
$view = fs_view_param(['dns', 'allow', 'ip'], 'dns');
$self = 'threatshield_feeds.php?view=' . $view;
$intervals = ['6hours' => gettext('Every 6 hours'), '12hours' => gettext('Every 12 hours'), 'daily' => gettext('Daily (recommended)'), 'weekly' => gettext('Weekly')];
$directions = ['in' => gettext('Inbound: block sources on WAN'), 'out' => gettext('Outbound: block LAN clients connecting to them'), 'both' => gettext('Both directions')];
$assigned = threatshield_assigned_interfaces();

/* the list of the current view, and the config key it lives in */
$list_key = ($view === 'ip') ? 'ip_feeds' : 'feeds';
$in_view = function (array $feed) use ($view): bool {
	if ($view === 'ip') return true;
	return (($feed['kind'] ?? 'block') === 'allow') === ($view === 'allow');
};

$input_errors = [];
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
	$list = threatshield_normalize_list($cfg[$list_key] ?? []);
	$find = function (string $id) use ($list): ?int {
		foreach ($list as $i => $f) {
			if (is_array($f) && (string)($f['id'] ?? '') === $id) return $i;
		}
		return null;
	};
	$changed = false;
	$message = '';
	if (isset($_POST['save_feed'])) {
		$name = trim((string)($_POST['feed_name'] ?? ''));
		$url = trim((string)($_POST['feed_url'] ?? ''));
		$id = (string)($_POST['feed_id'] ?? '');
		if ($name === '' || !filter_var($url, FILTER_VALIDATE_URL) || strtolower((string)parse_url($url, PHP_URL_SCHEME)) !== 'https') {
			$input_errors[] = gettext('A list needs a name and an HTTPS URL.');
		} else {
			$i = ($id !== '') ? $find($id) : null;
			$feed = ($i !== null) ? $list[$i] : ['enabled' => 'on', 'preset' => ''];
			$feed['name'] = $name;
			if (($feed['url'] ?? '') !== $url) $feed['preset'] = '';
			$feed['url'] = $url;
			if ($view === 'ip') {
				$feed['id'] = $feed['id'] ?? ('c' . substr(md5($url), 0, 7));
				$feed['kind'] = (($feed['kind'] ?? '') === 'doh') ? 'doh' : 'threat';
				$feed['direction'] = array_key_exists($_POST['feed_direction'] ?? '', $directions) ? $_POST['feed_direction'] : 'in';
				$feed['log'] = isset($_POST['feed_log']) ? 'on' : 'off';
			} else {
				$feed['id'] = $feed['id'] ?? substr(md5($url), 0, 8);
				$feed['kind'] = ($view === 'allow') ? 'allow' : 'block';
				$feed['category'] = trim((string)($_POST['feed_category'] ?? '')) ?: gettext('Custom');
			}
			if ($i === null && $find((string)$feed['id']) !== null) {
				$input_errors[] = gettext('This list is already configured.');
			} else {
				if ($i === null) $list[] = $feed; else $list[$i] = $feed;
				$changed = true;
				$message = sprintf(gettext('List "%s" saved.'), $name);
				if ($view !== 'ip') $cfg['feed_level'] = 'custom';
			}
		}
	} elseif (isset($_POST['add_preset'])) {
		$preset = (string)$_POST['add_preset'];
		$feed = ($view === 'ip') ? threatshield_ipfeed_from_catalog($preset, true) : threatshield_feed_from_catalog($preset, true);
		if ($feed !== null && $find((string)$feed['id']) === null) {
			$list[] = $feed;
			$changed = true;
			$message = sprintf(gettext('List "%s" added.'), $feed['name']);
			if ($view !== 'ip') $cfg['feed_level'] = 'custom';
		}
	} elseif (isset($_POST['set_level']) && array_key_exists($_POST['set_level'], threatshield_feed_levels())) {
		$list = threatshield_apply_feed_level($list, (string)$_POST['set_level']);
		$cfg['feed_level'] = (string)$_POST['set_level'];
		$changed = true;
		$message = sprintf(gettext('Protection level set to %s.'), threatshield_feed_levels()[$cfg['feed_level']][0]);
	} elseif (isset($_POST['toggle']) || isset($_POST['delete'])) {
		$i = $find((string)($_POST['toggle'] ?? $_POST['delete']));
		if ($i !== null) {
			$name = (string)($list[$i]['name'] ?? '');
			if (isset($_POST['delete'])) {
				array_splice($list, $i, 1);
				$message = sprintf(gettext('List "%s" deleted.'), $name);
			} else {
				$list[$i]['enabled'] = (($list[$i]['enabled'] ?? 'off') === 'on') ? 'off' : 'on';
				$message = sprintf(($list[$i]['enabled'] === 'on') ? gettext('List "%s" turned on.') : gettext('List "%s" turned off.'), $name);
			}
			$changed = true;
			if ($view !== 'ip') $cfg['feed_level'] = 'custom';
		}
	} elseif (isset($_POST['bulk_on']) || isset($_POST['bulk_off']) || isset($_POST['bulk_delete'])) {
		$ids = array_map('strval', (array)($_POST['sel'] ?? []));
		$keep = [];
		foreach ($list as $f) {
			$selected = is_array($f) && in_array((string)($f['id'] ?? ''), $ids, true);
			if ($selected && isset($_POST['bulk_delete'])) continue;
			if ($selected) $f['enabled'] = isset($_POST['bulk_on']) ? 'on' : 'off';
			$keep[] = $f;
		}
		$list = $keep;
		$changed = !empty($ids);
		$message = sprintf(gettext('%d lists changed.'), count($ids));
		if ($view !== 'ip') $cfg['feed_level'] = 'custom';
	} elseif (isset($_POST['save_options'])) {
		if ($view === 'ip') {
			$cfg['ipbl_enable'] = isset($_POST['ipbl_enable']) ? 'on' : 'off';
			$cfg['ipbl_update_interval'] = array_key_exists($_POST['ipbl_update_interval'] ?? '', $intervals) ? $_POST['ipbl_update_interval'] : 'daily';
			$cfg['ipbl_wan_interfaces'] = array_values(array_intersect(array_map('strval', (array)($_POST['ipbl_wan_interfaces'] ?? [])), array_keys($assigned)));
			$cfg['ipbl_lan_interfaces'] = array_values(array_intersect(array_map('strval', (array)($_POST['ipbl_lan_interfaces'] ?? [])), array_keys($assigned)));
		} else {
			$cfg['feed_update_interval'] = array_key_exists($_POST['feed_update_interval'] ?? '', $intervals) ? $_POST['feed_update_interval'] : 'daily';
		}
		$changed = true;
		$message = gettext('Update settings saved.');
	} elseif (isset($_POST['update_now'])) {
		mwexec_bg(THREATSHIELD_UPDATER . (($view === 'ip') ? ' ipfeeds force' : ' feeds force'));
		threatshield_flash('ok', gettext('Download started in the background; the status column updates when it finishes.'));
	}
	if ($changed && empty($input_errors)) {
		$cfg[$list_key] = $list;
		threatshield_apply($cfg, gettext('Threat Shield: updated the lists'), $message);
	}
	if (empty($input_errors)) threatshield_redirect($self);
}

$health = threatshield_feed_health($cfg);
$feeds = array_values(array_filter(threatshield_normalize_list($cfg[$list_key] ?? []), fn($f) => is_array($f) && $in_view($f)));
$present = array_filter(array_map(fn($f) => (string)($f['preset'] ?? ''), $feeds));
$catalog = ($view === 'ip') ? threatshield_ipfeed_catalog() : array_filter(threatshield_feed_catalog(), fn($c) => ($c['kind'] === 'allow') === ($view === 'allow'));
$available = array_diff_key($catalog, array_flip($present));
$enabled_count = count(array_filter($feeds, fn($f) => ($f['enabled'] ?? '') === 'on'));
$rules_total = 0;
foreach ($feeds as $f) $rules_total += (int)($health[(string)$f['url']]['rules'] ?? $health[(string)$f['url']]['entries'] ?? 0);
$last = threatshield_last_update(($view === 'ip') ? 'ipfeeds' : 'feeds');

$pgtitle = [gettext('Services'), gettext('Threat Shield'), gettext('Blocklists')];
$pglinks = ['', '/threatshield/threatshield_status.php', '@self'];

fs_page_action(gettext('Add list'), '#', 'fa-plus', 'primary', ['data-fs-modal' => '#feed-edit']);
if ($view === 'dns') {
	fs_page_action(gettext('Protection level'), '#', 'fa-sliders', 'secondary', ['data-fs-modal' => '#level-pick']);
}
fs_page_action(gettext('Download now'), $self . '&update_now=1', 'fa-cloud-arrow-down', 'secondary', ['usepost' => true]);

include('head.inc');
threatshield_print_messages($input_errors);
threatshield_display_tabs('feeds');
fs_view_switch(['dns' => gettext('DNS block lists'), 'allow' => gettext('Allowlist lists'), 'ip' => gettext('IP lists')], $view);

if ($view === 'ip' && ($cfg['ipbl_enable'] ?? 'off') !== 'on') {
	print_callout(htmlspecialchars(gettext('IP blocking is off: these lists only take effect after you turn it on below. The DoH resolver lists are used by "Block known DNS-over-HTTPS servers" in Settings.')), 'info');
} elseif ($view === 'allow') {
	print_callout(htmlspecialchars(gettext('Lists of domains that must never be blocked, maintained by others. For your own exceptions use the Allowlist tab.')), 'info');
}
?>

<div class="fs-tiles">
<?php
fs_tile(gettext('Lists in use'), sprintf(gettext('%1$d of %2$d'), $enabled_count, count($feeds)));
fs_tile(($view === 'ip') ? gettext('Addresses loaded') : gettext('Rules loaded'), number_format($rules_total));
if ($view === 'dns') {
	$levels = threatshield_feed_levels();
	fs_tile(gettext('Protection level'), ($cfg['feed_level'] ?? 'custom') === 'custom' ? gettext('Custom') : $levels[$cfg['feed_level']][0]);
}
fs_tile(gettext('Last download'), threatshield_age($last), null, ($last > 0) ? date('Y-m-d H:i', $last) : null);
?>
</div>

<form method="post" action="<?=htmlspecialchars($self)?>">
<div class="panel panel-default fs-table">
<?php fs_table_toolbar([
	'title' => ($view === 'ip') ? gettext('IP lists') : (($view === 'allow') ? gettext('Allowlist lists') : gettext('DNS block lists')),
	'search' => gettext('Search lists…'),
	'noun' => gettext('lists'),
	'noun_one' => gettext('list'),
	'bulk' => [
		['name' => 'bulk_on', 'label' => gettext('Turn on'), 'icon' => 'fa-toggle-on', 'value' => '1'],
		['name' => 'bulk_off', 'label' => gettext('Turn off'), 'icon' => 'fa-toggle-off', 'value' => '1'],
		['name' => 'bulk_delete', 'label' => gettext('Delete'), 'icon' => 'fa-trash-can', 'variant' => 'danger', 'value' => '1',
		 'confirm' => gettext('Delete the selected lists?')],
	],
]); ?>
	<div class="panel-body table-responsive">
		<table class="table table-hover" data-sortable>
			<thead>
				<tr>
					<th class="fs-col-select"><input type="checkbox" data-fs-select-all aria-label="<?=gettext('Select all')?>"></th>
					<th class="fs-col-status"><?=gettext('Status')?></th>
					<th data-fs-search><?=gettext('Name')?></th>
					<th data-fs-search><?=gettext('Source')?></th>
					<th class="ts-num"><?=($view === 'ip') ? gettext('Addresses') : gettext('Rules')?></th>
					<th><?=gettext('Downloaded')?></th>
					<th class="fs-col-actions" data-sortable="false"><span class="visually-hidden"><?=gettext('Actions')?></span></th>
				</tr>
			</thead>
			<tbody>
<?php
$state_badge = [
	'ok' => ['pass', gettext('OK')], 'pending' => ['pending', gettext('Waiting')], 'failing' => ['error', gettext('Failing')],
	'stale' => ['warn', gettext('Outdated')], 'empty' => ['warn', gettext('No rules')],
];
foreach ($feeds as $f):
	$id = (string)($f['id'] ?? '');
	$name = (string)($f['name'] ?? '');
	$url = (string)($f['url'] ?? '');
	$on = (($f['enabled'] ?? '') === 'on');
	$h = $health[$url] ?? ['state' => 'pending'];
	[$badge, $badge_label] = $on ? ($state_badge[$h['state']] ?? $state_badge['pending']) : ['disabled', gettext('Off')];
	$count = ($view === 'ip') ? ($h['entries'] ?? null) : ($h['rules'] ?? null);
	$fill = ['feed_id' => $id, 'feed_name' => $name, 'feed_url' => $url, 'feed_category' => (string)($f['category'] ?? ''),
	    'feed_direction' => (string)($f['direction'] ?? 'in'), 'feed_log' => (($f['log'] ?? 'on') === 'on')];
?>
				<tr<?=$on ? '' : ' class="fs-row-disabled"'?>>
					<td><input type="checkbox" name="sel[]" value="<?=htmlspecialchars($id)?>" data-fs-select aria-label="<?=htmlspecialchars(sprintf(gettext('Select %s'), $name))?>"></td>
					<td><?=fs_badge($badge, $badge_label, (string)($h['error'] ?? ''))?></td>
					<td>
						<strong><?=htmlspecialchars($name)?></strong>
<?php	if ($view === 'ip'): ?>
						<span class="fs-chip"><?=htmlspecialchars((($f['kind'] ?? '') === 'doh') ? gettext('DoH resolvers') : ($directions[$f['direction'] ?? 'in'] ?? ''))?></span>
<?php	elseif (($f['category'] ?? '') !== ''): ?>
						<span class="fs-chip"><?=htmlspecialchars((string)$f['category'])?></span>
<?php	endif; ?>
<?php	if (!empty($h['error'])): ?>
						<div class="small text-danger"><?=htmlspecialchars((string)$h['error'])?></div>
<?php	endif; ?>
					</td>
					<td class="fs-mono small ts-break"><?=htmlspecialchars($url)?></td>
					<td class="ts-num"><?=($count === null) ? '<span class="fs-muted">–</span>' : number_format((int)$count)?></td>
					<td class="ts-nowrap">
<?php	if (!empty($h['last_success'])): ?>
						<?=htmlspecialchars(threatshield_age((int)$h['last_success']))?>
						<div class="fs-muted small"><?=htmlspecialchars(format_bytes((int)($h['bytes'] ?? 0)))?></div>
<?php	else: ?>
						<span class="fs-muted"><?=gettext('Not yet')?></span>
<?php	endif; ?>
					</td>
					<td class="fs-col-actions"><?=fs_row_actions([
						['edit', '#', $name, ['attrs' => ['data-fs-modal' => '#feed-edit', 'data-fs-fill' => json_encode($fill), 'data-fs-modal-title' => sprintf(gettext('Edit “%s”'), $name)]]],
						['toggle', $self . '&toggle=' . rawurlencode($id), $name, ['enabled' => $on]],
						['delete', $self . '&delete=' . rawurlencode($id), $name, ['thing' => gettext('list')]],
					])?></td>
				</tr>
<?php
endforeach;
if (empty($feeds)) {
	fs_empty_row(7, gettext('No lists here yet. Add one from the catalog below.'));
}
?>
			</tbody>
		</table>
	</div>
</div>
</form>

<?php if (!empty($available)): ?>
<div class="panel panel-default fs-table">
<?php fs_table_toolbar(['title' => gettext('Catalog'), 'search' => false, 'noun' => gettext('lists')]); ?>
	<div class="panel-body table-responsive">
		<table class="table table-hover">
			<tbody>
<?php	foreach ($available as $preset => $c): ?>
				<tr>
					<td><strong><?=htmlspecialchars($c['name'])?></strong>
<?php		if (!empty($c['levels'])): ?>
						<span class="fs-chip"><?=htmlspecialchars(implode(', ', array_map(fn($l) => threatshield_feed_levels()[$l][0], $c['levels'])))?></span>
<?php		endif; ?>
						<div class="fs-mono small fs-muted ts-break"><?=htmlspecialchars($c['url'])?></div></td>
					<td class="ts-nowrap text-end"><a class="btn btn-sm btn-outline-secondary" usepost href="<?=htmlspecialchars($self . '&add_preset=' . rawurlencode($preset))?>">
						<i class="fa-solid fa-plus icon-embed-btn" aria-hidden="true"></i><?=gettext('Add')?></a></td>
				</tr>
<?php	endforeach; ?>
			</tbody>
		</table>
	</div>
</div>
<?php endif; ?>

<form method="post" action="<?=htmlspecialchars($self)?>" class="ts-options">
<div class="panel panel-default">
	<div class="panel-heading"><h2 class="panel-title"><?=($view === 'ip') ? gettext('IP blocking') : gettext('Automatic updates')?></h2></div>
	<div class="panel-body">
<?php if ($view === 'ip'): ?>
		<div class="form-group">
			<label class="col-sm-2 control-label"><?=gettext('IP blocking')?></label>
			<div class="col-sm-10">
				<label class="form-check"><input class="form-check-input" type="checkbox" name="ipbl_enable"<?=(($cfg['ipbl_enable'] ?? 'off') === 'on') ? ' checked' : ''?>> <?=gettext('Block the addresses of the lists that are turned on')?></label>
				<span class="form-text help-block"><?=gettext('Private, local and firewall addresses are never blocked; entries on the IP allowlist are cut out of every list.')?></span>
			</div>
		</div>
		<div class="form-group">
			<label class="col-sm-2 control-label"><?=gettext('Inbound on')?></label>
			<div class="col-sm-10"><?=threatshield_iface_checks('ipbl_wan_interfaces', $assigned, array_map('strval', threatshield_normalize_list($cfg['ipbl_wan_interfaces'] ?? [])))?>
				<span class="form-text help-block"><?=gettext('WAN interfaces where listed sources are dropped.')?></span></div>
		</div>
		<div class="form-group">
			<label class="col-sm-2 control-label"><?=gettext('Outbound from')?></label>
			<div class="col-sm-10"><?=threatshield_iface_checks('ipbl_lan_interfaces', $assigned, array_map('strval', threatshield_normalize_list($cfg['ipbl_lan_interfaces'] ?? [])))?>
				<span class="form-text help-block"><?=gettext('LAN interfaces whose clients may not connect to listed addresses (botnet control servers, for example).')?></span></div>
		</div>
<?php endif; ?>
		<div class="form-group">
			<label class="col-sm-2 control-label" for="interval"><?=gettext('Download')?></label>
			<div class="col-sm-10">
				<select name="<?=($view === 'ip') ? 'ipbl_update_interval' : 'feed_update_interval'?>" id="interval" class="form-select ts-interval">
<?php	$current = (string)($cfg[($view === 'ip') ? 'ipbl_update_interval' : 'feed_update_interval'] ?? 'daily');
	foreach ($intervals as $value => $text): ?>
					<option value="<?=$value?>"<?=($current === $value) ? ' selected' : ''?>><?=htmlspecialchars($text)?></option>
<?php	endforeach; ?>
				</select>
				<span class="form-text help-block"><?=gettext('Lists are downloaded in the background; filtering keeps working with the previous copy if a download fails.')?></span>
			</div>
		</div>
	</div>
</div>
<div class="fs-actionbar fs-actionbar--plain">
	<button type="submit" name="save_options" value="1" class="btn btn-primary"><i class="fa-solid fa-floppy-disk icon-embed-btn" aria-hidden="true"></i><?=gettext('Save')?></button>
</div>
</form>

<?php
fs_modal_form_begin('feed-edit', gettext('Add list'), $self, [], ($input_errors && isset($_POST['save_feed']))
    ? ['feed_id' => (string)($_POST['feed_id'] ?? ''), 'feed_name' => (string)($_POST['feed_name'] ?? ''), 'feed_url' => (string)($_POST['feed_url'] ?? ''),
       'feed_category' => (string)($_POST['feed_category'] ?? '')]
    : null);
?>
	<input type="hidden" name="feed_id" value="">
	<div class="mb-3">
		<label class="form-label" for="feed_name"><?=gettext('Name')?></label>
		<input type="text" class="form-control" id="feed_name" name="feed_name" required>
	</div>
	<div class="mb-3">
		<label class="form-label" for="feed_url"><?=gettext('URL')?></label>
		<input type="url" class="form-control fs-mono" id="feed_url" name="feed_url" placeholder="https://…" required>
		<div class="form-text"><?=($view === 'ip') ? gettext('HTTPS only. One IP address or network per line; text after # or ; is ignored.') : gettext('HTTPS only. Hosts files and AdGuard / Adblock Plus lists are supported.')?></div>
	</div>
<?php if ($view === 'ip'): ?>
	<div class="mb-3">
		<label class="form-label" for="feed_direction"><?=gettext('Direction')?></label>
		<select class="form-select" id="feed_direction" name="feed_direction">
<?php	foreach ($directions as $value => $text): ?>
			<option value="<?=$value?>"><?=htmlspecialchars($text)?></option>
<?php	endforeach; ?>
		</select>
	</div>
	<label class="form-check"><input class="form-check-input" type="checkbox" name="feed_log" checked> <?=gettext('Log blocked packets')?></label>
<?php else: ?>
	<div class="mb-3">
		<label class="form-label" for="feed_category"><?=gettext('Category')?></label>
		<input type="text" class="form-control" id="feed_category" name="feed_category" placeholder="<?=gettext('Custom')?>">
	</div>
<?php endif; ?>
<?php
fs_modal_form_end(gettext('Save list'), 'save_feed', '1', 'fa-floppy-disk');

if ($view === 'dns'):
	fs_modal_form_begin('level-pick', gettext('Protection level'), $self);
	$level_now = (string)($cfg['feed_level'] ?? 'custom');
?>
	<p class="fs-muted"><?=gettext('Turns the curated lists for a level on and the others off. Lists you added yourself are kept as they are.')?></p>
	<div class="ts-levels">
<?php	foreach (threatshield_feed_levels() as $level => [$label, $text]):
		$names = array_map(fn($c) => $c['name'], array_filter(threatshield_feed_catalog(), fn($c) => in_array($level, $c['levels'], true)));
?>
		<button type="submit" name="set_level" value="<?=$level?>" class="ts-level<?=($level === $level_now) ? ' is-current' : ''?>">
			<strong><?=htmlspecialchars($label)?><?=($level === $level_now) ? ' · ' . gettext('current') : ''?></strong>
			<span class="fs-muted small"><?=htmlspecialchars($text)?></span>
			<span class="small"><?=htmlspecialchars(implode(', ', $names))?></span>
		</button>
<?php	endforeach; ?>
	</div>
	</div><div class="modal-footer"><button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal"><?=gettext('Cancel')?></button></div></form></div></div></div>
<?php
endif;
threatshield_ui_styles();
?>
<style>
.ts-interval { max-width: 24rem; }
.ts-levels { display: flex; flex-direction: column; gap: var(--fs-sp-2); }
.ts-level { display: flex; flex-direction: column; gap: .2rem; text-align: left; padding: var(--fs-sp-3); border: 1px solid var(--fs-border);
	border-radius: var(--fs-r-md); background: var(--fs-surface); color: inherit; }
.ts-level:hover, .ts-level:focus-visible { border-color: var(--fs-coral); }
.ts-level.is-current { border-color: color-mix(in srgb, var(--fs-pass) 50%, transparent); background: color-mix(in srgb, var(--fs-pass) 8%, transparent); }
</style>

<?php include('foot.inc'); ?>
