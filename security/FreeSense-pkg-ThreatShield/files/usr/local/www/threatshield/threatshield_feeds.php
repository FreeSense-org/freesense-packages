<?php
/*
 * threatshield_feeds.php
 * FreeSense Threat Shield - DNS Threat Blocklists & Automated Schedule
 */

##|+PRIV
##|*IDENT=page-services-threatshield
##|*NAME=Services: Threat Shield Feeds
##|*DESCR=Manage Threat Shield DNS threat blocklists and automated updates
##|*MATCH=threatshield/threatshield_feeds.php*
##|-PRIV

require_once('guiconfig.inc');
require_once('/usr/local/pkg/threatshield.inc');

$input_errors = [];
$savemsg = null;
$ts_config = threatshield_config();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
	if (isset($_POST['save_feeds'])) {
		$ts_config['feed_update_interval'] = $_POST['feed_update_interval'] ?? 'daily';

		// Update enabled statuses
		if (!empty($ts_config['feeds']) && is_array($ts_config['feeds'])) {
			foreach ($ts_config['feeds'] as $idx => &$feed) {
				$feed['enabled'] = isset($_POST["feed_enable_{$idx}"]) ? 'on' : 'off';
			}
			unset($feed);
		}

		if (threatshield_save_and_apply($ts_config, gettext('Updated Threat Shield feed settings.'), $input_errors)) $savemsg = gettext('Feed settings saved successfully.');
	} elseif (isset($_POST['add_feed'])) {
		$name = trim($_POST['new_name'] ?? '');
		$url = trim($_POST['new_url'] ?? '');
		$cat = trim($_POST['new_category'] ?? 'Custom');

		if ($name === '' || $url === '') {
			$input_errors[] = gettext('A feed name and valid URL must be provided.');
		} elseif (!filter_var($url, FILTER_VALIDATE_URL) || strtolower((string)parse_url($url, PHP_URL_SCHEME)) !== 'https') {
			$input_errors[] = gettext('The entered feed URL must be a valid HTTPS URL.');
		} else {
			$ts_config['feeds'][] = [
				'name' => $name,
				'url' => $url,
				'enabled' => 'on',
				'category' => $cat
			];
			if (threatshield_save_and_apply($ts_config, gettext('Added a Threat Shield feed.'), $input_errors)) $savemsg = sprintf(gettext('Feed "%s" added and applied.'), htmlspecialchars($name));
		}
	} elseif (isset($_POST['delete_feed'])) {
		$del_idx = (int)$_POST['delete_feed'];
		if (isset($ts_config['feeds'][$del_idx])) {
			$name = $ts_config['feeds'][$del_idx]['name'];
			array_splice($ts_config['feeds'], $del_idx, 1);
			if (threatshield_save_and_apply($ts_config, gettext('Deleted a Threat Shield feed.'), $input_errors)) $savemsg = sprintf(gettext('Feed "%s" deleted.'), htmlspecialchars($name));
		}
	} elseif (isset($_POST['update_now'])) {
		mwexec_bg('/usr/local/sbin/freesense-threatshield-update feeds force');
		$savemsg = gettext('Feed download started in background.');
	}
}

$feeds = threatshield_normalize_list($ts_config['feeds'] ?? []);
$last_update = threatshield_last_update('feeds');
$categories = [];
$enabled_count = 0;
foreach ($feeds as $f) {
	$categories[(string)($f['category'] ?? 'General')] = (string)($f['category'] ?? 'General');
	if (($f['enabled'] ?? '') === 'on') $enabled_count++;
}
ksort($categories);

$pgtitle = [gettext('Services'), gettext('Threat Shield'), gettext('Feeds')];
$pglinks = ['', '/threatshield/threatshield_status.php', '@self'];

fs_page_action(gettext('Add feed'), '#', 'fa-plus', 'primary', ['data-fs-modal' => '#feed-add']);
fs_page_action(gettext('Download now'), 'threatshield_feeds.php?update_now=1', 'fa-cloud-arrow-down', 'secondary', ['usepost' => true]);

include('head.inc');

if ($input_errors) {
	print_input_errors($input_errors);
}
if ($savemsg) {
	print_info_box($savemsg, 'success');
}

threatshield_display_tabs('feeds');
?>

<div class="fs-tiles">
<?php
fs_tile(gettext('Enabled feeds'), sprintf(gettext('%1$d of %2$d'), $enabled_count, count($feeds)));
fs_tile(gettext('Last download'), threatshield_age($last_update), null, ($last_update > 0) ? date('Y-m-d H:i', $last_update) : null);
?>
</div>

<form method="post" action="threatshield_feeds.php" id="ts-feeds-form">
<div class="panel panel-default fs-table">
<?php fs_table_toolbar([
	'title' => gettext('Blocklists'),
	'search' => gettext('Search feeds…'),
	'noun' => gettext('feeds'),
	'noun_one' => gettext('feed'),
	'filters' => (count($categories) > 1) ? ['category' => array_merge([gettext('All categories')], $categories)] : [],
]); ?>
	<div class="panel-body table-responsive">
		<table class="table table-hover ts-feeds">
			<thead>
				<tr>
					<th class="ts-col-switch"><?=gettext('On')?></th>
					<th data-fs-search><?=gettext('Name')?></th>
					<th data-fs-search><?=gettext('Category')?></th>
					<th data-fs-search><?=gettext('Source')?></th>
					<th><?=gettext('Cached copy')?></th>
					<th class="fs-col-actions"><span class="visually-hidden"><?=gettext('Actions')?></span></th>
				</tr>
			</thead>
			<tbody>
<?php
foreach ($feeds as $idx => $f):
	$name = (string)($f['name'] ?? '');
	$url = (string)($f['url'] ?? '');
	$category = (string)($f['category'] ?? 'General');
	$on = (($f['enabled'] ?? '') === 'on');
	$cache = ($url !== '') ? threatshield_feed_path($url) : '';
	$cached = ($cache !== '' && is_file($cache));
?>
				<tr data-fs-filter-category="<?=htmlspecialchars($category)?>"<?=$on ? '' : ' class="fs-row-disabled"'?>>
					<td class="ts-col-switch">
						<div class="form-check form-switch">
							<input class="form-check-input" type="checkbox" role="switch" name="feed_enable_<?=(int)$idx?>" id="feed_enable_<?=(int)$idx?>"<?=$on ? ' checked' : ''?>
							    aria-label="<?=htmlspecialchars(sprintf(gettext('Use %s'), $name))?>">
						</div>
					</td>
					<td><strong><?=htmlspecialchars($name)?></strong></td>
					<td><span class="fs-chip"><?=htmlspecialchars($category)?></span></td>
					<td class="fs-mono small ts-url"><?=htmlspecialchars($url)?></td>
					<td class="ts-nowrap">
<?php	if ($cached): ?>
						<?=htmlspecialchars(format_bytes((int)filesize($cache)))?>
						<div class="fs-muted small"><?=htmlspecialchars(threatshield_age((int)filemtime($cache)))?></div>
<?php	else: ?>
						<span class="fs-muted"><?=gettext('Not downloaded')?></span>
<?php	endif; ?>
					</td>
					<td class="fs-col-actions"><?=fs_row_actions([
						['delete', 'threatshield_feeds.php?delete_feed=' . (int)$idx, $name, [
							'thing' => gettext('feed'),
							'detail' => gettext('Its domains are no longer blocked after the change is applied.'),
						]],
					])?></td>
				</tr>
<?php
endforeach;
if (empty($feeds)) {
	fs_empty_row(6, gettext('No feeds configured.'));
}
?>
			</tbody>
		</table>
	</div>
	<div class="panel-footer small fs-muted">
		<i class="fa-solid fa-circle-info" aria-hidden="true"></i>
		<?=gettext('Feeds are downloaded and merged in the background; DNS keeps answering meanwhile. Switch a feed off to keep it in the list without using it.')?>
	</div>
</div>

<div class="panel panel-default">
	<div class="panel-heading"><h2 class="panel-title"><?=gettext('Automatic updates')?></h2></div>
	<div class="panel-body">
		<div class="form-group">
			<label class="col-sm-2 control-label" for="feed_update_interval"><?=gettext('Download')?></label>
			<div class="col-sm-10">
				<select name="feed_update_interval" id="feed_update_interval" class="form-select ts-interval">
<?php foreach (['6hours' => gettext('Every 6 hours'), '12hours' => gettext('Every 12 hours'), 'daily' => gettext('Daily at 03:00 UTC (recommended)'), 'weekly' => gettext('Weekly')] as $value => $text): ?>
					<option value="<?=$value?>"<?=(($ts_config['feed_update_interval'] ?? '') === $value) ? ' selected' : ''?>><?=htmlspecialchars($text)?></option>
<?php endforeach; ?>
				</select>
				<span class="form-text help-block"><?=gettext('How often the enabled feeds are downloaded again.')?></span>
			</div>
		</div>
	</div>
</div>

<div class="fs-actionbar fs-actionbar--plain">
	<button type="submit" name="save_feeds" value="1" class="btn btn-primary"><i class="fa-solid fa-floppy-disk icon-embed-btn" aria-hidden="true"></i><?=gettext('Save')?></button>
	<span class="ts-dirty fs-muted small" hidden><i class="fa-solid fa-circle-exclamation" aria-hidden="true"></i><?=gettext('Changes are not saved yet.')?></span>
</div>
</form>

<?php
fs_modal_form_begin('feed-add', gettext('Add feed'), 'threatshield_feeds.php', [], $input_errors && isset($_POST['add_feed'])
    ? ['new_name' => (string)($_POST['new_name'] ?? ''), 'new_category' => (string)($_POST['new_category'] ?? ''), 'new_url' => (string)($_POST['new_url'] ?? '')]
    : null);
?>
	<div class="mb-3">
		<label class="form-label" for="new_name"><?=gettext('Name')?></label>
		<input type="text" class="form-control" id="new_name" name="new_name" placeholder="<?=gettext('Custom malware list')?>" required>
	</div>
	<div class="mb-3">
		<label class="form-label" for="new_category"><?=gettext('Category')?></label>
		<input type="text" class="form-control" id="new_category" name="new_category" value="Custom" list="ts-feed-categories">
		<datalist id="ts-feed-categories">
<?php foreach ($categories as $c): ?>
			<option value="<?=htmlspecialchars($c)?>"></option>
<?php endforeach; ?>
		</datalist>
	</div>
	<div class="mb-3">
		<label class="form-label" for="new_url"><?=gettext('URL')?></label>
		<input type="url" class="form-control fs-mono" id="new_url" name="new_url" placeholder="https://…" required>
		<div class="form-text"><?=gettext('HTTPS only. Hosts files and AdGuard / Adblock Plus lists are supported.')?></div>
	</div>
<?php
fs_modal_form_end(gettext('Add feed'), 'add_feed', '1', 'fa-plus');
?>

<style>
.ts-feeds .ts-col-switch { width: 3.5rem; }
.ts-feeds .ts-col-switch .form-check { margin: 0; min-height: 0; }
.ts-feeds .ts-url { word-break: break-all; min-width: 14rem; }
.ts-feeds .ts-nowrap { white-space: nowrap; }
.ts-interval { max-width: 24rem; }
.ts-dirty { display: inline-flex; align-items: center; gap: .4rem; margin-left: var(--fs-sp-3); }
.ts-dirty > i { color: var(--fs-coral); }
</style>
<script>
//<![CDATA[
events.push(function () {
	var form = document.getElementById('ts-feeds-form');
	var note = form.querySelector('.ts-dirty');
	form.addEventListener('change', function (e) {
		if (!e.target.name) {
			return;    /* list search and filter are not settings */
		}
		if (e.target.matches('input[name^="feed_enable_"]')) {
			e.target.closest('tr').classList.toggle('fs-row-disabled', !e.target.checked);
		}
		note.hidden = false;
	});
});
//]]>
</script>

<?php include('foot.inc'); ?>
