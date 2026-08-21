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

		config_set_path(THREATSHIELD_CONFIG_PATH, threatshield_config_for_storage($ts_config));
		write_config(gettext('Updated Threat Shield feed settings.'));
		threatshield_sync_config();
		$savemsg = gettext('Feed settings saved successfully.');
	} elseif (isset($_POST['add_feed'])) {
		$name = trim($_POST['new_name'] ?? '');
		$url = trim($_POST['new_url'] ?? '');
		$cat = trim($_POST['new_category'] ?? 'Custom');

		if ($name === '' || $url === '') {
			$input_errors[] = gettext('A feed name and valid URL must be provided.');
		} elseif (!filter_var($url, FILTER_VALIDATE_URL)) {
			$input_errors[] = gettext('The entered feed URL is not a valid HTTP/HTTPS URL.');
		} else {
			$ts_config['feeds'][] = [
				'name' => $name,
				'url' => $url,
				'enabled' => 'on',
				'category' => $cat
			];
			config_set_path(THREATSHIELD_CONFIG_PATH, threatshield_config_for_storage($ts_config));
			write_config(gettext("Added new Threat Shield feed: {$name}"));
			threatshield_sync_config();
			$savemsg = sprintf(gettext('Feed "%s" added and applied.'), htmlspecialchars($name));
		}
	} elseif (isset($_POST['delete_feed'])) {
		$del_idx = (int)$_POST['delete_feed'];
		if (isset($ts_config['feeds'][$del_idx])) {
			$name = $ts_config['feeds'][$del_idx]['name'];
			array_splice($ts_config['feeds'], $del_idx, 1);
			config_set_path(THREATSHIELD_CONFIG_PATH, threatshield_config_for_storage($ts_config));
			write_config(gettext("Deleted Threat Shield feed: {$name}"));
			threatshield_sync_config();
			$savemsg = sprintf(gettext('Feed "%s" deleted.'), htmlspecialchars($name));
		}
	} elseif (isset($_POST['update_now'])) {
		mwexec_bg('/usr/local/sbin/freesense-threatshield-update feeds');
		$savemsg = gettext('Feed download started in background.');
	}
}

$pgtitle = [gettext('Services'), gettext('Threat Shield'), gettext('DNS Feeds & Lists')];
$pglinks = ['', '@self', '@self'];

include('head.inc');

if ($input_errors) {
	print_input_errors($input_errors);
}
if ($savemsg) {
	print_info_box($savemsg, 'success');
}

threatshield_display_tabs('feeds');
?>

<div class="d-flex flex-wrap justify-content-between align-items-center gap-3 mb-3">
	<div>
		<h2 class="h3 mb-1"><i class="fa-solid fa-layer-group text-primary me-2"></i><?=gettext('DNS Threat Feeds & Blocklists')?></h2>
		<p class="text-muted mb-0"><?=gettext('Automated synchronization and deduplication of curated threat intelligence and ad/tracker feeds.')?></p>
	</div>
	<div class="d-flex gap-2">
		<form method="post" class="d-inline">
			<input type="hidden" name="update_now" value="1">
			<button type="submit" class="btn btn-outline-primary"><i class="fa-solid fa-cloud-arrow-down me-2"></i><?=gettext('Download Feeds Now')?></button>
		</form>
	</div>
</div>

<form method="post" action="threatshield_feeds.php">
	<div class="card shadow-sm mb-3">
		<div class="card-header bg-light">
			<h2 class="h5 mb-0"><i class="fa-solid fa-clock text-primary me-2"></i><?=gettext('Automated Feed Synchronization Schedule')?></h2>
		</div>
		<div class="card-body">
			<div class="row align-items-center g-3">
				<div class="col-md-6">
					<label for="feed_update_interval" class="form-label fw-semibold"><?=gettext('Automatic Download Interval')?></label>
					<select name="feed_update_interval" id="feed_update_interval" class="form-select">
						<option value="6hours" <?=$ts_config['feed_update_interval'] === '6hours' ? 'selected' : ''?>><?=gettext('Every 6 Hours')?></option>
						<option value="12hours" <?=$ts_config['feed_update_interval'] === '12hours' ? 'selected' : ''?>><?=gettext('Every 12 Hours')?></option>
						<option value="daily" <?=$ts_config['feed_update_interval'] === 'daily' ? 'selected' : ''?>><?=gettext('Daily (Recommended - 03:00 UTC)')?></option>
						<option value="weekly" <?=$ts_config['feed_update_interval'] === 'weekly' ? 'selected' : ''?>><?=gettext('Weekly')?></option>
					</select>
				</div>
				<div class="col-md-6">
					<div class="text-muted small mt-2">
						<?=gettext('Threat Shield downloads and deduplicates blocklists in the background without interrupting active DNS resolution.')?>
					</div>
				</div>
			</div>
		</div>
	</div>

	<div class="card shadow-sm mb-3">
		<div class="card-header bg-light">
			<h2 class="h5 mb-0"><i class="fa-solid fa-shield-virus text-primary me-2"></i><?=gettext('Subscribed DNS Threat Feeds')?></h2>
		</div>
		<div class="card-body p-0">
			<div class="table-responsive">
				<table class="table table-striped table-hover align-middle mb-0">
					<thead>
						<tr>
							<th style="width: 50px;" class="text-center"><?=gettext('Active')?></th>
							<th><?=gettext('Feed Name')?></th>
							<th><?=gettext('Category')?></th>
							<th><?=gettext('Feed Source URL')?></th>
							<th class="text-end"><?=gettext('Actions')?></th>
						</tr>
					</thead>
					<tbody>
						<?php if (empty($ts_config['feeds'])): ?>
							<tr><td colspan="5" class="text-center text-muted py-3"><?=gettext('No feeds configured.')?></td></tr>
						<?php else: ?>
							<?php foreach ($ts_config['feeds'] as $idx => $f): ?>
								<tr>
									<td class="text-center">
										<input class="form-check-input" type="checkbox" name="feed_enable_<?=$idx?>" <?=(!empty($f['enabled']) && $f['enabled'] === 'on') ? 'checked' : ''?>>
									</td>
									<td class="fw-semibold"><?=htmlspecialchars((string)$f['name'])?></td>
									<td><span class="badge bg-secondary"><?=htmlspecialchars((string)($f['category'] ?? 'General'))?></span></td>
									<td class="font-monospace text-break small text-muted"><?=htmlspecialchars((string)$f['url'])?></td>
									<td class="text-end">
										<button type="submit" name="delete_feed" value="<?=$idx?>" class="btn btn-sm btn-outline-danger" onclick="return confirm('<?=gettext('Are you sure you want to remove this feed?')?>');" title="<?=gettext('Delete Feed')?>">
											<i class="fa-solid fa-trash"></i>
										</button>
									</td>
								</tr>
							<?php endforeach; ?>
						<?php endif; ?>
					</tbody>
				</table>
			</div>
		</div>
		<div class="card-footer bg-light">
			<button type="submit" name="save_feeds" value="1" class="btn btn-primary"><i class="fa-solid fa-floppy-disk me-2"></i><?=gettext('Save Feed Settings')?></button>
		</div>
	</div>
</form>

<div class="card shadow-sm mb-4">
	<div class="card-header bg-light">
		<h2 class="h5 mb-0"><i class="fa-solid fa-plus text-primary me-2"></i><?=gettext('Add Custom DNS Threat Feed')?></h2>
	</div>
	<div class="card-body">
		<form method="post" action="threatshield_feeds.php" class="row g-3">
			<div class="col-md-4">
				<label class="form-label fw-semibold"><?=gettext('Feed Name')?></label>
				<input type="text" name="new_name" class="form-control" placeholder="e.g., Custom Malware List" required>
			</div>
			<div class="col-md-3">
				<label class="form-label fw-semibold"><?=gettext('Category')?></label>
				<input type="text" name="new_category" class="form-control" placeholder="e.g., Phishing, Ads" value="Custom">
			</div>
			<div class="col-md-5">
				<label class="form-label fw-semibold"><?=gettext('Feed URL')?></label>
				<div class="input-group">
					<input type="url" name="new_url" class="form-control font-monospace" placeholder="https://..." required>
					<button type="submit" name="add_feed" value="1" class="btn btn-success">
						<i class="fa-solid fa-plus me-1"></i><?=gettext('Add Feed')?>
					</button>
				</div>
			</div>
		</form>
	</div>
</div>

<?php include('foot.inc'); ?>
