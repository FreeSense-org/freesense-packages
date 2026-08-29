<?php
/*
 * threatshield_rules.php
 * FreeSense Threat Shield - Custom Allow & Block Rules
 */

##|+PRIV
##|*IDENT=page-services-threatshield
##|*NAME=Services: Threat Shield Rules
##|*DESCR=Configure custom user filtering rules and whitelists
##|*MATCH=threatshield/threatshield_rules.php*
##|-PRIV

require_once('guiconfig.inc');
require_once('/usr/local/pkg/threatshield.inc');

$input_errors = [];
$savemsg = null;
$ts_config = threatshield_config();

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['save_rules'])) {
	$ts_config['custom_rules'] = trim($_POST['custom_rules'] ?? '');
	if (threatshield_save_and_apply($ts_config, gettext('Updated Threat Shield custom rules.'), $input_errors)) {
		$savemsg = gettext('Custom filtering rules saved and applied.');
	}
}

$pgtitle = [gettext('Services'), gettext('Threat Shield'), gettext('Custom Rules')];
$pglinks = ['', '@self', '@self'];

include('head.inc');

if ($input_errors) print_input_errors($input_errors);

if ($savemsg) {
	print_info_box($savemsg, 'success');
}

threatshield_display_tabs('rules');
?>

<div class="d-flex flex-wrap justify-content-between align-items-center gap-3 mb-3">
	<div>
		<h2 class="h3 mb-1"><i class="fa-solid fa-code text-primary me-2"></i><?=gettext('Custom Filtering Rules & Whitelists')?></h2>
		<p class="text-muted mb-0"><?=gettext('Define custom domain filters, regular expressions, and whitelist overrides using standard syntax.')?></p>
	</div>
</div>

<form method="post" action="threatshield_rules.php">
	<div class="card shadow-sm mb-3">
		<div class="card-header">
			<h2 class="h5 mb-0"><i class="fa-solid fa-pen-to-square text-primary me-2"></i><?=gettext('User-Defined Filtering Rules')?></h2>
		</div>
		<div class="card-body">
			<div class="mb-3">
				<label for="custom_rules" class="form-label fw-semibold"><?=gettext('Custom Rules (One rule per line)')?></label>
				<textarea class="form-control font-monospace" name="custom_rules" id="custom_rules" rows="14" placeholder="||bad-tracker.com^&#10;@@||allowed-site.com^&#10;/^ads?[0-9]*\./"><?=htmlspecialchars((string)$ts_config['custom_rules'])?></textarea>
				<div class="form-text"><?=gettext('Supports standard Adblock Plus and AdGuard filtering syntax, regular expressions, and hosts format.')?></div>
			</div>
		</div>
		<div class="card-footer">
			<button type="submit" name="save_rules" value="1" class="btn btn-primary"><i class="fa-solid fa-floppy-disk me-2"></i><?=gettext('Save Rules')?></button>
		</div>
	</div>
</form>

<div class="card shadow-sm mb-4">
	<div class="card-header">
		<h2 class="h5 mb-0"><i class="fa-solid fa-circle-question text-primary me-2"></i><?=gettext('Rule Syntax Reference & Examples')?></h2>
	</div>
	<div class="card-body p-0">
		<div class="table-responsive">
			<table class="table table-bordered table-striped mb-0">
				<thead>
					<tr>
						<th style="width: 250px;"><?=gettext('Pattern Example')?></th>
						<th><?=gettext('Description & Behavior')?></th>
					</tr>
				</thead>
				<tbody>
					<tr>
						<td class="font-monospace fw-bold"><code>||example.org^</code></td>
						<td><?=gettext('Blocks domain <strong>example.org</strong> and all its subdomains (e.g. <code>api.example.org</code>, <code>ads.example.org</code>).')?></td>
					</tr>
					<tr>
						<td class="font-monospace fw-bold text-success"><code>@@||trusted.com^</code></td>
						<td><?=gettext('Whitelists/unblocks domain <strong>trusted.com</strong> and subdomains, overriding any subscribed blocklists.')?></td>
					</tr>
					<tr>
						<td class="font-monospace fw-bold"><code>|https://bad.com/</code></td>
						<td><?=gettext('Blocks address matching the exact beginning of URL.')?></td>
					</tr>
					<tr>
						<td class="font-monospace fw-bold"><code>/^ads?[0-9]*\./</code></td>
						<td><?=gettext('Blocks domain matching regular expression pattern (e.g. <code>ad1.server.com</code>, <code>ads42.net</code>).')?></td>
					</tr>
					<tr>
						<td class="font-monospace fw-bold"><code>127.0.0.1 tracker.com</code></td>
						<td><?=gettext('Standard /etc/hosts file format mapping.')?></td>
					</tr>
				</tbody>
			</table>
		</div>
	</div>
</div>

<?php include('foot.inc'); ?>
