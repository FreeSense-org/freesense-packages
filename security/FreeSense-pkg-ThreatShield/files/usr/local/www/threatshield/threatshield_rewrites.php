<?php
/*
 * threatshield_rewrites.php
 * FreeSense Threat Shield - Local DNS Rewrites & Host Overrides
 */

##|+PRIV
##|*IDENT=page-services-threatshield
##|*NAME=Services: Threat Shield Rewrites
##|*DESCR=Configure custom DNS rewrites and local host overrides
##|*MATCH=threatshield/threatshield_rewrites.php*
##|-PRIV

require_once('guiconfig.inc');
require_once('/usr/local/pkg/threatshield.inc');

$input_errors = [];
$savemsg = null;
$ts_config = threatshield_config();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
	if (isset($_POST['add_rewrite'])) {
		$domain = trim($_POST['domain'] ?? '');
		$answer = trim($_POST['answer'] ?? '');

		if ($domain === '' || $answer === '') {
			$input_errors[] = gettext('Both domain name and target IP address/host must be specified.');
		} else {
			$ts_config['rewrites'][] = [
				'domain' => $domain,
				'answer' => $answer
			];
			if (threatshield_save_and_apply($ts_config, gettext('Added a Threat Shield DNS rewrite.'), $input_errors)) $savemsg = sprintf(gettext('DNS rewrite for "%s" added.'), htmlspecialchars($domain));
		}
	} elseif (isset($_POST['delete_rewrite'])) {
		$del_idx = (int)$_POST['delete_rewrite'];
		if (isset($ts_config['rewrites'][$del_idx])) {
			$d = $ts_config['rewrites'][$del_idx]['domain'];
			array_splice($ts_config['rewrites'], $del_idx, 1);
			if (threatshield_save_and_apply($ts_config, gettext('Deleted a Threat Shield DNS rewrite.'), $input_errors)) $savemsg = sprintf(gettext('DNS rewrite for "%s" removed.'), htmlspecialchars($d));
		}
	}
}

$pgtitle = [gettext('Services'), gettext('Threat Shield'), gettext('DNS Rewrites')];
$pglinks = ['', '@self', '@self'];

include('head.inc');

if ($input_errors) {
	print_input_errors($input_errors);
}
if ($savemsg) {
	print_info_box($savemsg, 'success');
}

threatshield_display_tabs('rewrites');
?>

<div class="d-flex flex-wrap justify-content-between align-items-center gap-3 mb-3">
	<div>
		<h2 class="h3 mb-1"><i class="fa-solid fa-arrow-right-arrow-left text-primary me-2"></i><?=gettext('Local DNS Rewrites & Host Overrides')?></h2>
		<p class="text-muted mb-0"><?=gettext('Configure authoritative local host mappings, wildcards, and CNAME/A/AAAA aliases.')?></p>
	</div>
</div>

<div class="card shadow-sm mb-3">
	<div class="card-header bg-light">
		<h2 class="h5 mb-0"><i class="fa-solid fa-table-list text-primary me-2"></i><?=gettext('Configured DNS Rewrites')?></h2>
	</div>
	<div class="card-body p-0">
		<div class="table-responsive">
			<table class="table table-striped table-hover align-middle mb-0">
				<thead>
					<tr>
						<th><?=gettext('Domain / Hostname Pattern')?></th>
						<th><?=gettext('Rewrite Target (IPv4, IPv6, or Canonical Host)')?></th>
						<th class="text-end"><?=gettext('Actions')?></th>
					</tr>
				</thead>
				<tbody>
					<?php if (empty($ts_config['rewrites'])): ?>
						<tr><td colspan="3" class="text-center text-muted py-3"><?=gettext('No custom DNS rewrites configured.')?></td></tr>
					<?php else: ?>
						<?php foreach ($ts_config['rewrites'] as $idx => $rw): ?>
							<tr>
								<td class="font-monospace fw-semibold"><?=htmlspecialchars((string)$rw['domain'])?></td>
								<td class="font-monospace text-primary"><?=htmlspecialchars((string)$rw['answer'])?></td>
								<td class="text-end">
									<form method="post" class="d-inline">
										<button type="submit" name="delete_rewrite" value="<?=$idx?>" class="btn btn-sm btn-outline-danger" onclick="return confirm('<?=gettext('Delete this rewrite?')?>');" title="<?=gettext('Delete Rewrite')?>">
											<i class="fa-solid fa-trash"></i> <?=gettext('Delete')?>
										</button>
									</form>
								</td>
							</tr>
						<?php endforeach; ?>
					<?php endif; ?>
				</tbody>
			</table>
		</div>
	</div>
</div>

<div class="card shadow-sm mb-4">
	<div class="card-header bg-light">
		<h2 class="h5 mb-0"><i class="fa-solid fa-plus text-primary me-2"></i><?=gettext('Add New DNS Rewrite')?></h2>
	</div>
	<div class="card-body">
		<form method="post" action="threatshield_rewrites.php" class="row g-3">
			<div class="col-md-5">
				<label class="form-label fw-semibold"><?=gettext('Domain Name / FQDN')?></label>
				<input type="text" name="domain" class="form-control font-monospace" placeholder="e.g., nas.home.arpa or *.internal.lan" required>
			</div>
			<div class="col-md-5">
				<label class="form-label fw-semibold"><?=gettext('Target IP Address or Hostname')?></label>
				<input type="text" name="answer" class="form-control font-monospace" placeholder="e.g., 192.168.1.50 or router.local" required>
			</div>
			<div class="col-md-2 d-flex align-items-end">
				<button type="submit" name="add_rewrite" value="1" class="btn btn-success w-100">
					<i class="fa-solid fa-plus me-1"></i> <?=gettext('Add Rewrite')?>
				</button>
			</div>
		</form>
	</div>
</div>

<?php include('foot.inc'); ?>
