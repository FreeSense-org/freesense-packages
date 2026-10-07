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

$rewrites = threatshield_normalize_list($ts_config['rewrites'] ?? []);
/* answer type for the badge column */
$answer_type = function ($answer) {
	if (filter_var($answer, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) return 'A';
	if (filter_var($answer, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) return 'AAAA';
	return 'CNAME';
};

$pgtitle = [gettext('Services'), gettext('Threat Shield'), gettext('Rewrites')];
$pglinks = ['', '/threatshield/threatshield_status.php', '@self'];

fs_page_action(gettext('Add rewrite'), '#', 'fa-plus', 'primary', ['data-fs-modal' => '#rewrite-add']);

include('head.inc');

if ($input_errors) {
	print_input_errors($input_errors);
}
if ($savemsg) {
	print_info_box($savemsg, 'success');
}

threatshield_display_tabs('rewrites');
?>

<div class="panel panel-default fs-table">
<?php fs_table_toolbar([
	'title' => gettext('DNS rewrites'),
	'search' => gettext('Search rewrites…'),
	'noun' => gettext('rewrites'),
	'noun_one' => gettext('rewrite'),
	'filters' => ['type' => [gettext('All types'), 'A' => 'A (IPv4)', 'AAAA' => 'AAAA (IPv6)', 'CNAME' => gettext('CNAME (host name)')]],
]); ?>
	<div class="panel-body table-responsive">
		<table class="table table-hover" data-sortable>
			<thead>
				<tr>
					<th data-fs-search><?=gettext('Domain')?></th>
					<th><?=gettext('Type')?></th>
					<th data-fs-search><?=gettext('Answer')?></th>
					<th class="fs-col-actions" data-sortable="false"><span class="visually-hidden"><?=gettext('Actions')?></span></th>
				</tr>
			</thead>
			<tbody>
<?php
foreach ($rewrites as $idx => $rw):
	$domain = (string)($rw['domain'] ?? '');
	$answer = (string)($rw['answer'] ?? '');
	$type = $answer_type($answer);
?>
				<tr data-fs-filter-type="<?=$type?>">
					<td class="fs-mono">
						<?=htmlspecialchars($domain)?>
<?php	if (strncmp($domain, '*.', 2) === 0): ?>
						<?=fs_badge('info', gettext('Wildcard'))?>
<?php	endif; ?>
					</td>
					<td><span class="fs-chip fs-chip--mono fs-chip--strong"><?=$type?></span></td>
					<td class="fs-mono"><?=htmlspecialchars($answer)?></td>
					<td class="fs-col-actions"><?=fs_row_actions([
						['delete', 'threatshield_rewrites.php?delete_rewrite=' . (int)$idx, $domain, ['thing' => gettext('rewrite')]],
					])?></td>
				</tr>
<?php
endforeach;
if (empty($rewrites)) {
	fs_empty_row(4, gettext('No DNS rewrites yet.'));
}
?>
			</tbody>
		</table>
	</div>
	<div class="panel-footer small fs-muted">
		<i class="fa-solid fa-circle-info" aria-hidden="true"></i>
		<?=gettext('Threat Shield answers these names itself. *.example.lan matches every subdomain; an IP address answers A/AAAA, a host name answers as an alias (CNAME).')?>
	</div>
</div>

<?php
fs_modal_form_begin('rewrite-add', gettext('Add DNS rewrite'), 'threatshield_rewrites.php', [], ($input_errors && isset($_POST['add_rewrite']))
    ? ['domain' => (string)($_POST['domain'] ?? ''), 'answer' => (string)($_POST['answer'] ?? '')]
    : null);
?>
	<div class="mb-3">
		<label class="form-label" for="domain"><?=gettext('Domain')?></label>
		<input type="text" class="form-control fs-mono" id="domain" name="domain" placeholder="nas.home.arpa, *.internal.lan" required>
		<div class="form-text"><?=gettext('A host name, or *.domain for all its subdomains.')?></div>
	</div>
	<div class="mb-3">
		<label class="form-label" for="answer"><?=gettext('Answer')?></label>
		<input type="text" class="form-control fs-mono" id="answer" name="answer" placeholder="192.168.1.50, router.local" required>
		<div class="form-text"><?=gettext('An IPv4 or IPv6 address, or another host name.')?></div>
	</div>
<?php
fs_modal_form_end(gettext('Add rewrite'), 'add_rewrite', '1', 'fa-plus');
?>

<?php include('foot.inc'); ?>
