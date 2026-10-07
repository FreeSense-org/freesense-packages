<?php
require_once('guiconfig.inc'); require_once('/usr/local/pkg/crowdsec/crowdsec.inc'); $pgtitle=[gettext('Services'),gettext('CrowdSec'),gettext('Decisions')]; $pglinks=['','/crowdsec/crowdsec.php','@self'];
$savemsg = null; $input_errors = [];
if($_SERVER['REQUEST_METHOD']==='POST'&&isset($_POST['delete'])){ $id=(string)($_POST['id']??''); if(ctype_digit($id)) { crowdsec_cscli('decisions delete --id '.escapeshellarg($id).' 2>&1',$delete_output,$delete_rc); if ($delete_rc === 0) $savemsg = gettext('Decision removed. The address is unblocked within a minute.'); else $input_errors[] = gettext('The decision could not be removed.'); } }
$running=is_process_running('crowdsec'); $decisions=crowdsec_decisions(); $failed=$running&&$decisions===null; $decisions=$decisions??[];

/* a decision field, accepting both the lower- and upper-case keys of the cscli releases */
$field = function (array $d, $key) {
	return (string)($d[$key] ?? $d[ucfirst($key)] ?? '');
};
$origins = [];
$scenarios = [];
foreach ($decisions as $d) {
	$o = $field($d, 'origin');
	if ($o !== '') $origins[$o] = ($origins[$o] ?? 0) + 1;
	$s = $field($d, 'scenario');
	if ($s !== '') $scenarios[$s] = true;
}
ksort($origins);

fs_page_action(gettext('Refresh'), 'crowdsec_decisions.php', 'fa-arrows-rotate', 'secondary');

include('head.inc');
if ($input_errors) print_input_errors($input_errors);
if ($savemsg) print_info_box($savemsg, 'success');
$tabs=[[gettext('Overview'),false,'/crowdsec/crowdsec.php'],[gettext('Decisions'),true,'/crowdsec/crowdsec_decisions.php']]; display_top_tabs($tabs);
if(!$running) print_info_box(gettext('CrowdSec is not running, so no decisions can be shown.'),'warning',false); elseif($failed) print_info_box(gettext('Could not read the CrowdSec decisions.'),'danger',false);
?>

<div class="fs-tiles">
<?php
fs_tile(gettext('Active decisions'), count($decisions));
fs_tile(gettext('Scenarios'), count($scenarios));
fs_tile(gettext('Origins'), count($origins), null, $origins ? implode(', ', array_map(function ($o, $n) { return "{$o} {$n}"; }, array_keys($origins), $origins)) : null);
?>
</div>

<div class="panel panel-default fs-table">
<?php fs_table_toolbar([
	'title' => gettext('Active decisions'),
	'search' => gettext('Search addresses, scenarios…'),
	'noun' => gettext('decisions'),
	'noun_one' => gettext('decision'),
	'filters' => (count($origins) > 1) ? ['origin' => array_merge([gettext('All origins')], array_combine(array_keys($origins), array_keys($origins)))] : [],
]); ?>
	<div class="panel-body table-responsive">
		<table class="table table-hover" data-sortable>
			<thead>
				<tr>
					<th data-fs-search><?=gettext('Value')?></th>
					<th><?=gettext('Action')?></th>
					<th data-fs-search><?=gettext('Reason')?></th>
					<th data-fs-search><?=gettext('Origin')?></th>
					<th><?=gettext('Expires in')?></th>
					<th class="fs-col-actions" data-sortable="false"><span class="visually-hidden"><?=gettext('Actions')?></span></th>
				</tr>
			</thead>
			<tbody>
<?php
foreach ($decisions as $d):
	$id = (string)($d['id'] ?? $d['ID'] ?? '');
	$value = $field($d, 'value');
	$scope = $field($d, 'scope');
	$type = $field($d, 'type');
	$origin = $field($d, 'origin');
?>
				<tr data-fs-filter-origin="<?=htmlspecialchars($origin)?>">
					<td>
						<span class="fs-mono"><?=htmlspecialchars($value)?></span>
<?php	if ($scope !== '' && strcasecmp($scope, 'ip') !== 0): ?>
						<span class="fs-chip fs-chip--muted"><?=htmlspecialchars($scope)?></span>
<?php	endif; ?>
					</td>
					<td><?=($type === '' || strcasecmp($type, 'ban') === 0) ? fs_badge('block', ($type === '') ? gettext('Ban') : ucfirst($type)) : fs_badge('warn', ucfirst($type))?></td>
					<td><?=htmlspecialchars($field($d, 'scenario'))?></td>
					<td><span class="fs-chip"><?=htmlspecialchars($origin)?></span></td>
					<td class="fs-mono"><?=htmlspecialchars($field($d, 'duration'))?></td>
					<td class="fs-col-actions"><?=ctype_digit($id) ? fs_row_actions([
						['custom', 'crowdsec_decisions.php?delete=1&id=' . $id, $value, [
							'icon' => 'fa-solid fa-trash-can', 'post' => true,
							'label' => sprintf(gettext('Remove decision for %s'), $value),
							'confirm' => sprintf(gettext('Remove the decision for “%s”?'), $value),
							'detail' => gettext('The address is no longer blocked. CrowdSec may decide again if the behaviour continues.'),
							'confirm_action' => gettext('Remove'),
							'attrs' => ['class' => 'fs-action fs-action--delete'],
						]],
					]) : ''?></td>
				</tr>
<?php
endforeach;
if (empty($decisions)) {
	fs_empty_row(6, $running ? gettext('No active decisions. Nothing is blocked by CrowdSec right now.') : gettext('No decisions while CrowdSec is not running.'));
}
?>
			</tbody>
		</table>
	</div>
</div>
<?php include('foot.inc'); ?>
