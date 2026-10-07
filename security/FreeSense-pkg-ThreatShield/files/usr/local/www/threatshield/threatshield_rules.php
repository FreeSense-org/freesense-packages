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

/* rule counts of the saved rules */
$counts = ['block' => 0, 'allow' => 0, 'comment' => 0];
foreach (preg_split('/\r?\n/', (string)($ts_config['custom_rules'] ?? '')) as $line) {
	$line = trim($line);
	if ($line === '') continue;
	if ($line[0] === '!' || $line[0] === '#') $counts['comment']++;
	elseif (strncmp($line, '@@', 2) === 0) $counts['allow']++;
	else $counts['block']++;
}

$pgtitle = [gettext('Services'), gettext('Threat Shield'), gettext('Custom rules')];
$pglinks = ['', '/threatshield/threatshield_status.php', '@self'];

fs_page_action(gettext('Query log'), 'threatshield_querylog.php', 'fa-list-check', 'secondary');

include('head.inc');

if ($input_errors) print_input_errors($input_errors);

if ($savemsg) {
	print_info_box($savemsg, 'success');
}

threatshield_display_tabs('rules');
?>

<div class="fs-tiles">
<?php
fs_tile(gettext('Block rules'), $counts['block']);
fs_tile(gettext('Allow rules'), $counts['allow']);
fs_tile(gettext('Comments'), $counts['comment']);
?>
</div>

<?php
$save = new Form_Button('save_rules', 'Save', null, 'fa-solid fa-floppy-disk');
$save->addClass('btn-primary');
$form = new Form($save);

$section = new Form_Section('Rules');
$section->addInput(new Form_Textarea('custom_rules', 'Custom rules', (string)$ts_config['custom_rules']))
	->setRows(14)->addClass('fs-mono')->setNoWrap()
	->setAttribute('placeholder', "||bad-tracker.com^\n@@||allowed-site.com^\n/^ads?[0-9]*\\./")
	->setAttribute('spellcheck', 'false')
	->setHelp('One rule per line, in AdGuard / Adblock Plus syntax, as regular expressions or in hosts-file format. ' .
	    'Lines starting with ! or # are comments. Allow rules override every feed.');
$form->add($section);

print($form);
?>

<div class="panel panel-default fs-table">
<?php fs_table_toolbar(['title' => gettext('Syntax examples'), 'search' => false, 'noun' => gettext('examples')]); ?>
	<div class="panel-body table-responsive">
		<table class="table">
			<thead>
				<tr>
					<th><?=gettext('Rule')?></th>
					<th><?=gettext('Effect')?></th>
				</tr>
			</thead>
			<tbody>
<?php foreach ([
	['||example.org^', 'block', gettext('Blocks example.org and all its subdomains (api.example.org, ads.example.org).')],
	['@@||trusted.com^', 'pass', gettext('Allows trusted.com and its subdomains, even when a feed blocks them.')],
	['|https://bad.com/', 'block', gettext('Blocks addresses that start exactly like this URL.')],
	['/^ads?[0-9]*\./', 'block', gettext('Blocks domains matching the regular expression (ad1.server.com, ads42.net).')],
	['127.0.0.1 tracker.com', 'info', gettext('Hosts-file format: answers tracker.com with the given address.')],
	['! comment', 'neutral', gettext('A comment; ignored.')],
] as list($rule, $state, $text)): ?>
				<tr>
					<td class="ts-rule"><code><?=htmlspecialchars($rule)?></code></td>
					<td><?=fs_badge($state, ['block' => gettext('Block'), 'pass' => gettext('Allow'), 'info' => gettext('Hosts'), 'neutral' => gettext('Comment')][$state])?> <?=htmlspecialchars($text)?></td>
				</tr>
<?php endforeach; ?>
			</tbody>
		</table>
	</div>
</div>

<style>
.ts-rule { white-space: nowrap; width: 1%; }
#custom_rules { overflow-x: auto; }
</style>

<?php include('foot.inc'); ?>
