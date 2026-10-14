<?php
/*
 * threatshield_rules.php
 * FreeSense Threat Shield - custom filtering rules and DNS rewrites
 *
 * Copyright (c) 2025-2026 The FreeSense Project.
 * Licensed under the Apache License, Version 2.0.
 */

##|+PRIV
##|*IDENT=page-services-threatshield
##|*NAME=Services: Threat Shield Rules
##|*DESCR=Configure custom filtering rules and DNS rewrites
##|*MATCH=threatshield/threatshield_rules.php*
##|-PRIV

require_once('guiconfig.inc');
require_once('/usr/local/pkg/threatshield.inc');
require_once('/usr/local/pkg/threatshield/threatshield_ui.inc');

$cfg = threatshield_config();
$view = fs_view_param(['custom', 'rewrites'], 'custom');
$self = 'threatshield_rules.php?view=' . $view;
$input_errors = [];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
	$changed = false;
	$message = '';
	$rewrites = threatshield_normalize_list($cfg['rewrites'] ?? []);
	if (isset($_POST['save_rules'])) {
		$cfg['custom_rules'] = trim((string)($_POST['custom_rules'] ?? ''));
		$changed = true;
		$message = gettext('Custom rules saved and applied.');
	} elseif (isset($_POST['save_rewrite'])) {
		$i = ($_POST['rewrite_index'] ?? '') === '' ? null : (int)$_POST['rewrite_index'];
		$rw = ['domain' => strtolower(trim((string)($_POST['domain'] ?? ''))), 'answer' => trim((string)($_POST['answer'] ?? '')),
		    'enabled' => ($i !== null && isset($rewrites[$i])) ? ($rewrites[$i]['enabled'] ?? 'on') : 'on'];
		if ($rw['domain'] === '' || $rw['answer'] === '') {
			$input_errors[] = gettext('A rewrite needs a domain and an answer.');
		} else {
			if ($i !== null && isset($rewrites[$i])) $rewrites[$i] = $rw; else $rewrites[] = $rw;
			$cfg['rewrites'] = $rewrites;
			$changed = true;
			$message = sprintf(gettext('Rewrite for %s saved.'), $rw['domain']);
		}
	} elseif (isset($_POST['toggle']) || isset($_POST['delete'])) {
		$i = (int)($_POST['toggle'] ?? $_POST['delete']);
		if (isset($rewrites[$i])) {
			$d = (string)($rewrites[$i]['domain'] ?? '');
			if (isset($_POST['delete'])) {
				array_splice($rewrites, $i, 1);
				$message = sprintf(gettext('Rewrite for %s removed.'), $d);
			} else {
				$rewrites[$i]['enabled'] = (($rewrites[$i]['enabled'] ?? 'on') === 'on') ? 'off' : 'on';
				$message = sprintf(gettext('Rewrite for %s changed.'), $d);
			}
			$cfg['rewrites'] = $rewrites;
			$changed = true;
		}
	}
	if ($changed && empty($input_errors)) {
		$errors = $warnings = [];
		if (threatshield_save_and_apply($cfg, gettext('Threat Shield: updated DNS rules'), $errors, $warnings)) {
			threatshield_flash('ok', $message);
			threatshield_flash('warn', $warnings);
		} else {
			$input_errors = $errors;
		}
	}
	if (empty($input_errors)) threatshield_redirect($self);
}

$pgtitle = [gettext('Services'), gettext('Threat Shield'), gettext('DNS rules')];
$pglinks = ['', '/threatshield/threatshield_status.php', '@self'];
if ($view === 'rewrites') {
	fs_page_action(gettext('Add rewrite'), '#', 'fa-plus', 'primary', ['data-fs-modal' => '#rewrite-edit']);
} else {
	fs_page_action(gettext('Allowlist'), 'threatshield_allowlist.php', 'fa-circle-check', 'secondary');
	fs_page_action(gettext('Query log'), 'threatshield_querylog.php', 'fa-list-check', 'secondary');
}

include('head.inc');
threatshield_print_messages($input_errors);
threatshield_display_tabs('rules');
fs_view_switch(['custom' => gettext('Custom rules'), 'rewrites' => gettext('Rewrites')], $view);

if ($view === 'custom'):
	$counts = ['block' => 0, 'allow' => 0, 'comment' => 0];
	foreach (threatshield_lines((string)($cfg['custom_rules'] ?? '')) as $line) {
		$line = trim($line);
		if ($line === '') continue;
		if ($line[0] === '!' || $line[0] === '#') $counts['comment']++;
		elseif (strncmp($line, '@@', 2) === 0) $counts['allow']++;
		else $counts['block']++;
	}
?>
<div class="fs-tiles">
<?php
	fs_tile(gettext('Block rules'), $counts['block']);
	fs_tile(gettext('Allow rules'), $counts['allow'], null, gettext('Simple allows belong on the Allowlist tab'));
	fs_tile(gettext('Comments'), $counts['comment']);
?>
</div>
<?php
	$save = new Form_Button('save_rules', 'Save', null, 'fa-solid fa-floppy-disk');
	$save->addClass('btn-primary');
	$form = new Form($save);
	$form->setAction($self);
	$section = new Form_Section('Rules');
	$section->addInput(new Form_Textarea('custom_rules', 'Custom rules', (string)$cfg['custom_rules']))
		->setRows(14)->addClass('fs-mono')->setNoWrap()
		->setAttribute('placeholder', "||bad-tracker.com^" . chr(10) . "||ads.example.org^\$client=192.168.1.20" . chr(10) . "/^ads?[0-9]*\\./")
		->setAttribute('spellcheck', 'false')
		->setHelp('One rule per line, in AdGuard / Adblock Plus syntax, as regular expressions or in hosts-file format. ' .
		    'Lines starting with ! or # are comments. Use the Allowlist tab to let a domain through; it wins over every rule here.');
	$form->add($section);
	print($form);
?>
<div class="panel panel-default fs-table">
<?php fs_table_toolbar(['title' => gettext('Syntax examples'), 'search' => false, 'noun' => gettext('examples')]); ?>
	<div class="panel-body table-responsive">
		<table class="table">
			<thead><tr><th><?=gettext('Rule')?></th><th><?=gettext('Effect')?></th></tr></thead>
			<tbody>
<?php	foreach ([
		['||example.org^', 'block', gettext('Blocks example.org and all its subdomains.')],
		['||example.org^$client=192.168.1.20', 'block', gettext('Blocks it for one client only.')],
		['||example.org^$dnstype=AAAA', 'block', gettext('Blocks only its IPv6 answers.')],
		['/^ads?[0-9]*\./', 'block', gettext('Blocks domains matching the regular expression (ad1.server.com, ads42.net).')],
		['@@||trusted.com^', 'pass', gettext('Allows trusted.com and its subdomains, even when a list blocks them.')],
		['127.0.0.1 tracker.com', 'info', gettext('Hosts-file format: answers tracker.com with the given address.')],
		['! comment', 'neutral', gettext('A comment; ignored.')],
	] as list($rule, $state, $text)): ?>
				<tr>
					<td class="ts-rule"><code><?=htmlspecialchars($rule)?></code></td>
					<td><?=fs_badge($state, ['block' => gettext('Block'), 'pass' => gettext('Allow'), 'info' => gettext('Hosts'), 'neutral' => gettext('Comment')][$state])?> <?=htmlspecialchars($text)?></td>
				</tr>
<?php	endforeach; ?>
			</tbody>
		</table>
	</div>
</div>
<?php
else:
	$rewrites = threatshield_normalize_list($cfg['rewrites'] ?? []);
	$answer_type = function ($answer) {
		if (filter_var($answer, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) return 'A';
		if (filter_var($answer, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) return 'AAAA';
		return 'CNAME';
	};
?>
<div class="panel panel-default fs-table">
<?php fs_table_toolbar([
	'title' => gettext('DNS rewrites'), 'search' => gettext('Search rewrites…'), 'noun' => gettext('rewrites'), 'noun_one' => gettext('rewrite'),
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
<?php	foreach ($rewrites as $i => $rw):
		$domain = (string)($rw['domain'] ?? '');
		$answer = (string)($rw['answer'] ?? '');
		$type = $answer_type($answer);
		$on = ($rw['enabled'] ?? 'on') === 'on';
?>
				<tr data-fs-filter-type="<?=$type?>"<?=$on ? '' : ' class="fs-row-disabled"'?>>
					<td class="fs-mono"><?=htmlspecialchars($domain)?><?=(strncmp($domain, '*.', 2) === 0) ? ' ' . fs_badge('info', gettext('Wildcard')) : ''?></td>
					<td><span class="fs-chip fs-chip--mono fs-chip--strong"><?=$type?></span></td>
					<td class="fs-mono"><?=htmlspecialchars($answer)?></td>
					<td class="fs-col-actions"><?=fs_row_actions([
						['edit', '#', $domain, ['attrs' => ['data-fs-modal' => '#rewrite-edit', 'data-fs-fill' => json_encode(['rewrite_index' => (string)$i, 'domain' => $domain, 'answer' => $answer])]]],
						['toggle', $self . '&toggle=' . (int)$i, $domain, ['enabled' => $on]],
						['delete', $self . '&delete=' . (int)$i, $domain, ['thing' => gettext('rewrite')]],
					])?></td>
				</tr>
<?php	endforeach;
	if (empty($rewrites)) fs_empty_row(4, gettext('No DNS rewrites yet.'));
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
	fs_modal_form_begin('rewrite-edit', gettext('DNS rewrite'), $self, [], ($input_errors && isset($_POST['save_rewrite']))
	    ? ['rewrite_index' => (string)($_POST['rewrite_index'] ?? ''), 'domain' => (string)($_POST['domain'] ?? ''), 'answer' => (string)($_POST['answer'] ?? '')] : null);
?>
	<input type="hidden" name="rewrite_index" value="">
	<div class="mb-3">
		<label class="form-label" for="domain"><?=gettext('Domain')?></label>
		<input type="text" class="form-control fs-mono" id="domain" name="domain" placeholder="nas.home.arpa, *.internal.lan" required>
	</div>
	<div class="mb-0">
		<label class="form-label" for="answer"><?=gettext('Answer')?></label>
		<input type="text" class="form-control fs-mono" id="answer" name="answer" placeholder="192.168.1.50, router.local" required>
		<div class="form-text"><?=gettext('An IPv4 or IPv6 address, or another host name.')?></div>
	</div>
<?php
	fs_modal_form_end(gettext('Save rewrite'), 'save_rewrite', '1', 'fa-floppy-disk');
endif;
threatshield_ui_styles();
?>
<style>
.ts-rule { white-space: nowrap; width: 1%; }
#custom_rules { overflow-x: auto; }
</style>
<?php include('foot.inc'); ?>
