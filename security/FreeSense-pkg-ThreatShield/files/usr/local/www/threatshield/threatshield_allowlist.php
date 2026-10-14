<?php
/*
 * threatshield_allowlist.php
 * FreeSense Threat Shield - domains and addresses that are never blocked
 *
 * Copyright (c) 2025-2026 The FreeSense Project.
 * Licensed under the Apache License, Version 2.0.
 */

##|+PRIV
##|*IDENT=page-services-threatshield
##|*NAME=Services: Threat Shield Allowlist
##|*DESCR=Manage domains and addresses Threat Shield never blocks
##|*MATCH=threatshield/threatshield_allowlist.php*
##|-PRIV

require_once('guiconfig.inc');
require_once('/usr/local/pkg/threatshield.inc');
require_once('/usr/local/pkg/threatshield/threatshield_ui.inc');

$cfg = threatshield_config();
$view = fs_view_param(['domains', 'ips'], 'domains');
$self = 'threatshield_allowlist.php?view=' . $view;
$key = ($view === 'ips') ? 'ip_allowlist' : 'allowlist';
$field = ($view === 'ips') ? 'address' : 'domain';
$sources = ['manual' => gettext('Added here'), 'querylog' => gettext('Query log'), 'overview' => gettext('Overview'),
    'migrated' => gettext('From custom rules'), 'inbound' => gettext('Inbound protection')];

$input_errors = [];
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
	$list = threatshield_normalize_list($cfg[$key] ?? []);
	$changed = false;
	$message = '';
	if (isset($_POST['save_entry'])) {
		$index = ($_POST['entry_index'] ?? '') === '' ? null : (int)$_POST['entry_index'];
		$comment = trim((string)($_POST['entry_comment'] ?? ''));
		/* one entry per line: paste several at once */
		$values = array_values(array_filter(array_map('trim', threatshield_lines((string)($_POST['entry_value'] ?? '')))));
		if (empty($values)) {
			$input_errors[] = ($view === 'ips') ? gettext('Enter an IP address or network.') : gettext('Enter a domain name.');
		}
		$work = $cfg;
		if ($index !== null && isset($list[$index])) {
			/* editing: replace the entry in place */
			$value = $values[0] ?? '';
			$normalized = ($view === 'ips') ? threatshield_cidr_normalize($value) : threatshield_normalize_domain($value);
			if ($normalized === null) {
				$input_errors[] = sprintf(gettext('"%s" is not valid.'), $value);
			} else {
				$list[$index][$field] = $normalized;
				$list[$index]['comment'] = $comment;
				if ($view === 'domains') $list[$index]['subdomains'] = isset($_POST['entry_subdomains']) ? 'on' : 'off';
				$work[$key] = $list;
				$changed = true;
				$message = sprintf(gettext('%s saved.'), $normalized);
			}
		} else {
			$added = [];
			$notes = [];
			foreach ($values as $value) {
				$m = null;
				$ok = ($view === 'ips')
				    ? threatshield_ip_allowlist_add($work, $value, 'manual', $comment, $m)
				    : threatshield_allowlist_add($work, $value, isset($_POST['entry_subdomains']), 'manual', $comment, $m);
				if ($ok) $added[] = $value; else $notes[] = $m;
			}
			if (count($values) === 1 && empty($added) && !empty($notes)) $input_errors = array_merge($input_errors, $notes);
			else threatshield_flash('warn', $notes);
			$changed = !empty($added);
			$message = sprintf(gettext('%d entries added.'), count($added));
		}
		if ($changed && empty($input_errors)) $cfg = $work;
		$list = threatshield_normalize_list($cfg[$key] ?? []);
	} elseif (isset($_POST['toggle']) || isset($_POST['delete'])) {
		$i = (int)($_POST['toggle'] ?? $_POST['delete']);
		if (isset($list[$i])) {
			$name = (string)($list[$i][$field] ?? '');
			if (isset($_POST['delete'])) {
				array_splice($list, $i, 1);
				$message = sprintf(gettext('%s removed from the allowlist.'), $name);
			} else {
				$list[$i]['enabled'] = (($list[$i]['enabled'] ?? 'on') === 'on') ? 'off' : 'on';
				$message = sprintf(($list[$i]['enabled'] === 'on') ? gettext('%s turned on.') : gettext('%s turned off.'), $name);
			}
			$changed = true;
		}
	} elseif (isset($_POST['bulk_on']) || isset($_POST['bulk_off']) || isset($_POST['bulk_delete'])) {
		$sel = array_map('intval', (array)($_POST['sel'] ?? []));
		$keep = [];
		foreach ($list as $i => $entry) {
			if (in_array($i, $sel, true)) {
				if (isset($_POST['bulk_delete'])) continue;
				$entry['enabled'] = isset($_POST['bulk_on']) ? 'on' : 'off';
			}
			$keep[] = $entry;
		}
		$list = $keep;
		$changed = !empty($sel);
		$message = sprintf(gettext('%d entries changed.'), count($sel));
	}
	if ($changed && empty($input_errors)) {
		$cfg[$key] = $list;
		threatshield_apply($cfg, gettext('Threat Shield: updated the allowlist'), $message);
	}
	if (empty($input_errors)) threatshield_redirect($self);
}

$entries = threatshield_normalize_list($cfg[$key] ?? []);
$on = count(array_filter($entries, fn($e) => is_array($e) && ($e['enabled'] ?? 'on') === 'on'));

$pgtitle = [gettext('Services'), gettext('Threat Shield'), gettext('Allowlist')];
$pglinks = ['', '/threatshield/threatshield_status.php', '@self'];

fs_page_action(($view === 'ips') ? gettext('Add address') : gettext('Add domain'), '#', 'fa-plus', 'primary', ['data-fs-modal' => '#entry-edit']);
fs_page_action(gettext('Query log'), 'threatshield_querylog.php?status=blocked', 'fa-list-check', 'secondary');

include('head.inc');
threatshield_print_messages($input_errors);
threatshield_display_tabs('allowlist');
fs_view_switch(['domains' => gettext('Domains'), 'ips' => gettext('IP addresses')], $view);
?>

<div class="fs-tiles">
<?php
fs_tile(($view === 'ips') ? gettext('Allowed addresses') : gettext('Allowed domains'), sprintf(gettext('%1$d of %2$d on'), $on, count($entries)));
fs_tile(gettext('Applies to'), ($view === 'ips') ? gettext('IP lists, GeoIP, reputation and flood checks') : gettext('Every block list and custom rule'));
?>
</div>

<form method="post" action="<?=htmlspecialchars($self)?>">
<div class="panel panel-default fs-table">
<?php fs_table_toolbar([
	'title' => ($view === 'ips') ? gettext('Allowed addresses') : gettext('Allowed domains'),
	'search' => ($view === 'ips') ? gettext('Search addresses…') : gettext('Search domains…'),
	'noun' => gettext('entries'),
	'noun_one' => gettext('entry'),
	'filters' => ['source' => array_merge([gettext('All sources')], $sources)],
	'bulk' => [
		['name' => 'bulk_on', 'label' => gettext('Turn on'), 'icon' => 'fa-toggle-on', 'value' => '1'],
		['name' => 'bulk_off', 'label' => gettext('Turn off'), 'icon' => 'fa-toggle-off', 'value' => '1'],
		['name' => 'bulk_delete', 'label' => gettext('Remove'), 'icon' => 'fa-trash-can', 'variant' => 'danger', 'value' => '1',
		 'confirm' => gettext('Remove the selected entries from the allowlist?')],
	],
]); ?>
	<div class="panel-body table-responsive">
		<table class="table table-hover table-rowdblclickedit" data-sortable>
			<thead>
				<tr>
					<th class="fs-col-select"><input type="checkbox" data-fs-select-all aria-label="<?=gettext('Select all')?>"></th>
					<th data-fs-search><?=($view === 'ips') ? gettext('Address') : gettext('Domain')?></th>
<?php if ($view === 'domains'): ?>
					<th><?=gettext('Match')?></th>
<?php endif; ?>
					<th data-fs-search><?=gettext('Comment')?></th>
					<th><?=gettext('Source')?></th>
					<th><?=gettext('Added')?></th>
					<th class="fs-col-actions" data-sortable="false"><span class="visually-hidden"><?=gettext('Actions')?></span></th>
				</tr>
			</thead>
			<tbody>
<?php
foreach ($entries as $i => $e):
	if (!is_array($e)) continue;
	$value = (string)($e[$field] ?? '');
	$enabled = ($e['enabled'] ?? 'on') === 'on';
	$source = (string)($e['source'] ?? 'manual');
	$fill = ['entry_index' => (string)$i, 'entry_value' => $value, 'entry_comment' => (string)($e['comment'] ?? ''),
	    'entry_subdomains' => (($e['subdomains'] ?? 'on') === 'on')];
?>
				<tr data-fs-filter-source="<?=htmlspecialchars($source)?>"<?=$enabled ? '' : ' class="fs-row-disabled"'?>>
					<td><input type="checkbox" name="sel[]" value="<?=(int)$i?>" data-fs-select aria-label="<?=htmlspecialchars(sprintf(gettext('Select %s'), $value))?>"></td>
					<td class="fs-mono ts-break"><?=htmlspecialchars($value)?></td>
<?php	if ($view === 'domains'): ?>
					<td><?=(($e['subdomains'] ?? 'on') === 'on') ? fs_badge('info', gettext('With subdomains')) : fs_badge('neutral', gettext('Exact name'))?></td>
<?php	endif; ?>
					<td><?=htmlspecialchars((string)($e['comment'] ?? ''))?></td>
					<td><span class="fs-chip"><?=htmlspecialchars($sources[$source] ?? $source)?></span></td>
					<td class="ts-nowrap"><?=!empty($e['added']) ? htmlspecialchars(date('Y-m-d', (int)$e['added'])) : '–'?></td>
					<td class="fs-col-actions"><?=fs_row_actions([
						['edit', '#', $value, ['attrs' => ['data-fs-modal' => '#entry-edit', 'data-fs-fill' => json_encode($fill), 'data-fs-modal-title' => sprintf(gettext('Edit “%s”'), $value)]]],
						['toggle', $self . '&toggle=' . (int)$i, $value, ['enabled' => $enabled]],
						['delete', $self . '&delete=' . (int)$i, $value, ['thing' => gettext('entry'),
						    'detail' => gettext('Threat Shield can block it again when a list contains it.')]],
					])?></td>
				</tr>
<?php
endforeach;
if (empty($entries)) {
	fs_empty_row(($view === 'domains') ? 7 : 6, ($view === 'ips')
	    ? gettext('No allowed addresses. Add partners, monitoring services or your own remote offices that must never be blocked.')
	    : gettext('Nothing allowed yet. Unblock a domain from the query log, or add one here.'));
}
?>
			</tbody>
		</table>
	</div>
	<div class="panel-footer small fs-muted">
		<i class="fa-solid fa-circle-info" aria-hidden="true"></i>
		<?=($view === 'ips')
		    ? gettext('Addresses here are cut out of every IP list and GeoIP table, never get a reputation lookup and are never caught by flood limits.')
		    : gettext('An allowed domain wins over every block list, the anti-bypass lists and the custom rules. Changes apply within seconds.')?>
	</div>
</div>
</form>

<?php
fs_modal_form_begin('entry-edit', ($view === 'ips') ? gettext('Add address') : gettext('Add domain'), $self, [], ($input_errors && isset($_POST['save_entry']))
    ? ['entry_index' => (string)($_POST['entry_index'] ?? ''), 'entry_value' => (string)($_POST['entry_value'] ?? ''),
       'entry_comment' => (string)($_POST['entry_comment'] ?? ''), 'entry_subdomains' => isset($_POST['entry_subdomains'])]
    : null);
?>
	<input type="hidden" name="entry_index" value="">
	<div class="mb-3">
		<label class="form-label" for="entry_value"><?=($view === 'ips') ? gettext('IP address or network') : gettext('Domain')?></label>
		<textarea class="form-control fs-mono" id="entry_value" name="entry_value" rows="3" required spellcheck="false"
		    placeholder="<?=($view === 'ips') ? '198.51.100.7&#10;203.0.113.0/24' : 'example.com&#10;cdn.example.net'?>"></textarea>
		<div class="form-text"><?=($view === 'ips') ? gettext('One per line when adding several.') : gettext('One per line when adding several. URLs and *.domain are accepted; the host name is kept.')?></div>
	</div>
<?php if ($view === 'domains'): ?>
	<label class="form-check mb-3"><input class="form-check-input" type="checkbox" name="entry_subdomains" checked> <?=gettext('Include all subdomains')?></label>
<?php endif; ?>
	<div class="mb-0">
		<label class="form-label" for="entry_comment"><?=gettext('Comment')?></label>
		<input type="text" class="form-control" id="entry_comment" name="entry_comment" placeholder="<?=gettext('Why it is allowed')?>">
	</div>
<?php
fs_modal_form_end(gettext('Save'), 'save_entry', '1', 'fa-floppy-disk');
threatshield_ui_styles();
include('foot.inc');
