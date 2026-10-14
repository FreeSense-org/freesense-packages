<?php
/*
 * threatshield_ui.inc
 * FreeSense Threat Shield - helpers shared by the WebUI pages
 *
 * Copyright (c) 2025-2026 The FreeSense Project.
 * Licensed under the Apache License, Version 2.0.
 */

/* Messages survive the redirect after a POST (post/redirect/get), so a
 * reload never repeats an action. */
function threatshield_flash(string $type, $messages): void {
	$messages = array_filter(array_map('strval', (array)$messages), 'strlen');
	if (empty($messages)) return;
	phpsession_begin();
	foreach ($messages as $m) {
		$_SESSION['threatshield_flash'][$type][] = $m;
	}
	phpsession_end(true);
}

/* Takes the flashed messages while headers can still be sent (pages include
 * this file before any output). */
if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'GET' && function_exists('phpsession_begin')) {
	phpsession_begin();
	$GLOBALS['threatshield_flash_messages'] = $_SESSION['threatshield_flash'] ?? [];
	unset($_SESSION['threatshield_flash']);
	phpsession_end(!empty($GLOBALS['threatshield_flash_messages']));
}

function threatshield_redirect(string $url): void {
	header('Location: ' . $url);
	exit;
}

/* Prints the flashed and the current messages. */
function threatshield_print_messages(array $errors = [], ?string $saved = null, array $warnings = []): void {
	$flash = $GLOBALS['threatshield_flash_messages'] ?? [];
	$errors = array_merge($flash['error'] ?? [], $errors);
	$warnings = array_merge($flash['warn'] ?? [], $warnings);
	$saved_list = array_merge($flash['ok'] ?? [], ($saved !== null) ? [$saved] : []);
	if (!empty($errors)) print_input_errors(array_map('htmlspecialchars', $errors));
	foreach ($saved_list as $m) print_info_box(htmlspecialchars($m), 'success');
	if (!empty($warnings)) {
		print_callout('<ul class="ts-list">' . implode('', array_map(fn($w) => '<li>' . htmlspecialchars($w) . '</li>', $warnings)) . '</ul>',
		    'warning', gettext('Check these settings'));
	}
}

/* Applies a changed configuration and flashes the outcome. */
function threatshield_apply(array $cfg, string $description, string $success): bool {
	$errors = [];
	$warnings = [];
	$ok = threatshield_save_and_apply($cfg, $description, $errors, $warnings);
	threatshield_flash('error', $errors);
	threatshield_flash('warn', $warnings);
	if ($ok) threatshield_flash('ok', $success);
	return $ok;
}

/* The health checklist (also served by threatshield_ajax.php). */
function threatshield_health_html(array $checks): string {
	$states = ['ok' => 'pass', 'warn' => 'warn', 'fail' => 'error', 'skip' => 'neutral'];
	$labels = ['ok' => gettext('OK'), 'warn' => gettext('Check'), 'fail' => gettext('Problem'), 'skip' => gettext('Off')];
	$fixes = [
		'restart' => gettext('Restart'), 'update_feeds' => gettext('Download lists'), 'reload_filter' => gettext('Reload firewall'),
		'resync' => gettext('Apply settings again'), 'start_dnsbl' => gettext('Start'), 'resume' => gettext('Resume'),
		'reload_unbound' => gettext('Restart DNS Resolver'),
	];
	$html = '<ul class="ts-health">';
	foreach ($checks as $c) {
		$html .= '<li class="ts-health-' . htmlspecialchars($c['state']) . '">' . fs_badge($states[$c['state']] ?? 'neutral', $labels[$c['state']] ?? '')
		    . '<span class="ts-health-text"><strong>' . htmlspecialchars($c['label']) . '</strong>'
		    . '<span class="fs-muted">' . htmlspecialchars($c['detail']) . '</span></span>';
		if ($c['fix'] === 'settings') {
			$html .= '<a class="btn btn-sm btn-outline-secondary" href="threatshield.php">' . htmlspecialchars(gettext('Settings')) . '</a>';
		} elseif (isset($fixes[$c['fix']]) && $c['state'] !== 'ok') {
			/* a form, not a usepost link: this list is loaded after the page */
			$html .= '<form method="post" action="threatshield_status.php"><button type="submit" class="btn btn-sm btn-outline-secondary" name="fix" value="'
			    . htmlspecialchars($c['fix']) . '">' . htmlspecialchars($fixes[$c['fix']]) . '</button></form>';
		}
		$html .= '</li>';
	}
	return $html . '</ul>';
}

/* Runs a health-panel fix action. */
function threatshield_run_fix(string $fix): string {
	switch ($fix) {
		case 'restart':
			return threatshield_service_control('restart') ? gettext('Threat Shield restarted.') : gettext('Threat Shield did not start. Check the system log.');
		case 'update_feeds':
			mwexec_bg(THREATSHIELD_UPDATER . ' all force');
			return gettext('List downloads started in the background.');
		case 'reload_filter':
			@unlink('/tmp/rules.packages.threatshield');
			filter_configure();
			return gettext('The firewall rules are being reloaded.');
		case 'resync':
			return threatshield_sync_config() ? gettext('Settings applied again.') : gettext('The settings could not be applied. ') . threatshield_last_error();
		case 'start_dnsbl':
			return threatshield_service_control('start', 'threatshield_dnsbl') ? gettext('Reputation checks started.') : gettext('The reputation service did not start.');
		case 'resume':
			threatshield_resume();
			return gettext('Blocking resumed.');
		case 'reload_unbound':
			services_unbound_configure();
			return gettext('DNS Resolver restarted.');
	}
	return '';
}

/* Packets blocked per Threat Shield rule label, from pf's label counters. */
function threatshield_label_counters(): array {
	$cache = THREATSHIELD_CACHE_DIR . '/labels.json';
	if (is_file($cache) && time() - (int)filemtime($cache) < 30) {
		$data = json_decode((string)@file_get_contents($cache), true);
		if (is_array($data)) return $data;
	}
	$out = [];
	if (file_exists('/sbin/pfctl')) {
		exec('/sbin/pfctl -sl 2>/dev/null', $lines);
		foreach ($lines as $line) {
			if (preg_match('/^(ThreatShield .+?) (\d+) (\d+) (\d+)/', $line, $m)) {
				$out[$m[1]] = ($out[$m[1]] ?? 0) + (int)$m[3];
			}
		}
	}
	if (is_dir(THREATSHIELD_CACHE_DIR)) @file_put_contents($cache, json_encode($out), LOCK_EX);
	return $out;
}

function threatshield_label_sum(array $counters, string $needle, ?string $exclude = null): int {
	$sum = 0;
	foreach ($counters as $label => $packets) {
		if (strpos($label, $needle) !== false && ($exclude === null || strpos($label, $exclude) === false)) $sum += $packets;
	}
	return $sum;
}

/* Interface checkboxes for raw-HTML forms and modals. */
function threatshield_iface_checks(string $name, array $interfaces, array $selected): string {
	$html = '<div class="ts-ifaces">';
	foreach ($interfaces as $key => $label) {
		$id = $name . '_' . preg_replace('/[^a-z0-9_]/i', '', (string)$key);
		$html .= '<label class="form-check" for="' . $id . '"><input class="form-check-input" type="checkbox" id="' . $id . '" name="'
		    . htmlspecialchars($name) . '[]" value="' . htmlspecialchars((string)$key) . '"' . (in_array((string)$key, $selected, true) ? ' checked' : '')
		    . '> ' . htmlspecialchars($label) . '</label>';
	}
	return $html . '</div>';
}

/* Styles shared by the Threat Shield pages. */
function threatshield_ui_styles(): void {
?>
<style>
.ts-list { margin: 0; padding-left: 1.1rem; }
.ts-health { list-style: none; margin: 0; padding: 0; }
.ts-health li { display: flex; align-items: center; gap: var(--fs-sp-3); padding: var(--fs-sp-2) var(--fs-sp-4); border-top: 1px solid var(--fs-border); }
.ts-health li:first-child { border-top: 0; }
.ts-health .fs-badge { flex: 0 0 6.5rem; justify-content: center; }
.ts-health-text { display: flex; flex-direction: column; flex: 1 1 auto; min-width: 0; }
.ts-health-text .fs-muted { font-size: var(--fs-fs-sm); word-break: break-word; }
.ts-nowrap { white-space: nowrap; }
.ts-num { text-align: right; white-space: nowrap; font-variant-numeric: tabular-nums; }
.ts-break { word-break: break-all; }
.ts-col-switch { width: 3.5rem; }
.ts-col-switch .form-check { margin: 0; min-height: 0; }
.ts-ifaces { display: flex; flex-wrap: wrap; gap: 0 var(--fs-sp-4); }
.ts-ifaces .form-check { margin: 0; font-weight: 400; }
.ts-dirty { display: inline-flex; align-items: center; gap: .4rem; margin-left: var(--fs-sp-3); }
.ts-dirty > i { color: var(--fs-coral); }
.ts-pager { display: flex; align-items: center; gap: var(--fs-sp-2); justify-content: flex-end; }
@media (max-width: 575px) { .ts-health li { flex-wrap: wrap; } .ts-health .fs-badge { flex-basis: auto; } }
</style>
<?php
}
