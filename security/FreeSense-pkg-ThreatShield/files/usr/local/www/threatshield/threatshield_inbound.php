<?php
/*
 * threatshield_inbound.php
 * FreeSense Threat Shield - inbound protection: DNSBL reputation checks and
 * flood limits for exposed services
 *
 * Copyright (c) 2025-2026 The FreeSense Project.
 * Licensed under the Apache License, Version 2.0.
 */

##|+PRIV
##|*IDENT=page-services-threatshield
##|*NAME=Services: Threat Shield Inbound Protection
##|*DESCR=Configure DNSBL reputation checks and flood protection for exposed services
##|*MATCH=threatshield/threatshield_inbound.php*
##|-PRIV

require_once('guiconfig.inc');
require_once('/usr/local/pkg/threatshield.inc');
require_once('/usr/local/pkg/threatshield/threatshield_ui.inc');

$cfg = threatshield_config();
$view = fs_view_param(['policies', 'zones', 'activity'], 'policies');
$self = 'threatshield_inbound.php?view=' . $view;
$wans = threatshield_wan_interfaces() ?: threatshield_assigned_interfaces();
$modes = ['greylist' => gettext('Check first (greylist)'), 'failopen' => gettext('Let through, check in the background'), 'off' => gettext('No reputation check')];
$failures = ['allow' => gettext('Allow the connection'), 'deny' => gettext('Block the connection')];
$protocols = ['tcp' => 'TCP', 'udp' => 'UDP', 'both' => 'TCP + UDP'];

$blank_policy = ['id' => '', 'name' => '', 'enable' => 'on', 'interfaces' => array_slice(array_keys($wans), 0, 1), 'protocol' => 'tcp',
    'dest' => 'self', 'ports' => '', 'dnsbl_mode' => 'greylist', 'on_failure' => 'allow', 'log' => 'on', 'owned' => 'off',
    'flood_max_conn' => '', 'flood_conn_rate' => '', 'flood_max_states' => '', 'synproxy' => 'off'];

$edit = isset($_GET['edit']) ? (string)$_GET['edit'] : (isset($_POST['policy_index']) ? (string)$_POST['policy_index'] : null);
$policies = threatshield_normalize_list($cfg['inbound_policies'] ?? []);
$input_errors = [];
$pconfig = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
	$changed = false;
	$message = '';
	if (isset($_POST['save_policy'])) {
		$index = ($edit === null || !ctype_digit($edit) || !isset($policies[(int)$edit])) ? null : (int)$edit;
		$p = ($index !== null) ? $policies[$index] : $blank_policy;
		$p['name'] = trim((string)($_POST['name'] ?? ''));
		$p['enable'] = isset($_POST['enable']) ? 'on' : 'off';
		$p['interfaces'] = array_values(array_intersect(array_map('strval', (array)($_POST['interfaces'] ?? [])), array_keys(threatshield_assigned_interfaces())));
		$p['protocol'] = array_key_exists($_POST['protocol'] ?? '', $protocols) ? $_POST['protocol'] : 'tcp';
		$p['dest'] = trim((string)($_POST['dest'] ?? 'self')) ?: 'self';
		$p['ports'] = trim((string)($_POST['ports'] ?? ''));
		$p['dnsbl_mode'] = array_key_exists($_POST['dnsbl_mode'] ?? '', $modes) ? $_POST['dnsbl_mode'] : 'greylist';
		$p['on_failure'] = array_key_exists($_POST['on_failure'] ?? '', $failures) ? $_POST['on_failure'] : 'allow';
		$p['log'] = isset($_POST['log']) ? 'on' : 'off';
		$p['owned'] = isset($_POST['owned']) ? 'on' : 'off';
		foreach (['flood_max_conn', 'flood_max_states'] as $k) {
			$v = trim((string)($_POST[$k] ?? ''));
			$p[$k] = ($v === '' || !ctype_digit($v) || (int)$v === 0) ? '' : (string)(int)$v;
		}
		$p['flood_conn_rate'] = trim((string)($_POST['flood_conn_rate'] ?? ''));
		$p['synproxy'] = isset($_POST['synproxy']) ? 'on' : 'off';
		if ($p['name'] === '') $input_errors[] = gettext('Give the policy a name.');
		if ($p['id'] === '') {
			$base = substr(threatshield_pf_ident($p['name']), 0, 8) ?: 'policy';
			$ids = array_map(fn($x) => (string)($x['id'] ?? ''), $policies);
			$id = $base;
			for ($n = 2; in_array($id, $ids, true); $n++) $id = substr($base, 0, 8) . $n;
			$p['id'] = $id;
		}
		if (empty($input_errors)) {
			if ($index === null) $policies[] = $p; else $policies[$index] = $p;
			$cfg['inbound_policies'] = $policies;
			/* a policy with a reputation check needs the service on */
			if ($p['dnsbl_mode'] !== 'off' && $p['enable'] === 'on') $cfg['dnsbl_enable'] = 'on';
			$errors = [];
			$warnings = [];
			if (threatshield_save_and_apply($cfg, gettext('Threat Shield: saved an inbound protection policy'), $errors, $warnings)) {
				threatshield_flash('ok', sprintf(gettext('Policy "%s" saved and applied.'), $p['name']));
				threatshield_flash('warn', $warnings);
				threatshield_redirect('threatshield_inbound.php?view=policies');
			}
			$input_errors = $errors;
		}
		$pconfig = $p;
	} elseif (isset($_POST['toggle']) || isset($_POST['delete'])) {
		$i = (int)($_POST['toggle'] ?? $_POST['delete']);
		if (isset($policies[$i])) {
			$name = (string)($policies[$i]['name'] ?? '');
			if (isset($_POST['delete'])) {
				array_splice($policies, $i, 1);
				$message = sprintf(gettext('Policy "%s" deleted.'), $name);
			} else {
				$policies[$i]['enable'] = (($policies[$i]['enable'] ?? 'on') === 'on') ? 'off' : 'on';
				$message = sprintf(($policies[$i]['enable'] === 'on') ? gettext('Policy "%s" turned on.') : gettext('Policy "%s" turned off.'), $name);
			}
			$cfg['inbound_policies'] = $policies;
			$changed = true;
		}
	} elseif (isset($_POST['save_zone'])) {
		$zones = threatshield_normalize_list($cfg['dnsbl_zones'] ?? []);
		$i = ($_POST['zone_index'] ?? '') === '' ? null : (int)$_POST['zone_index'];
		$z = ($i !== null && isset($zones[$i])) ? $zones[$i] : ['id' => '', 'enabled' => 'on', 'preset' => ''];
		$z['name'] = trim((string)($_POST['zone_name'] ?? ''));
		$z['zone'] = strtolower(trim((string)($_POST['zone_zone'] ?? '')));
		$z['match'] = trim((string)($_POST['zone_match'] ?? 'any')) ?: 'any';
		$z['ipv6'] = isset($_POST['zone_ipv6']) ? 'on' : 'off';
		if (isset($_POST['zone_key']) && $_POST['zone_key'] !== '') $z['access_key'] = trim((string)$_POST['zone_key']);
		if ($z['id'] === '') $z['id'] = 'z' . substr(md5($z['zone']), 0, 7);
		if ($z['name'] === '' || $z['zone'] === '') {
			$input_errors[] = gettext('A zone needs a name and a zone name.');
		} else {
			if ($i === null) $zones[] = $z; else $zones[$i] = $z;
			$cfg['dnsbl_zones'] = $zones;
			$changed = true;
			$message = sprintf(gettext('Zone "%s" saved.'), $z['name']);
		}
	} elseif (isset($_POST['zone_toggle']) || isset($_POST['zone_delete']) || isset($_POST['zone_add'])) {
		$zones = threatshield_normalize_list($cfg['dnsbl_zones'] ?? []);
		if (isset($_POST['zone_add'])) {
			$z = threatshield_dnsbl_zone_from_catalog((string)$_POST['zone_add'], true);
			if ($z !== null) {
				$zones[] = $z;
				$message = sprintf(gettext('Zone "%s" added.'), $z['name']);
			}
		} else {
			$i = (int)($_POST['zone_toggle'] ?? $_POST['zone_delete']);
			if (isset($zones[$i])) {
				if (isset($_POST['zone_delete'])) {
					$message = sprintf(gettext('Zone "%s" deleted.'), (string)$zones[$i]['name']);
					array_splice($zones, $i, 1);
				} else {
					$zones[$i]['enabled'] = (($zones[$i]['enabled'] ?? 'off') === 'on') ? 'off' : 'on';
					$message = sprintf(gettext('Zone "%s" changed.'), (string)$zones[$i]['name']);
				}
			}
		}
		$cfg['dnsbl_zones'] = $zones;
		$changed = true;
	} elseif (isset($_POST['save_dnsbl'])) {
		$cfg['dnsbl_enable'] = isset($_POST['dnsbl_enable']) ? 'on' : 'off';
		$cfg['dnsbl_resolver'] = trim((string)($_POST['dnsbl_resolver'] ?? 'auto')) ?: 'auto';
		foreach (['dnsbl_quorum', 'dnsbl_ttl_good', 'dnsbl_ttl_bad', 'dnsbl_ttl_fail', 'dnsbl_timeout_ms', 'dnsbl_retries', 'dnsbl_max_qps',
		    'dnsbl_concurrency', 'dnsbl_queue_max', 'dnsbl_breaker_secs', 'flood_release_secs'] as $k) {
			$cfg[$k] = trim((string)($_POST[$k] ?? $cfg[$k]));
		}
		foreach (['dnsbl_ttl_good', 'dnsbl_ttl_bad', 'flood_release_secs'] as $k) {
			if (ctype_digit($cfg[$k])) $cfg[$k] = (string)((int)$cfg[$k] * 60);    // entered in minutes
		}
		$changed = true;
		$message = gettext('Reputation settings saved.');
	} elseif (isset($_POST['forget'])) {
		threatshield_dnsbl_forget([(string)$_POST['forget']]);
		threatshield_flash('ok', sprintf(gettext('%s will be checked again on its next connection.'), (string)$_POST['forget']));
	} elseif (isset($_POST['flush_cache'])) {
		threatshield_dnsbl_flush();
		threatshield_flash('ok', gettext('The reputation cache was emptied; every source is checked again.'));
	} elseif (isset($_POST['allow_ip'])) {
		$m = null;
		if (threatshield_ip_allowlist_add($cfg, (string)$_POST['allow_ip'], 'inbound', gettext('Allowed from inbound protection'), $m)) {
			threatshield_dnsbl_forget([(string)$_POST['allow_ip']]);
			$changed = true;
		}
		$message = (string)$m;
	} elseif (isset($_POST['check'])) {
		/* answered on this page below; a lookup sends the address out, so
		 * it needs a POST with the CSRF token */
	} elseif (isset($_POST['release'])) {
		$ok = threatshield_flood_release((string)$_POST['release'], (string)($_POST['table'] ?? THREATSHIELD_T_FLOOD));
		threatshield_flash($ok ? 'ok' : 'error', $ok ? sprintf(gettext('%s released.'), (string)$_POST['release']) : gettext('The address could not be released.'));
	}
	if ($changed && empty($input_errors)) {
		threatshield_apply($cfg, gettext('Threat Shield: updated inbound protection'), $message);
	}
	if (empty($input_errors) && !isset($_POST['save_policy']) && !isset($_POST['check'])) threatshield_redirect($self);
}

$editing = ($edit !== null);
if ($editing && $pconfig === null) {
	$pconfig = (ctype_digit($edit) && isset($policies[(int)$edit])) ? $policies[(int)$edit] + $blank_policy : $blank_policy;
}
$status = threatshield_dnsbl_status();

$pgtitle = [gettext('Services'), gettext('Threat Shield'), gettext('Inbound protection')];
$pglinks = ['', '/threatshield/threatshield_status.php', 'threatshield_inbound.php'];
if ($editing) {
	$pgtitle[] = ($edit === 'new') ? gettext('Add policy') : gettext('Edit policy');
	$pglinks[] = '@self';
} elseif ($view === 'policies') {
	fs_page_action(gettext('Add policy'), 'threatshield_inbound.php?view=policies&edit=new', 'fa-plus');
} elseif ($view === 'zones') {
	fs_page_action(gettext('Add zone'), '#', 'fa-plus', 'primary', ['data-fs-modal' => '#zone-edit']);
} elseif ($view === 'activity') {
	fs_page_action(gettext('Empty cache'), $self . '&flush_cache=1', 'fa-broom', 'secondary', ['usepost' => true,
	    'data-fs-confirm' => gettext('Empty the reputation cache?'), 'data-fs-confirm-detail' => gettext('Every source is looked up again on its next connection.'),
	    'data-fs-confirm-action' => gettext('Empty')]);
}

include('head.inc');
threatshield_print_messages($input_errors);
threatshield_display_tabs('inbound');

/* ------------------------------------------------------------- editor */
if ($editing):
	$nat = [];
	foreach (config_get_path('nat/rule', []) as $r) {
		if (!is_array($r) || isset($r['disabled']) || empty($r['target'])) continue;
		$proto = (string)($r['protocol'] ?? 'tcp');
		$nat[] = ['label' => trim((string)($r['descr'] ?? '')) ?: sprintf('%s → %s', (string)($r['destination']['port'] ?? ''), (string)$r['target']),
		    'dest' => (string)$r['target'], 'ports' => (string)($r['local-port'] ?? ($r['destination']['port'] ?? '')),
		    'protocol' => ($proto === 'tcp/udp') ? 'both' : (in_array($proto, ['tcp', 'udp'], true) ? $proto : 'tcp'),
		    'interface' => (string)($r['interface'] ?? 'wan')];
	}
	$on = fn($k) => (($pconfig[$k] ?? 'off') === 'on');
	$form = new Form((new Form_Button('save_policy', 'Save', null, 'fa-solid fa-floppy-disk'))->addClass('btn-primary'));
	$section = new Form_Section('Service');
	$section->addInput(new Form_Checkbox('enable', 'Enable', 'Protect this service', $on('enable'), 'on'));
	$section->addInput(new Form_Input('name', '*Name', 'text', (string)$pconfig['name']))->setHelp('For example "SSH" or "Mail server".');
	if (!empty($nat)) {
		$choices = ['' => gettext('Choose a port forward to copy its target…')];
		foreach ($nat as $i => $n) $choices[(string)$i] = $n['label'];
		$section->addInput(new Form_Select('from_nat', 'From port forward', '', $choices))
		    ->setHelp('Fills in the address, port and protocol the forward sends the traffic to.');
	}
	$group = new Form_MultiCheckboxGroup('*Interfaces');
	$group->addClass('notoggleall');
	foreach ($wans as $key => $label) {
		$box = new Form_MultiCheckbox('interfaces[]', null, $label, in_array((string)$key, array_map('strval', threatshield_normalize_list($pconfig['interfaces'] ?? [])), true), (string)$key);
		$box->setAttribute('id', 'interfaces_' . $key);
		$group->add($box);
	}
	$section->add($group)->setHelp('Interfaces with a gateway (WAN). Connections arriving here are checked.');
	$section->addInput(new Form_Select('protocol', 'Protocol', (string)$pconfig['protocol'], $protocols));
	$section->addInput(new Form_Input('dest', '*Destination', 'text', (string)$pconfig['dest'], ['list' => 'ts-dest-list']))
	    ->addClass('fs-mono')->setHelp('"self" for a service on this firewall (SSH, VPN), or the internal address, network or alias a port forward sends to. Checks run after NAT.');
	$section->addInput(new Form_Input('ports', '*Ports', 'text', (string)$pconfig['ports']))
	    ->addClass('fs-mono')->setPlaceholder('22, 8000-8100')->setHelp('After NAT: for a port forward, the internal port.');
	$section->addInput(new Form_Checkbox('log', 'Log', 'Log blocked connections in the firewall log', $on('log'), 'on'));
	$form->add($section);

	$section = new Form_Section('Reputation check (DNSBL)');
	$section->addInput(new Form_Select('dnsbl_mode', 'Mode', (string)$pconfig['dnsbl_mode'], $modes))
	    ->setHelp('<b>Check first</b>: the first connection attempt of a new address is held back for about a second while it is looked up; ' .
		'listed addresses never get in. TCP clients retry on their own; for UDP services pick the background check. ' .
		'<b>In the background</b>: the connection goes through at once and is cut off if the address turns out to be listed.');
	$section->addInput(new Form_Select('on_failure', 'When a lookup fails', (string)$pconfig['on_failure'], $failures))
	    ->setHelp('Applies to timeouts, resolver errors and refused lookups (and while lookups are failing for a longer time). ' .
		'The decision is only kept for a short time, then the address is looked up again; a failure never becomes a long-term block.');
	$form->add($section);

	$section = new Form_Section('Flood protection');
	$section->addInput(new Form_Checkbox('owned', 'Pass rule', 'Threat Shield passes this traffic itself (needed for the limits below)', $on('owned'), 'on'))
	    ->setHelp('pf can only limit connections in the rule that lets them in. With this on, Threat Shield lets the service in before your own firewall rules, ' .
		'so rules for exactly this destination and these ports no longer apply. Addresses on the IP allowlist pass without limits.');
	$group = new Form_Group('Limits per source');
	$group->add(new Form_Input('flood_max_conn', 'Connections', 'number', (string)$pconfig['flood_max_conn'], ['min' => 1]))->setHelp('Open connections at once');
	$group->add(new Form_Input('flood_conn_rate', 'Rate', 'text', (string)$pconfig['flood_conn_rate']))->setPlaceholder('15/5')->setHelp('New connections / seconds');
	$group->add(new Form_Input('flood_max_states', 'States', 'number', (string)$pconfig['flood_max_states'], ['min' => 1]))->setHelp('Firewall states');
	$section->add($group)->setHelp('A source that goes over a limit is cut off and blocked for the release time set on the DNSBL zones view. Leave empty for no limit.');
	$section->addInput(new Form_Checkbox('synproxy', 'SYN proxy', 'Answer the TCP handshake on behalf of the service', $on('synproxy'), 'on'))
	    ->setHelp('Shields the service from SYN floods with spoofed sources. Can conflict with multi-WAN and some port forwards; test before relying on it.');
	$form->addGlobal(new Form_Input('policy_index', null, 'hidden', (string)$edit));
	$form->add($section);
	fs_form_cancel($form, 'threatshield_inbound.php?view=policies');
	print($form);
?>
<datalist id="ts-dest-list">
	<option value="self"></option>
<?php	foreach (threatshield_alias_names() as $alias): ?>
	<option value="<?=htmlspecialchars($alias)?>"></option>
<?php	endforeach; ?>
</datalist>
<script>
//<![CDATA[
events.push(function () {
	var nat = <?=json_encode($nat)?>;
	var pick = document.getElementById('from_nat');
	if (pick) {
		pick.addEventListener('change', function () {
			var n = nat[pick.value];
			if (!n) {
				return;
			}
			document.getElementById('dest').value = n.dest;
			document.getElementById('ports').value = n.ports;
			document.getElementById('protocol').value = n.protocol;
			var name = document.getElementById('name');
			if (!name.value) {
				name.value = n.label;
			}
			document.querySelectorAll('input[name="interfaces[]"]').forEach(function (box) {
				box.checked = (box.value === n.interface);
			});
		});
	}
	/* the limits need the pass rule */
	var owned = document.getElementById('owned');
	function limits() {
		['flood_max_conn', 'flood_conn_rate', 'flood_max_states', 'synproxy'].forEach(function (id) {
			var el = document.getElementById(id);
			if (el) {
				el.disabled = !owned.checked;
			}
		});
	}
	owned.addEventListener('change', limits);
	limits();
});
//]]>
</script>
<?php
	include('foot.inc');
	exit;
endif;

fs_view_switch(['policies' => gettext('Policies'), 'zones' => gettext('DNSBL zones & settings'), 'activity' => gettext('Activity')], $view);

if (($cfg['dnsbl_enable'] ?? 'off') === 'on' && ($status['breaker'] ?? 'closed') === 'open') {
	print_callout(htmlspecialchars(sprintf(gettext('Reputation lookups are failing (%s). New sources are handled by each policy\'s failure action until lookups work again.'),
	    (string)($status['last_error'] ?? ''))), 'warning');
}

/* ------------------------------------------------------------- policies */
if ($view === 'policies'):
?>
<div class="panel panel-default fs-table">
<?php fs_table_toolbar(['title' => gettext('Protected services'), 'search' => gettext('Search policies…'), 'noun' => gettext('policies'), 'noun_one' => gettext('policy')]); ?>
	<div class="panel-body table-responsive">
		<table class="table table-hover table-rowdblclickedit">
			<thead>
				<tr>
					<th class="fs-col-status"><?=gettext('Status')?></th>
					<th data-fs-search><?=gettext('Name')?></th>
					<th data-fs-search><?=gettext('Service')?></th>
					<th><?=gettext('Reputation check')?></th>
					<th><?=gettext('Flood limits')?></th>
					<th class="ts-num"><?=gettext('Blocked')?></th>
					<th class="fs-col-actions"><span class="visually-hidden"><?=gettext('Actions')?></span></th>
				</tr>
			</thead>
			<tbody>
<?php
	$labels = threatshield_label_counters();
	foreach ($policies as $i => $p):
		if (!is_array($p)) continue;
		$name = (string)($p['name'] ?? '');
		$on = ($p['enable'] ?? 'on') === 'on';
		$id = threatshield_pf_ident((string)($p['id'] ?? ''));
		$limits = [];
		if (($p['owned'] ?? 'off') === 'on') {
			if ((int)($p['flood_max_conn'] ?? 0) > 0) $limits[] = sprintf(gettext('%d connections'), (int)$p['flood_max_conn']);
			if (trim((string)($p['flood_conn_rate'] ?? '')) !== '') $limits[] = sprintf(gettext('%s per s'), (string)$p['flood_conn_rate']);
			if ((int)($p['flood_max_states'] ?? 0) > 0) $limits[] = sprintf(gettext('%d states'), (int)$p['flood_max_states']);
			if (($p['synproxy'] ?? 'off') === 'on') $limits[] = gettext('SYN proxy');
		}
		$ifs = array_map(fn($f) => $wans[$f] ?? strtoupper((string)$f), threatshield_normalize_list($p['interfaces'] ?? []));
		$blocked = threatshield_label_sum($labels, "ThreatShield {$id} DNSBL listed") + threatshield_label_sum($labels, "ThreatShield {$id} DNSBL unverified");
?>
				<tr<?=$on ? '' : ' class="fs-row-disabled"'?>>
					<td><?=$on ? fs_badge('active') : fs_badge('disabled')?></td>
					<td><a href="threatshield_inbound.php?view=policies&amp;edit=<?=(int)$i?>"><strong><?=htmlspecialchars($name)?></strong></a></td>
					<td class="fs-mono small"><?=htmlspecialchars(sprintf('%s %s → %s:%s', implode(', ', $ifs), $protocols[$p['protocol'] ?? 'tcp'] ?? '', (string)($p['dest'] ?? ''), (string)($p['ports'] ?? '')))?></td>
					<td>
<?php		if (($cfg['dnsbl_enable'] ?? 'off') !== 'on' || ($p['dnsbl_mode'] ?? 'off') === 'off'): ?>
						<span class="fs-muted"><?=gettext('Off')?></span>
<?php		else: ?>
						<?=htmlspecialchars($modes[$p['dnsbl_mode']] ?? '')?>
						<div class="fs-muted small"><?=htmlspecialchars(sprintf(gettext('On failure: %s'), strtolower($failures[$p['on_failure'] ?? 'allow'])))?></div>
<?php		endif; ?>
					</td>
					<td><?=empty($limits) ? '<span class="fs-muted">' . gettext('None') . '</span>' : '<span class="fs-chips">' . implode('', array_map(fn($l) => '<span class="fs-chip">' . htmlspecialchars($l) . '</span>', $limits)) . '</span>'?></td>
					<td class="ts-num"><?=number_format($blocked)?></td>
					<td class="fs-col-actions"><?=fs_row_actions([
						['edit', 'threatshield_inbound.php?view=policies&edit=' . (int)$i, $name],
						['toggle', $self . '&toggle=' . (int)$i, $name, ['enabled' => $on]],
						['delete', $self . '&delete=' . (int)$i, $name, ['thing' => gettext('policy')]],
					])?></td>
				</tr>
<?php
	endforeach;
	if (empty($policies)) {
		fs_empty_row(7, gettext('No protected services yet. Add one for each port you expose to the internet, for example SSH, VPN or a port forward.'),
		    'threatshield_inbound.php?view=policies&edit=new', gettext('Add policy'));
	}
?>
			</tbody>
		</table>
	</div>
	<div class="panel-footer small fs-muted">
		<i class="fa-solid fa-circle-info" aria-hidden="true"></i>
		<?=gettext('Reputation checks look up the address of every new outside source in the DNSBL zones and keep the answer for hours, so repeat visitors are not checked again. The addresses are sent to the DNSBL operators. DNS query flooding is limited separately under Settings > Rate limiting.')?>
	</div>
</div>
<?php
/* ---------------------------------------------------------------- zones */
elseif ($view === 'zones'):
	$zones = threatshield_normalize_list($cfg['dnsbl_zones'] ?? []);
	$present = array_map(fn($z) => (string)($z['preset'] ?? ''), $zones);
	[$rserver, $rport] = threatshield_dnsbl_resolver($cfg);
?>
<div class="panel panel-default fs-table">
<?php fs_table_toolbar(['title' => gettext('DNSBL zones'), 'search' => false, 'noun' => gettext('zones'), 'noun_one' => gettext('zone')]); ?>
	<div class="panel-body table-responsive">
		<table class="table table-hover">
			<thead>
				<tr>
					<th class="fs-col-status"><?=gettext('Status')?></th>
					<th><?=gettext('Name')?></th>
					<th><?=gettext('Zone')?></th>
					<th><?=gettext('Listed when the answer is')?></th>
					<th class="ts-num"><?=gettext('Listings')?></th>
					<th class="fs-col-actions"><span class="visually-hidden"><?=gettext('Actions')?></span></th>
				</tr>
			</thead>
			<tbody>
<?php	foreach ($zones as $i => $z):
		$on = ($z['enabled'] ?? 'off') === 'on';
		$fill = ['zone_index' => (string)$i, 'zone_name' => (string)$z['name'], 'zone_zone' => (string)$z['zone'], 'zone_match' => (string)$z['match'], 'zone_ipv6' => ($z['ipv6'] ?? 'off') === 'on'];
?>
				<tr<?=$on ? '' : ' class="fs-row-disabled"'?>>
					<td><?=$on ? fs_badge('active') : fs_badge('disabled')?></td>
					<td><strong><?=htmlspecialchars((string)$z['name'])?></strong>
<?php		if (isset(threatshield_dnsbl_zone_catalog()[$z['preset'] ?? ''])): ?>
						<div class="fs-muted small"><?=htmlspecialchars(threatshield_dnsbl_zone_catalog()[$z['preset']]['note'])?></div>
<?php		endif; ?></td>
					<td class="fs-mono small"><?=htmlspecialchars(str_replace('{key}', '•••', (string)$z['zone']))?><?=(($z['ipv6'] ?? 'off') === 'on') ? ' ' . fs_badge('info', 'IPv6') : ''?></td>
					<td class="fs-mono small"><?=htmlspecialchars((string)$z['match'])?></td>
					<td class="ts-num"><?=number_format((int)($status['per_zone'][$z['id']] ?? 0))?></td>
					<td class="fs-col-actions"><?=fs_row_actions([
						['edit', '#', (string)$z['name'], ['attrs' => ['data-fs-modal' => '#zone-edit', 'data-fs-fill' => json_encode($fill)]]],
						['toggle', $self . '&zone_toggle=' . (int)$i, (string)$z['name'], ['enabled' => $on]],
						['delete', $self . '&zone_delete=' . (int)$i, (string)$z['name'], ['thing' => gettext('zone')]],
					])?></td>
				</tr>
<?php	endforeach; ?>
			</tbody>
		</table>
	</div>
<?php	$missing = array_diff_key(threatshield_dnsbl_zone_catalog(), array_flip($present));
	if (!empty($missing)): ?>
	<div class="panel-footer small">
		<?=gettext('Add from the catalog:')?>
<?php		foreach ($missing as $preset => $c): ?>
		<a class="btn btn-sm btn-outline-secondary" usepost href="<?=htmlspecialchars($self . '&zone_add=' . rawurlencode($preset))?>"><?=htmlspecialchars($c['name'])?></a>
<?php		endforeach; ?>
	</div>
<?php	endif; ?>
</div>

<?php
	$minutes = fn($k) => (string)intdiv((int)$cfg[$k], 60);
	$form = new Form((new Form_Button('save_dnsbl', 'Save', null, 'fa-solid fa-floppy-disk'))->addClass('btn-primary'));
	$form->setAction($self);
	$section = new Form_Section('Reputation checks');
	$section->addInput(new Form_Checkbox('dnsbl_enable', 'Enable', 'Look up new inbound sources in the zones above', ($cfg['dnsbl_enable'] ?? 'off') === 'on', 'on'))
	    ->setHelp('Only policies with a reputation check use it.');
	$section->addInput(new Form_Input('dnsbl_resolver', 'Resolver', 'text', (string)$cfg['dnsbl_resolver']))->addClass('fs-mono')
	    ->setHelp(sprintf('"auto" uses %s:%d. Most DNSBLs refuse lookups that arrive through public resolvers (Google, Cloudflare, Quad9), so use a resolver that recurses itself.',
		htmlspecialchars($rserver), $rport));
	$section->addInput(new Form_Input('dnsbl_quorum', 'Listed by at least', 'number', (string)$cfg['dnsbl_quorum'], ['min' => 1, 'max' => 10]))
	    ->setHelp('How many zones must list an address before it is blocked.');
	$group = new Form_Group('Remember (minutes)');
	$group->add(new Form_Input('dnsbl_ttl_good', 'Clean', 'number', $minutes('dnsbl_ttl_good'), ['min' => 1]))->setHelp('Clean addresses');
	$group->add(new Form_Input('dnsbl_ttl_bad', 'Listed', 'number', $minutes('dnsbl_ttl_bad'), ['min' => 1]))->setHelp('Listed addresses');
	$section->add($group);
	$section->addInput(new Form_Input('dnsbl_ttl_fail', 'Retry failed lookups after (s)', 'number', (string)$cfg['dnsbl_ttl_fail'], ['min' => 10, 'max' => 3600]));
	$form->add($section);
	$section = new Form_Section('Limits', 'ts-dnsbl-limits', COLLAPSIBLE | SEC_CLOSED);
	$group = new Form_Group('Lookups');
	$group->add(new Form_Input('dnsbl_max_qps', 'Per second', 'number', (string)$cfg['dnsbl_max_qps'], ['min' => 1]))->setHelp('Queries per second');
	$group->add(new Form_Input('dnsbl_concurrency', 'Parallel', 'number', (string)$cfg['dnsbl_concurrency'], ['min' => 1]))->setHelp('Addresses at once');
	$group->add(new Form_Input('dnsbl_queue_max', 'Queue', 'number', (string)$cfg['dnsbl_queue_max'], ['min' => 10]))->setHelp('Waiting addresses');
	$section->add($group)->setHelp('A flood of new sources beyond these limits is handled by the failure action instead of queueing without end.');
	$group = new Form_Group('Timeouts');
	$group->add(new Form_Input('dnsbl_timeout_ms', 'Timeout', 'number', (string)$cfg['dnsbl_timeout_ms'], ['min' => 200]))->setHelp('Per query (ms)');
	$group->add(new Form_Input('dnsbl_retries', 'Retries', 'number', (string)$cfg['dnsbl_retries'], ['min' => 0, 'max' => 5]))->setHelp('Retries');
	$group->add(new Form_Input('dnsbl_breaker_secs', 'Outage', 'number', (string)$cfg['dnsbl_breaker_secs'], ['min' => 5]))->setHelp('Failing for (s) counts as an outage');
	$section->add($group);
	$section->addInput(new Form_Input('flood_release_secs', 'Release flood offenders after (minutes)', 'number', $minutes('flood_release_secs'), ['min' => 1]));
	$form->add($section);
	print($form);

	fs_modal_form_begin('zone-edit', gettext('DNSBL zone'), $self);
?>
	<input type="hidden" name="zone_index" value="">
	<div class="mb-3"><label class="form-label" for="zone_name"><?=gettext('Name')?></label><input class="form-control" id="zone_name" name="zone_name" required></div>
	<div class="mb-3"><label class="form-label" for="zone_zone"><?=gettext('Zone')?></label><input class="form-control fs-mono" id="zone_zone" name="zone_zone" placeholder="dnsbl.example.org" required>
		<div class="form-text"><?=gettext('Write {key} where an access key goes, for example {key}.zen.dq.spamhaus.net.')?></div></div>
	<div class="mb-3"><label class="form-label" for="zone_key"><?=gettext('Access key')?></label><input class="form-control fs-mono" id="zone_key" name="zone_key" autocomplete="off" placeholder="<?=gettext('Leave empty to keep the current key')?>"></div>
	<div class="mb-3"><label class="form-label" for="zone_match"><?=gettext('Listed when the answer is')?></label><input class="form-control fs-mono" id="zone_match" name="zone_match" placeholder="any, 127.0.0.2-127.0.0.9">
		<div class="form-text"><?=gettext('"any" or addresses and ranges. Answers 127.255.255.x are errors (for example a refused public resolver) and never count as listed.')?></div></div>
	<label class="form-check"><input class="form-check-input" type="checkbox" name="zone_ipv6"> <?=gettext('The zone also lists IPv6 addresses')?></label>
<?php
	fs_modal_form_end(gettext('Save zone'), 'save_zone', '1', 'fa-floppy-disk');

/* ------------------------------------------------------------- activity */
else:
	$verdict = in_array($_GET['verdict'] ?? '', ['listed', 'clean'], true) ? $_GET['verdict'] : 'all';
	$search = trim((string)($_GET['q'] ?? ''));
	$page = max(0, (int)($_GET['page'] ?? 0));
	$total = 0;
	$rows = threatshield_dnsbl_rows($verdict, $search, 50, $page * 50, $total);
	$flood = threatshield_flood_entries();
	$check_ip = trim((string)($_POST['check'] ?? ''));
	$check = ($check_ip !== '') ? threatshield_dnsbl_lookup($check_ip, $cfg) : null;
?>
<div class="fs-tiles">
<?php
	fs_tile(gettext('Lookups'), number_format((int)($status['lookups'] ?? 0)), null, sprintf(gettext('%s per second now'), (string)($status['qps'] ?? 0)));
	fs_tile(gettext('Listed sources blocked'), number_format((int)($status['cached_listed'] ?? 0)), null, sprintf(gettext('%s found since start'), number_format((int)($status['listed'] ?? 0))));
	fs_tile(gettext('Clean sources remembered'), number_format((int)($status['cached_clean'] ?? 0)), null, sprintf(gettext('%s answered from cache'), number_format((int)($status['cache_hits'] ?? 0))));
	fs_tile(gettext('Failed lookups'), number_format((int)($status['failures'] ?? 0)), (($status['breaker'] ?? 'closed') === 'open') ? 'degraded' : null,
	    sprintf(gettext('%1$s dropped by limits'), number_format((int)($status['dropped_queue'] ?? 0) + (int)($status['dropped_ingest'] ?? 0))));
?>
</div>

<div class="panel panel-default">
	<div class="panel-heading"><h2 class="panel-title"><?=gettext('Check an address')?></h2></div>
	<div class="panel-body ts-pad">
		<form method="post" action="threatshield_inbound.php?view=activity" class="ts-log-filter">
			<input type="text" class="form-control fs-mono ts-check-ip" name="check" value="<?=htmlspecialchars($check_ip)?>" placeholder="198.51.100.7" aria-label="<?=gettext('IP address')?>" required>
			<button type="submit" class="btn btn-sm btn-outline-secondary"><i class="fa-solid fa-magnifying-glass icon-embed-btn" aria-hidden="true"></i><?=gettext('Look up now')?></button>
			<span class="form-text"><?=gettext('Asks every enabled zone directly, without the cache, and does not change any verdict.')?></span>
		</form>
<?php	if ($check !== null): ?>
		<div class="ts-check-result">
			<p><strong class="fs-mono"><?=htmlspecialchars($check_ip)?></strong>
			<?=['listed' => fs_badge('block', gettext('Listed')), 'clean' => fs_badge('pass', gettext('Clean')),
			    'fail' => fs_badge('degraded', gettext('Lookup failed')), 'skip' => fs_badge('neutral', gettext('Not checked'))][$check['verdict']] ?? ''?>
			<?=htmlspecialchars($check['reason'])?></p>
<?php		if (!empty($check['zones'])): ?>
			<table class="table table-sm">
				<thead><tr><th><?=gettext('Zone')?></th><th><?=gettext('Query')?></th><th><?=gettext('Answer')?></th></tr></thead>
				<tbody>
<?php			foreach ($check['zones'] as $id => $z):
				$answer = (($z['error'] ?? null) !== null) ? sprintf(gettext('Error: %s'), $z['error'])
				    : ((($z['rcode'] ?? null) === 3) ? gettext('Not listed') : implode(', ', (array)$z['answers']) . (empty($z['answers']) ? sprintf(gettext('Response code %d'), (int)$z['rcode']) : ''));
?>
					<tr>
						<td><?=htmlspecialchars((string)$id)?></td>
						<td class="fs-mono small"><?=htmlspecialchars(preg_replace('/[a-z0-9]{16,64}\./i', '•••.', (string)$z['qname']))?></td>
						<td class="fs-mono small"><?=htmlspecialchars($answer)?> <?=!empty($z['listed']) ? fs_badge('block', gettext('Listed')) : ''?></td>
					</tr>
<?php			endforeach; ?>
				</tbody>
			</table>
<?php		endif; ?>
		</div>
<?php	endif; ?>
	</div>
</div>

<div class="panel panel-default fs-table">
<?php
	ob_start();
?>
	<form method="get" action="threatshield_inbound.php" class="ts-log-filter">
		<input type="hidden" name="view" value="activity">
		<div class="fs-search"><i class="fa-solid fa-magnifying-glass" aria-hidden="true"></i>
			<input type="search" class="form-control" name="q" value="<?=htmlspecialchars($search)?>" placeholder="<?=gettext('Address or zone…')?>" aria-label="<?=gettext('Search')?>"></div>
		<select name="verdict" class="form-select form-select-sm" aria-label="<?=gettext('Verdict')?>" onchange="this.form.submit()">
			<option value="all"><?=gettext('All verdicts')?></option>
			<option value="listed"<?=($verdict === 'listed') ? ' selected' : ''?>><?=gettext('Listed')?></option>
			<option value="clean"<?=($verdict === 'clean') ? ' selected' : ''?>><?=gettext('Clean')?></option>
		</select>
		<button type="submit" class="btn btn-sm btn-outline-secondary"><?=gettext('Filter')?></button>
	</form>
<?php
	fs_table_toolbar(['title' => gettext('Reputation cache'), 'search' => false, 'noun' => gettext('sources'), 'custom' => ob_get_clean()]);
?>
	<div class="panel-body table-responsive">
		<table class="table table-hover table-sm">
			<thead>
				<tr>
					<th><?=gettext('Source')?></th>
					<th><?=gettext('Verdict')?></th>
					<th><?=gettext('Listed by')?></th>
					<th><?=gettext('Checked')?></th>
					<th><?=gettext('Kept until')?></th>
					<th class="ts-num"><?=gettext('Seen')?></th>
					<th class="fs-col-actions"><span class="visually-hidden"><?=gettext('Actions')?></span></th>
				</tr>
			</thead>
			<tbody>
<?php	foreach ($rows as $r): ?>
				<tr>
					<td class="fs-mono"><?=htmlspecialchars($r['ip'])?></td>
					<td><?=($r['verdict'] === 'listed') ? fs_badge('block', gettext('Listed')) : fs_badge('pass', gettext('Clean'))?></td>
					<td class="fs-mono small"><?=htmlspecialchars(str_replace(';', ', ', (string)$r['zones']))?></td>
					<td class="ts-nowrap"><?=htmlspecialchars(threatshield_age((int)$r['checked']))?></td>
					<td class="ts-nowrap"><?=htmlspecialchars(date('Y-m-d H:i', (int)$r['expires']))?></td>
					<td class="ts-num"><?=number_format((int)$r['hits'])?></td>
					<td class="fs-col-actions"><?=fs_row_actions([
						['custom', $self . '&forget=' . rawurlencode($r['ip']), $r['ip'], ['icon' => 'fa-solid fa-rotate', 'post' => true, 'label' => sprintf(gettext('Check %s again'), $r['ip'])]],
						['custom', $self . '&allow_ip=' . rawurlencode($r['ip']), $r['ip'], ['icon' => 'fa-solid fa-circle-check', 'post' => true,
						 'label' => sprintf(gettext('Always allow %s'), $r['ip']), 'confirm' => sprintf(gettext('Always allow %s?'), $r['ip']),
						 'detail' => gettext('It is added to the IP allowlist: no reputation check, IP list, GeoIP or flood limit blocks it any more.'),
						 'confirm_action' => gettext('Allow')]],
					])?></td>
				</tr>
<?php	endforeach;
	if (empty($rows)) fs_empty_row(7, ($search !== '' || $verdict !== 'all') ? gettext('No cached sources match the filter.') : gettext('No sources checked yet.'));
?>
			</tbody>
		</table>
	</div>
<?php	if ($total > 50): ?>
	<div class="panel-footer ts-pager small">
		<?=htmlspecialchars(sprintf(gettext('%1$d–%2$d of %3$d'), $page * 50 + 1, min($total, ($page + 1) * 50), $total))?>
<?php		$q = ['view' => 'activity', 'verdict' => $verdict, 'q' => $search]; ?>
		<a class="btn btn-sm btn-outline-secondary<?=($page === 0) ? ' disabled' : ''?>" href="threatshield_inbound.php?<?=htmlspecialchars(http_build_query($q + ['page' => $page - 1]))?>"><?=gettext('Newer')?></a>
		<a class="btn btn-sm btn-outline-secondary<?=(($page + 1) * 50 >= $total) ? ' disabled' : ''?>" href="threatshield_inbound.php?<?=htmlspecialchars(http_build_query($q + ['page' => $page + 1]))?>"><?=gettext('Older')?></a>
	</div>
<?php	endif; ?>
</div>

<div class="panel panel-default fs-table">
<?php fs_table_toolbar(['title' => gettext('Flood offenders'), 'search' => false, 'noun' => gettext('addresses')]); ?>
	<div class="panel-body table-responsive">
		<table class="table table-hover table-sm">
			<thead>
				<tr>
					<th><?=gettext('Address')?></th>
					<th><?=gettext('Caught by')?></th>
					<th><?=gettext('Since')?></th>
					<th class="fs-col-actions"><span class="visually-hidden"><?=gettext('Actions')?></span></th>
				</tr>
			</thead>
			<tbody>
<?php	foreach ($flood as $f): ?>
				<tr>
					<td class="fs-mono"><?=htmlspecialchars($f['ip'])?></td>
					<td><?=($f['table'] === 'virusprot') ? gettext('A firewall rule limit') : gettext('Threat Shield policy')?></td>
					<td class="ts-nowrap"><?=($f['since'] > 0) ? htmlspecialchars(threatshield_age((int)$f['since'])) : '–'?></td>
					<td class="fs-col-actions"><?=fs_row_actions([['custom', $self . '&release=' . rawurlencode($f['ip']) . '&table=' . rawurlencode($f['table']), $f['ip'],
					    ['icon' => 'fa-solid fa-unlock', 'post' => true, 'label' => sprintf(gettext('Release %s'), $f['ip'])]]])?></td>
				</tr>
<?php	endforeach;
	if (empty($flood)) fs_empty_row(4, gettext('No address is blocked for flooding.'));
?>
			</tbody>
		</table>
	</div>
	<div class="panel-footer small fs-muted">
		<i class="fa-solid fa-circle-info" aria-hidden="true"></i>
		<?=htmlspecialchars(sprintf(gettext('Offenders are released automatically after %d minutes. Firewall rules with "Max. src. conn. Rate" put offenders in the virusprot table, shown here too.'), intdiv((int)$cfg['flood_release_secs'], 60)))?>
	</div>
</div>
<?php
endif;
threatshield_ui_styles();
?>
<style>
.ts-log-filter { display: flex; flex-wrap: wrap; align-items: center; gap: var(--fs-sp-2); flex: 1 1 32rem; }
.ts-log-filter .fs-search { flex: 1 1 14rem; }
.ts-log-filter .form-select { width: auto; }
.ts-pad { padding: var(--fs-sp-3) var(--fs-sp-4) var(--fs-sp-4); }
.ts-check-ip { flex: 0 1 18rem; }
.ts-check-result { margin-top: var(--fs-sp-3); }
.ts-check-result .table { margin-bottom: 0; }
</style>
<?php include('foot.inc'); ?>
