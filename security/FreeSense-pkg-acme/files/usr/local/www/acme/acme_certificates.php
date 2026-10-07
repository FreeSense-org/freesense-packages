<?php
/*
 * acme_certificates.php
 *
 * part of FreeSense (https://www.freesense.org/)
 * Copyright (c) 2016 PiBa-NL
 * All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

namespace pfsense_pkg\acme;

$shortcut_section = "acme";
require_once("guiconfig.inc");
require_once("freesense-utils.inc");
require_once("certs.inc");
require_once("acme/acme.inc");
require_once("acme/acme_gui.inc");
require_once("acme/acme_utils.inc");
require_once("acme/pkg_acme_tabs.inc");

$changedesc = "Services: ACME: Certificates";

if($_POST['action'] == "toggle") {
	$id = $_POST['id'];
	echo "$id|";
	if (config_get_path('installedpackages/acme/certificates/item/' . get_certificate_id($id)) !== null) {
		if (config_get_path('installedpackages/acme/certificates/item/' . get_certificate_id($id) . '/status') != "disabled"){
			config_set_path('installedpackages/acme/certificates/item/' . get_certificate_id($id) . '/status', 'disabled');
			echo "0|";
		}else{
			config_set_path('installedpackages/acme/certificates/item/' . get_certificate_id($id) . '/status', 'active');
			echo "1|";
		}
		$changedesc .= " set item '$id' status to: " . config_get_path('installedpackages/acme/certificates/item/' . get_certificate_id($id) . '/status');

		write_config($changedesc);
	}
	echo "ok|";
	exit;
}
if($_POST['action'] == "issuecert") {
	$id = $_POST['id'];
	echo $id . "\n";
	if (config_get_path('installedpackages/acme/certificates/item/' . get_certificate_id($id)) !== null) {
		issue_certificate($id, true);
	}
	exit;
}
if($_POST['action'] == "renewcert") {
	$id = $_POST['id'];
	echo $id . "\n";
	if (config_get_path('installedpackages/acme/certificates/item/' . get_certificate_id($id)) !== null) {
		issue_certificate($id, true, true);
	}
	exit;
}

if ($_POST) {
	$pconfig = $_POST;

	if ($_POST['del_x']) {
		/* delete selected rules */
		$deleted = false;
		if (is_array($_POST['rule']) && count($_POST['rule'])) {
			$selected = array();
			foreach($_POST['rule'] as $selection) {
				$selected[] = get_certificate_id($selection);
			}
			foreach ($selected as $itemnr) {
				config_del_path("installedpackages/acme/certificates/item/{$itemnr}");
				$deleted = true;
			}
			if ($deleted) {
				write_config("Acme, deleting certificate(s)");
			}
			header("Location: acme_certificates.php");
			exit;
		}
	} else {
		/* a hidden move_<name> submit button moves the checked entries before <name> */
		unset($movebtn);
		/* the target name comes from the button value: PHP turns "." and spaces in
		 * POST field names into "_", so the field name itself is not usable */
		foreach ($_POST as $pn => $pd) {
			if ((strpos($pn, 'move_') === 0) && is_string($pd) && (strpos($pd, 'move_') === 0)) {
				$movebtn = substr($pd, 5);
			}
		}

		if (isset($movebtn) && is_array($_POST['rule']) && count($_POST['rule'])) {
			$moveto = get_certificate_id($movebtn);
			$selected = array();
			foreach($_POST['rule'] as $selection) {
				$selected[] = get_certificate_id($selection);
			}
			$a_certificates = config_get_path('installedpackages/acme/certificates/item', []);
			array_moveitemsbefore($a_certificates, $moveto, $selected);
			config_set_path('installedpackages/acme/certificates/item', $a_certificates);

			write_config($changedesc);
		}
	}
}

/* Delete one certificate entry. The row action posts (usepost); a plain GET no longer deletes. */
if ($_POST['act'] == "del") {
	$id = $_POST['id'];
	$id = get_certificate_id($id);
	if (config_get_path("installedpackages/acme/certificates/item/{$id}") !== null) {
		if (!$input_errors) {
			config_del_path("installedpackages/acme/certificates/item/{$id}");
			$changedesc .= " Item delete";
			write_config($changedesc);
		}
		header("Location: acme_certificates.php");
		exit;
	}
}

$a_certificates = config_get_path('installedpackages/acme/certificates/item', []);
$a_accountkeys = config_get_path('installedpackages/acme/accountkeys/item', []);
$account_descr = [];
foreach ($a_accountkeys as $acctkey) {
	if (is_array($acctkey) && !empty($acctkey['name'])) {
		$account_descr[$acctkey['name']] = $acctkey['descr'] ?? '';
	}
}

/* Expiry of the certificate ACME stored in the Certificate Manager (same name), or null */
$issued_expiry = function ($name) {
	$issued = lookup_cert_by_name($name)['item'] ?? null;
	if (empty($issued['crt'])) {
		return null;
	}
	$details = openssl_x509_parse(base64_decode($issued['crt']));
	if (empty($details['validTo_time_t'])) {
		return null;
	}
	return (int)$details['validTo_time_t'];
};

$rows = [];
$counts = ['active' => 0, 'disabled' => 0, 'issued' => 0, 'expiring' => 0, 'expired' => 0];
$now = time();
foreach ($a_certificates as $certificate) {
	if (!is_array($certificate)) {
		continue;
	}
	$domains = [];
	$methods = [];
	$method = "";
	foreach (($certificate['a_domainlist']['item'] ?? []) as $domain) {
		if (!is_array($domain) || ($domain['status'] ?? '') == 'disable') {
			continue;
		}
		$domains[] = $domain['name'] ?? '';
		$method = $domain['method'] ?? '';
		$methods[$method] = $acme_domain_validation_method[$method]['name'] ?? $method;
	}
	$expires = $issued_expiry($certificate['name']);
	$state = 'none';
	if ($expires !== null) {
		$counts['issued']++;
		if ($expires < $now) {
			$state = 'expired';
			$counts['expired']++;
		} elseif ($expires < $now + 30 * 86400) {
			$state = 'expiring';
			$counts['expiring']++;
		} else {
			$state = 'valid';
		}
	}
	$disabled = ($certificate['status'] ?? '') != 'active';
	$counts[$disabled ? 'disabled' : 'active']++;
	$rows[] = [
		'cert' => $certificate,
		'disabled' => $disabled,
		'domains' => array_values(array_filter($domains, 'strlen')),
		'methods' => $methods,
		'method' => $method,
		'expires' => $expires,
		'state' => $state,
	];
}

$pgtitle = array(gettext("Services"), gettext("ACME"), gettext("Certificates"));
$pglinks = array("", "acme_certificates.php", "@self");
fs_page_action(gettext('Add certificate'), 'acme_certificates_edit.php', 'fa-plus');
include("head.inc");
if ($input_errors) {
	print_input_errors($input_errors);
}
if ($savemsg) {
	print_info_box($savemsg);
}

display_top_tabs_active($acme_tab_array['acme'], "certificates");
?>
<style>
.fs-acme-sub { display: block; font-size: var(--fs-fs-xs); color: var(--fs-text-muted); }
.fs-acme-num { white-space: nowrap; font-variant-numeric: tabular-nums; }
.fs-acme-output .panel-heading { display: flex; align-items: center; gap: .5rem; }
.fs-acme-output .panel-heading .panel-title { margin-right: auto; }
.fs-acme-output .fs-console { margin: 0; white-space: pre-wrap; }
</style>

<div class="panel panel-default fs-acme-output d-none" id="renewoutputbox" role="region" aria-labelledby="renewoutput-title">
	<div class="panel-heading">
		<h2 class="panel-title" id="renewoutput-title"><?=gettext('Issue / renew output')?></h2>
		<button type="button" class="btn btn-sm btn-outline-secondary" data-fs-copy="#renewoutput"><i class="fa-regular fa-copy icon-embed-btn" aria-hidden="true"></i><?=gettext('Copy')?></button>
		<button type="button" class="btn-close" id="renewoutputclose" aria-label="<?=gettext('Close output')?>"></button>
	</div>
	<pre class="fs-console" id="renewoutput" aria-live="polite"></pre>
</div>

<?php if (!empty($rows)): ?>
<div class="fs-tiles">
<?php
	fs_tile(gettext('Certificates'), count($rows), null, $counts['disabled'] ? sprintf(gettext('%d disabled'), $counts['disabled']) : gettext('All renew automatically'));
	fs_tile(gettext('Issued'), $counts['issued'], null, gettext('Present in the Certificate Manager'));
	fs_tile(gettext('Expiring soon'), $counts['expiring'], $counts['expiring'] ? 'warn' : null, gettext('Within 30 days'));
	fs_tile(gettext('Expired'), $counts['expired'], $counts['expired'] ? 'expired' : null);
?>
</div>
<?php endif; ?>

<form action="acme_certificates.php" method="post">
<div class="panel panel-default fs-table">
<?php fs_table_toolbar([
	'title' => gettext('Certificates'),
	'search' => gettext('Search certificates…'),
	'noun' => gettext('certificates'),
	'noun_one' => gettext('certificate'),
	'filters' => [
		'state' => [gettext('All states'), 'active' => gettext('Active'), 'disabled' => gettext('Disabled')],
		'expiry' => [gettext('Any expiry'), 'valid' => gettext('Valid'), 'expiring' => gettext('Expiring soon'),
		    'expired' => gettext('Expired'), 'none' => gettext('Not issued')],
	],
	'bulk' => [
		['name' => 'del_x', 'label' => gettext('Delete'), 'icon' => 'fa-trash-can', 'variant' => 'danger',
		 'value' => gettext('Delete selected certificates'), 'confirm' => gettext('Delete the selected certificates?')],
	],
]); ?>
	<div class="panel-body table-responsive">
		<table class="table table-hover table-rowdblclickedit" data-sortable>
			<thead>
				<tr>
					<th class="fs-col-select" data-sortable="false"><input type="checkbox" data-fs-select-all aria-label="<?=gettext('Select all')?>"></th>
					<th class="fs-col-status"><?=gettext('Status')?></th>
					<th data-fs-search><?=gettext('Certificate')?></th>
					<th data-fs-search><?=gettext('Domains')?></th>
					<th data-fs-search><?=gettext('Account key')?></th>
					<th data-sortable-type="numeric"><?=gettext('Expires')?></th>
					<th data-sortable-type="numeric"><?=gettext('Last renewed')?></th>
					<th class="fs-col-actions" data-sortable="false"><span class="visually-hidden"><?=gettext('Actions')?></span></th>
				</tr>
			</thead>
			<tbody>
<?php foreach ($rows as $row):
	$certificate = $row['cert'];
	$name = (string)$certificate['name'];
	$hname = htmlspecialchars($name);
	$uname = rawurlencode($name);
	$more = array_slice($row['domains'], 3);
	$actions = [];
	$actions[] = ['edit', "acme_certificates_edit.php?id={$uname}", $name];
	$actions[] = ['copy', "acme_certificates_edit.php?dup={$uname}", $name];
	$actions[] = ['custom', '#', $name, ['icon' => $row['disabled'] ? 'fa-toggle-off' : 'fa-toggle-on',
	    'label' => sprintf($row['disabled'] ? gettext('Enable %s') : gettext('Disable %s'), $name),
	    'attrs' => ['data-acme-toggle' => $name]]];
	if ($row['method'] == "dns_manual") {
		$actions[] = ['custom', '#', $name, ['icon' => 'fa-arrows-rotate', 'label' => sprintf(gettext('Renew %s'), $name),
		    'attrs' => ['data-acme-run' => 'renewcert', 'data-acme-id' => $name, 'id' => "btnrenew_{$name}"]]];
		$actions[] = ['custom', '#', $name, ['icon' => 'fa-certificate', 'label' => sprintf(gettext('Issue %s'), $name),
		    'attrs' => ['data-acme-run' => 'issuecert', 'data-acme-id' => $name, 'id' => "btnissue_{$name}"]]];
	} else {
		$actions[] = ['custom', '#', $name, ['icon' => 'fa-certificate', 'label' => sprintf(gettext('Issue or renew %s'), $name),
		    'attrs' => ['data-acme-run' => 'issuecert', 'data-acme-id' => $name, 'id' => "btnissue_{$name}"]]];
	}
	$actions[] = ['custom', '#', $name, ['icon' => 'fa-anchor', 'label' => sprintf(gettext('Move selected certificates before %s'), $name),
	    'attrs' => ['data-acme-move' => "move_{$name}"]]];
	$actions[] = ['delete', "acme_certificates.php?act=del&id={$uname}", $name, ['thing' => gettext('certificate'),
	    'detail' => gettext('The issued certificate stays in the Certificate Manager.')]];
	$badge = $row['disabled'] ? fs_badge('disabled') : fs_badge('enabled', gettext('Active'));
?>
				<tr data-fs-filter-state="<?=$row['disabled'] ? 'disabled' : 'active'?>" data-fs-filter-expiry="<?=$row['state']?>"<?=$row['disabled'] ? ' class="fs-row-disabled"' : ''?>>
					<td><input type="checkbox" id="frc<?=$hname?>" name="rule[]" value="<?=$hname?>" data-fs-select aria-label="<?=htmlspecialchars(sprintf(gettext('Select %s'), $name))?>"></td>
					<td data-value="<?=$row['disabled'] ? 1 : 0?>"><?=$badge?></td>
					<td>
						<a href="acme_certificates_edit.php?id=<?=htmlspecialchars($uname)?>"><strong><?=$hname?></strong></a>
<?php if (!empty($certificate['descr'])): ?>
						<span class="fs-acme-sub"><?=htmlspecialchars($certificate['descr'])?></span>
<?php endif; ?>
					</td>
					<td>
<?php if (empty($row['domains'])): ?>
						<span class="fs-muted">—</span>
<?php else: ?>
						<div class="fs-chips">
<?php foreach (array_slice($row['domains'], 0, 3) as $domain): ?>
							<span class="fs-chip fs-chip--mono"><?=htmlspecialchars($domain)?></span>
<?php endforeach; ?>
<?php if (!empty($more)): ?>
							<span class="fs-chip fs-chip--mono fs-chip--muted" title="<?=htmlspecialchars(implode(', ', $more))?>">+<?=count($more)?></span>
<?php endif; ?>
						</div>
						<span class="fs-acme-sub"><?=htmlspecialchars(implode(', ', $row['methods']))?></span>
<?php endif; ?>
					</td>
					<td>
						<?=htmlspecialchars($certificate['acmeaccount'] ?? '')?>
<?php if (!empty($account_descr[$certificate['acmeaccount'] ?? ''])): ?>
						<span class="fs-acme-sub"><?=htmlspecialchars($account_descr[$certificate['acmeaccount']])?></span>
<?php endif; ?>
					</td>
					<td class="fs-acme-num" data-value="<?=(int)$row['expires']?>">
<?php if ($row['expires'] === null): ?>
						<span class="fs-muted"><?=gettext('Not issued')?></span>
<?php else: ?>
						<?=htmlspecialchars(date('Y-m-d', $row['expires']))?>
<?php	if ($row['state'] == 'expired'): ?>
						<?=fs_badge('expired')?>
<?php	elseif ($row['state'] == 'expiring'): ?>
						<?=fs_badge('warn', sprintf(ngettext('%d day', '%d days', $days_left = max(0, (int)floor(($row['expires'] - $now) / 86400))), $days_left))?>
<?php	endif; ?>
<?php endif; ?>
					</td>
					<td class="fs-acme-num" data-value="<?=(int)($certificate['lastrenewal'] ?? 0)?>">
<?php if (empty($certificate['lastrenewal'])): ?>
						<span class="fs-muted"><?=gettext('Never')?></span>
<?php else: ?>
						<?=htmlspecialchars(cert_format_date('', $certificate['lastrenewal'], true))?>
<?php endif; ?>
					</td>
					<td class="fs-col-actions">
						<button class="d-none" type="submit" id="move_<?=$hname?>" name="move_<?=$hname?>" value="move_<?=$hname?>" tabindex="-1" aria-hidden="true"></button>
						<?=fs_row_actions($actions)?>
					</td>
				</tr>
<?php endforeach; ?>
<?php if (empty($rows)) {
	fs_empty_row(8, gettext('No certificates yet.'), 'acme_certificates_edit.php', gettext('Add certificate'));
} ?>
			</tbody>
		</table>
	</div>
</div>
</form>

<div class="infoblock">
	<?php print_callout(gettext('Select certificates and use the anchor action on another row to move them before it. Sorting by a column header only changes the view, not the stored order. Issue/renew runs acme.sh now and shows its output above.'), 'info'); ?>
</div>

<script type="text/javascript">
//<![CDATA[
events.push(function() {
	var output = document.getElementById('renewoutput');
	var outputbox = document.getElementById('renewoutputbox');
	var running = <?=json_encode(gettext('Running acme.sh for %s…'))?>;
	var failed = <?=json_encode(gettext('The request failed.'))?>;

	document.getElementById('renewoutputclose').addEventListener('click', function () {
		outputbox.classList.add('d-none');
	});

	/* issue / renew: POST action=issuecert|renewcert, show the acme.sh output */
	$(document).on('click', '[data-acme-run]', function (e) {
		e.preventDefault();
		var a = this;
		var icon = a.querySelector('i');
		var iconClass = icon.className;
		var id = a.getAttribute('data-acme-id');
		icon.className = 'fa-solid fa-gear fa-spin';
		outputbox.classList.remove('d-none');
		output.textContent = running.replace('%s', id);
		$.ajax({
			url: '',
			type: 'post',
			data: {id: id, action: a.getAttribute('data-acme-run')},
			success: function (data) {
				output.textContent = data;
				icon.className = iconClass;
			},
			error: function () {
				output.textContent = failed;
				icon.className = 'fa-solid fa-link-slash';
			}
		});
	});

	/* enable / disable: POST action=toggle, the server answers "id|1|ok|" or "id|0|ok|" */
	$(document).on('click', '[data-acme-toggle]', function (e) {
		e.preventDefault();
		var icon = this.querySelector('i');
		icon.className = 'fa-solid fa-gear fa-spin';
		$.ajax({
			url: '',
			type: 'post',
			data: {id: this.getAttribute('data-acme-toggle'), action: 'toggle'},
			complete: function () {
				window.location.reload();
			}
		});
	});

	/* move the checked rows before this one (hidden move_<name> submit button) */
	$(document).on('click', '[data-acme-move]', function (e) {
		e.preventDefault();
		var btn = document.getElementById(this.getAttribute('data-acme-move'));
		if (btn) {
			btn.click();
		}
	});
});
//]]>
</script>
<?php include("foot.inc");
