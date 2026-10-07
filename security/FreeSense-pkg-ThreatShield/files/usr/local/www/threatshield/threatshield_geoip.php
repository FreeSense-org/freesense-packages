<?php
/*
 * threatshield_geoip.php
 * FreeSense Threat Shield - Native GeoIP & Country Protection
 */

##|+PRIV
##|*IDENT=page-services-threatshield
##|*NAME=Services: Threat Shield GeoIP
##|*DESCR=Configure GeoIP country blocking and PF firewall integration
##|*MATCH=threatshield/threatshield_geoip.php*
##|-PRIV

require_once('guiconfig.inc');
require_once('/usr/local/pkg/threatshield.inc');

$input_errors = [];
$savemsg = null;
$ts_config = threatshield_config();
$interfaces = threatshield_assigned_interfaces();

$all_countries = [
	'Europe' => [
		'AL' => 'Albania', 'AD' => 'Andorra', 'AT' => 'Austria', 'BY' => 'Belarus', 'BE' => 'Belgium',
		'BA' => 'Bosnia and Herzegovina', 'BG' => 'Bulgaria', 'HR' => 'Croatia', 'CY' => 'Cyprus',
		'CZ' => 'Czechia', 'DK' => 'Denmark', 'EE' => 'Estonia', 'FI' => 'Finland', 'FR' => 'France',
		'DE' => 'Germany', 'GR' => 'Greece', 'HU' => 'Hungary', 'IS' => 'Iceland', 'IE' => 'Ireland',
		'IT' => 'Italy', 'LV' => 'Latvia', 'LT' => 'Lithuania', 'LU' => 'Luxembourg', 'MT' => 'Malta',
		'MD' => 'Moldova', 'MC' => 'Monaco', 'ME' => 'Montenegro', 'NL' => 'Netherlands', 'MK' => 'North Macedonia',
		'NO' => 'Norway', 'PL' => 'Poland', 'PT' => 'Portugal', 'RO' => 'Romania', 'RU' => 'Russian Federation',
		'RS' => 'Serbia', 'SK' => 'Slovakia', 'SI' => 'Slovenia', 'ES' => 'Spain', 'SE' => 'Sweden',
		'CH' => 'Switzerland', 'UA' => 'Ukraine', 'GB' => 'United Kingdom'
	],
	'Asia' => [
		'AF' => 'Afghanistan', 'AM' => 'Armenia', 'AZ' => 'Azerbaijan', 'BH' => 'Bahrain', 'BD' => 'Bangladesh',
		'CN' => 'China', 'GE' => 'Georgia', 'HK' => 'Hong Kong', 'IN' => 'India', 'ID' => 'Indonesia',
		'IR' => 'Iran', 'IQ' => 'Iraq', 'IL' => 'Israel', 'JP' => 'Japan', 'JO' => 'Jordan',
		'KZ' => 'Kazakhstan', 'KP' => 'North Korea', 'KR' => 'South Korea', 'KW' => 'Kuwait', 'KG' => 'Kyrgyzstan',
		'LB' => 'Lebanon', 'MY' => 'Malaysia', 'MN' => 'Mongolia', 'MM' => 'Myanmar', 'PK' => 'Pakistan',
		'PS' => 'Palestine', 'PH' => 'Philippines', 'QA' => 'Qatar', 'SA' => 'Saudi Arabia', 'SG' => 'Singapore',
		'SY' => 'Syria', 'TW' => 'Taiwan', 'TH' => 'Thailand', 'TR' => 'Turkey', 'AE' => 'United Arab Emirates',
		'VN' => 'Vietnam', 'YE' => 'Yemen'
	],
	'North America' => [
		'BS' => 'Bahamas', 'BB' => 'Barbados', 'BZ' => 'Belize', 'CA' => 'Canada', 'CR' => 'Costa Rica',
		'CU' => 'Cuba', 'DO' => 'Dominican Republic', 'SV' => 'El Salvador', 'GT' => 'Guatemala', 'HT' => 'Haiti',
		'HN' => 'Honduras', 'JM' => 'Jamaica', 'MX' => 'Mexico', 'NI' => 'Nicaragua', 'PA' => 'Panama',
		'TT' => 'Trinidad and Tobago', 'US' => 'United States'
	],
	'South America' => [
		'AR' => 'Argentina', 'BO' => 'Bolivia', 'BR' => 'Brazil', 'CL' => 'Chile', 'CO' => 'Colombia',
		'EC' => 'Ecuador', 'GY' => 'Guyana', 'PY' => 'Paraguay', 'PE' => 'Peru', 'SR' => 'Suriname',
		'UY' => 'Uruguay', 'VE' => 'Venezuela'
	],
	'Africa' => [
		'DZ' => 'Algeria', 'AO' => 'Angola', 'EG' => 'Egypt', 'ET' => 'Ethiopia', 'GH' => 'Ghana',
		'KE' => 'Kenya', 'LY' => 'Libya', 'MA' => 'Morocco', 'NG' => 'Nigeria', 'ZA' => 'South Africa',
		'SD' => 'Sudan', 'TN' => 'Tunisia', 'UG' => 'Uganda', 'ZW' => 'Zimbabwe'
	],
	'Oceania' => [
		'AU' => 'Australia', 'FJ' => 'Fiji', 'NZ' => 'New Zealand', 'PG' => 'Papua New Guinea', 'WS' => 'Samoa'
	]
];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
	if (isset($_POST['save_geoip'])) {
		$ts_config['geoip_enable'] = isset($_POST['geoip_enable']) ? 'on' : 'off';
		$ts_config['geoip_countries'] = array_map('strtoupper', (array)($_POST['countries'] ?? []));
		$ts_config['geoip_update_interval'] = in_array($_POST['geoip_update_interval'] ?? '', ['6hours','12hours','daily','weekly'], true) ? $_POST['geoip_update_interval'] : 'weekly';
		$ts_config['geoip_policies'] = [[
			'id' => 'default', 'enable' => $ts_config['geoip_enable'],
			'action' => in_array($_POST['geoip_action'] ?? '', ['block_selected','allow_selected'], true) ? $_POST['geoip_action'] : 'block_selected',
			'direction' => in_array($_POST['geoip_direction'] ?? '', ['in','out','both'], true) ? $_POST['geoip_direction'] : 'in',
			'interfaces' => array_values(array_intersect(array_map('strval', (array)($_POST['geoip_interfaces'] ?? [])), array_keys($interfaces))),
			'protocol' => in_array($_POST['geoip_protocol'] ?? '', ['any','tcp','udp'], true) ? $_POST['geoip_protocol'] : 'any',
			'ports' => trim((string)($_POST['geoip_ports'] ?? 'any')) ?: 'any', 'countries' => $ts_config['geoip_countries'],
		]];
		if (threatshield_save_and_apply($ts_config, gettext('Updated Threat Shield GeoIP settings.'), $input_errors)) $savemsg = gettext('GeoIP country protection settings saved and applied to PF kernel tables.');
	} elseif (isset($_POST['update_geoip_now'])) {
		mwexec_bg('/usr/local/sbin/freesense-threatshield-update geoip force');
		$savemsg = gettext('GeoIP Country CIDR database download started in background.');
	}
}

$selected_countries = array_flip($ts_config['geoip_countries'] ?? []);
$policy = threatshield_normalize_list($ts_config['geoip_policies'] ?? [])[0] ?? ['action' => 'block_selected', 'direction' => 'in', 'interfaces' => ['wan'], 'protocol' => 'any', 'ports' => 'any'];
$policy_ifs = array_map('strval', threatshield_normalize_list($policy['interfaces'] ?? []));
$geo_on = ($ts_config['geoip_enable'] ?? 'off') === 'on';
$last_update = threatshield_last_update('geoip');

$action_labels = ['block_selected' => gettext('Block selected countries'), 'allow_selected' => gettext('Allow selected countries only')];
$direction_labels = ['in' => gettext('Inbound'), 'out' => gettext('Outbound'), 'both' => gettext('Both directions')];
$protocol_labels = ['any' => gettext('Any'), 'tcp' => 'TCP', 'udp' => 'UDP'];

$pgtitle = [gettext('Services'), gettext('Threat Shield'), gettext('GeoIP')];
$pglinks = ['', '/threatshield/threatshield_status.php', '@self'];

fs_page_action(gettext('Update database'), 'threatshield_geoip.php?update_geoip_now=1', 'fa-cloud-arrow-down', 'secondary', ['usepost' => true]);

include('head.inc');

if ($input_errors) {
	print_input_errors($input_errors);
}
if ($savemsg) {
	print_info_box($savemsg, 'success');
}

threatshield_display_tabs('geoip');

$ports = (string)($policy['ports'] ?? 'any');
fs_summary_card([
	'icon' => 'fa-earth-europe',
	'title' => gettext('Country policy'),
	'subtitle' => gettext('Enforced in the firewall with PF tables of country networks'),
	'badges' => [$geo_on ? fs_badge('enabled') : fs_badge('disabled')],
	'label' => gettext('GeoIP policy summary'),
	'facts' => [
		[gettext('Action'), $action_labels[$policy['action'] ?? 'block_selected'] ?? ''],
		[gettext('Direction'), $direction_labels[$policy['direction'] ?? 'in'] ?? ''],
		[gettext('Interfaces'), '', 'chips' => array_map(function ($k) use ($interfaces) { return $interfaces[$k] ?? strtoupper($k); }, $policy_ifs), 'empty' => gettext('None')],
		[gettext('Traffic'), ($protocol_labels[$policy['protocol'] ?? 'any'] ?? '') . ' / ' . ((strtolower($ports) === 'any') ? gettext('any port') : $ports)],
		[gettext('Database'), threatshield_age($last_update), 'note' => ($last_update > 0) ? date('Y-m-d H:i', $last_update) : ''],
	],
]);

/* raw markup as a form section, so the country picker posts with the form */
$raw_section = function ($html) {
	return new class($html) extends Form_Section {
		private $fsRaw;
		public function __construct($html) {
			parent::__construct('');
			$this->fsRaw = $html;
		}
		public function __toString() {
			return $this->fsRaw;
		}
	};
};

$save = new Form_Button('save_geoip', 'Save', null, 'fa-solid fa-floppy-disk');
$save->addClass('btn-primary');
$form = new Form($save);

$section = new Form_Section('Policy');
$section->addInput(new Form_Checkbox('geoip_enable', 'Enable', 'Enforce the country policy', $geo_on, 'on'))
	->setHelp('Adds firewall rules for the selected countries on the chosen interfaces, protocol and ports.');
$section->addInput(new Form_Select('geoip_action', 'Action', $policy['action'] ?? 'block_selected', $action_labels))
	->setHelp('"Allow only" blocks every country that is not selected.');
$section->addInput(new Form_Select('geoip_direction', 'Direction', $policy['direction'] ?? 'in', $direction_labels));
$group = new Form_MultiCheckboxGroup('Interfaces');
$group->addClass('notoggleall');
foreach ($interfaces as $key => $label) {
	$box = new Form_MultiCheckbox('geoip_interfaces[]', null, $label, in_array((string)$key, $policy_ifs, true), (string)$key);
	$box->setAttribute('id', 'geoip_if_' . $key);
	$group->add($box);
}
$group->setHelp('The policy applies to traffic on these interfaces.');
$section->add($group);
$group = new Form_Group('Traffic');
$group->add(new Form_Select('geoip_protocol', 'Protocol', $policy['protocol'] ?? 'any', $protocol_labels))
	->setHelp('Protocol');
$group->add(new Form_Input('geoip_ports', 'Ports', 'text', $ports))
	->addClass('fs-mono')->setPlaceholder('any or 22,80,443')->setHelp('Ports or ranges, comma separated, or "any"');
$section->add($group);
$section->addInput(new Form_Select('geoip_update_interval', 'Update database', (string)$ts_config['geoip_update_interval'], [
	'6hours' => gettext('Every 6 hours'),
	'12hours' => gettext('Every 12 hours'),
	'daily' => gettext('Daily'),
	'weekly' => gettext('Weekly'),
]))->setHelp('How often the country network lists are downloaded again.');
$form->add($section);

ob_start();
?>
	<div class="panel panel-default ts-countries" id="ts-countries">
		<div class="fs-toolbar">
			<div class="fs-toolbar-default">
				<h2 class="fs-toolbar-title"><?=gettext('Countries')?></h2>
				<div class="fs-search" role="search">
					<i class="fa-solid fa-magnifying-glass" aria-hidden="true"></i>
					<input type="search" class="form-control" id="ts-country-search" autocomplete="off"
					    placeholder="<?=gettext('Search countries or codes…')?>" aria-label="<?=gettext('Search countries or codes')?>">
				</div>
				<select class="form-select form-select-sm" id="ts-region" aria-label="<?=gettext('Region')?>">
					<option value=""><?=gettext('All regions')?></option>
<?php foreach (array_keys($all_countries) as $region): ?>
					<option value="<?=htmlspecialchars($region)?>"><?=htmlspecialchars(gettext($region))?></option>
<?php endforeach; ?>
				</select>
				<label class="form-check ts-only-selected">
					<input class="form-check-input" type="checkbox" id="ts-only-selected"> <?=gettext('Selected only')?>
				</label>
				<span class="fs-toolbar-spacer"></span>
				<span class="fs-toolbar-count" id="ts-country-count" aria-live="polite"></span>
				<button type="button" class="btn btn-sm btn-outline-secondary" id="ts-high-risk"
				    title="<?=gettext('Select RU, CN, KP, IR, BY and SY only')?>"><i class="fa-solid fa-triangle-exclamation icon-embed-btn" aria-hidden="true"></i><?=gettext('High-risk preset')?></button>
				<button type="button" class="btn btn-sm btn-outline-secondary" id="ts-clear"><?=gettext('Clear all')?></button>
			</div>
		</div>
		<div class="panel-body">
<?php foreach ($all_countries as $region => $c_list):
	$rid = preg_replace('/[^a-zA-Z]/', '', $region);
?>
			<fieldset class="ts-region" data-region="<?=htmlspecialchars($region)?>">
				<legend>
					<span><?=htmlspecialchars(gettext($region))?></span>
					<span class="fs-muted small ts-region-count"></span>
					<span class="ts-region-actions">
						<button type="button" class="btn btn-sm btn-link" data-ts-region="<?=$rid?>" data-ts-state="1"
						    aria-label="<?=htmlspecialchars(sprintf(gettext('Select all of %s'), gettext($region)))?>"><?=gettext('All')?></button>
						<button type="button" class="btn btn-sm btn-link" data-ts-region="<?=$rid?>" data-ts-state="0"
						    aria-label="<?=htmlspecialchars(sprintf(gettext('Select none of %s'), gettext($region)))?>"><?=gettext('None')?></button>
					</span>
				</legend>
				<div class="ts-country-grid">
<?php	foreach ($c_list as $code => $c_name): ?>
					<label class="ts-country" for="cc_<?=$code?>">
						<input class="form-check-input country-chk cont-<?=$rid?>" type="checkbox" name="countries[]" value="<?=$code?>" id="cc_<?=$code?>"<?=isset($selected_countries[$code]) ? ' checked' : ''?>>
						<span class="fs-chip fs-chip--mono fs-chip--strong"><?=$code?></span>
						<span class="ts-country-name"><?=htmlspecialchars($c_name)?></span>
					</label>
<?php	endforeach; ?>
				</div>
			</fieldset>
<?php endforeach; ?>
			<p class="fs-muted ts-country-none" hidden><?=gettext('No countries match.')?></p>
		</div>
	</div>
<?php
$form->add($raw_section(ob_get_clean()));

print($form);
?>

<style>
.ts-countries .fs-toolbar-default { flex-wrap: wrap; }
.ts-countries .form-select { width: auto; }
.ts-only-selected { display: inline-flex; align-items: center; gap: .4rem; margin: 0; white-space: nowrap; font-size: var(--fs-fs-sm); }
.ts-only-selected .form-check-input { float: none; margin: 0; }
.ts-region { margin: 0 0 var(--fs-sp-4); padding: 0; border: 0; }
.ts-region:last-of-type { margin-bottom: 0; }
.ts-region legend { display: flex; align-items: center; gap: var(--fs-sp-2); width: 100%; margin-bottom: var(--fs-sp-2); padding-bottom: var(--fs-sp-1);
	border-bottom: 1px solid var(--fs-border); font-size: var(--fs-fs-md); font-weight: 600; color: var(--fs-text-strong); }
.ts-region-actions { margin-left: auto; }
.ts-region-actions .btn { padding: 0 var(--fs-sp-2); }
.ts-country-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(12.5rem, 1fr)); gap: var(--fs-sp-1) var(--fs-sp-3); }
.ts-country { display: flex; align-items: center; gap: var(--fs-sp-2); min-width: 0; margin: 0; padding: .3rem var(--fs-sp-2);
	border: 1px solid transparent; border-radius: var(--fs-r-sm); cursor: pointer; font-weight: 400; }
.ts-country:hover { background: var(--fs-surface-raised); }
.ts-country .form-check-input { float: none; flex: none; margin: 0; }
.ts-country-name { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.ts-country:has(input:checked) { border-color: color-mix(in srgb, var(--fs-coral) 45%, transparent); background: var(--fs-accent-tint); }
@media (max-width: 575px) { .ts-country-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); } }
</style>
<script>
//<![CDATA[
events.push(function () {
	var card = document.getElementById('ts-countries');
	var boxes = card.querySelectorAll('input.country-chk');
	var search = document.getElementById('ts-country-search');
	var region = document.getElementById('ts-region');
	var only = document.getElementById('ts-only-selected');
	var none = card.querySelector('.ts-country-none');
	var countFmt = <?=json_encode(gettext('%1$s of %2$s selected'))?>;
	var regionFmt = <?=json_encode(gettext('%s selected'))?>;

	function refresh() {
		var term = search.value.trim().toLowerCase();
		var shown = 0, selected = 0;
		card.querySelectorAll('.ts-region').forEach(function (fs) {
			var visible = 0, regionSelected = 0;
			var regionOk = !region.value || fs.getAttribute('data-region') === region.value;
			fs.querySelectorAll('.ts-country').forEach(function (label) {
				var box = label.querySelector('input');
				var text = label.textContent.toLowerCase();
				var ok = regionOk && (!term || text.indexOf(term) !== -1) && (!only.checked || box.checked);
				label.hidden = !ok;
				if (ok) visible++;
				if (box.checked) regionSelected++;
			});
			fs.hidden = (visible === 0);
			fs.querySelector('.ts-region-count').textContent = regionSelected ? regionFmt.replace('%s', regionSelected) : '';
			shown += visible;
			selected += regionSelected;
		});
		none.hidden = (shown !== 0);
		document.getElementById('ts-country-count').textContent = countFmt.replace('%1$s', selected).replace('%2$s', boxes.length);
	}

	card.querySelectorAll('[data-ts-region]').forEach(function (btn) {
		btn.addEventListener('click', function () {
			var state = btn.getAttribute('data-ts-state') === '1';
			card.querySelectorAll('.cont-' + btn.getAttribute('data-ts-region')).forEach(function (el) {
				if (!el.closest('.ts-country').hidden) el.checked = state;
			});
			refresh();
		});
	});
	document.getElementById('ts-clear').addEventListener('click', function () {
		boxes.forEach(function (el) { el.checked = false; });
		refresh();
	});
	document.getElementById('ts-high-risk').addEventListener('click', function () {
		var highRisk = ['RU', 'CN', 'KP', 'IR', 'BY', 'SY'];
		boxes.forEach(function (el) { el.checked = highRisk.indexOf(el.value) !== -1; });
		refresh();
	});
	search.addEventListener('input', refresh);
	search.addEventListener('keydown', function (e) {
		if (e.key === 'Enter') e.preventDefault();    /* searching never submits the policy */
	});
	region.addEventListener('change', refresh);
	only.addEventListener('change', refresh);
	card.addEventListener('change', function (e) {
		if (e.target.classList.contains('country-chk')) refresh();
	});
	refresh();
});
//]]>
</script>

<?php include('foot.inc'); ?>
