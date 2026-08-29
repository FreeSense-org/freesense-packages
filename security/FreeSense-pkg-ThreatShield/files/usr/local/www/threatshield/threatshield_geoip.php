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

$pgtitle = [gettext('Services'), gettext('Threat Shield'), gettext('GeoIP Country Shield')];
$pglinks = ['', '@self', '@self'];

include('head.inc');

if ($savemsg) {
	print_info_box($savemsg, 'success');
}

threatshield_display_tabs('geoip');
?>

<div class="d-flex flex-wrap justify-content-between align-items-center gap-3 mb-3">
	<div>
		<h2 class="h3 mb-1"><i class="fa-solid fa-earth-americas text-primary me-2"></i><?=gettext('GeoIP & Country Shield')?></h2>
		<p class="text-muted mb-0"><?=gettext('Block network connections by country at wire-speed using native PF kernel firewall tables.')?></p>
	</div>
	<div class="d-flex gap-2">
		<form method="post" class="d-inline">
			<input type="hidden" name="update_geoip_now" value="1">
			<button type="submit" class="btn btn-outline-primary"><i class="fa-solid fa-cloud-arrow-down me-2"></i><?=gettext('Update GeoIP Database')?></button>
		</form>
	</div>
</div>

<form method="post" action="threatshield_geoip.php">
	<div class="card shadow-sm mb-3">
		<div class="card-header">
			<h2 class="h5 mb-0"><i class="fa-solid fa-shield-halved text-primary me-2"></i><?=gettext('GeoIP Enforcement Policy')?></h2>
		</div>
		<div class="card-body">
			<div class="form-check form-switch mb-3">
				<input class="form-check-input" type="checkbox" name="geoip_enable" id="geoip_enable" <?=$ts_config['geoip_enable'] === 'on' ? 'checked' : ''?>>
				<label class="form-check-label fw-semibold" for="geoip_enable">
					<?=gettext('Enable Native GeoIP Country Blocking')?>
				</label>
				<div class="form-text"><?=gettext('Enforces wire-speed PF country policies on the selected interface, protocol, and ports.')?></div>
			</div>

			<div class="row g-3"><div class="col-md-3"><label class="form-label"><?=gettext('Action')?></label><select class="form-select" name="geoip_action"><option value="block_selected" <?=($policy['action'] ?? '') === 'block_selected' ? 'selected' : ''?>><?=gettext('Block selected countries')?></option><option value="allow_selected" <?=($policy['action'] ?? '') === 'allow_selected' ? 'selected' : ''?>><?=gettext('Allow selected countries only')?></option></select></div><div class="col-md-3"><label class="form-label"><?=gettext('Direction')?></label><select class="form-select" name="geoip_direction"><option value="in" <?=($policy['direction'] ?? '') === 'in' ? 'selected' : ''?>><?=gettext('Inbound')?></option><option value="out" <?=($policy['direction'] ?? '') === 'out' ? 'selected' : ''?>><?=gettext('Outbound')?></option><option value="both" <?=($policy['direction'] ?? '') === 'both' ? 'selected' : ''?>><?=gettext('Both')?></option></select></div><div class="col-md-3"><label class="form-label"><?=gettext('Protocol')?></label><select class="form-select" name="geoip_protocol"><option value="any" <?=($policy['protocol'] ?? '') === 'any' ? 'selected' : ''?>><?=gettext('Any')?></option><option value="tcp" <?=($policy['protocol'] ?? '') === 'tcp' ? 'selected' : ''?>>TCP</option><option value="udp" <?=($policy['protocol'] ?? '') === 'udp' ? 'selected' : ''?>>UDP</option></select></div><div class="col-md-3"><label class="form-label"><?=gettext('Ports/ranges')?></label><input class="form-control" name="geoip_ports" value="<?=htmlspecialchars((string)($policy['ports'] ?? 'any'))?>" placeholder="any or 22,80,443"></div></div>
			<div class="mt-3"><label for="geoip_update_interval" class="form-label fw-semibold"><?=gettext('GeoIP update interval')?></label><select class="form-select" name="geoip_update_interval" id="geoip_update_interval"><option value="6hours" <?=$ts_config['geoip_update_interval'] === '6hours' ? 'selected' : ''?>><?=gettext('Every 6 hours')?></option><option value="12hours" <?=$ts_config['geoip_update_interval'] === '12hours' ? 'selected' : ''?>><?=gettext('Every 12 hours')?></option><option value="daily" <?=$ts_config['geoip_update_interval'] === 'daily' ? 'selected' : ''?>><?=gettext('Daily')?></option><option value="weekly" <?=$ts_config['geoip_update_interval'] === 'weekly' ? 'selected' : ''?>><?=gettext('Weekly')?></option></select></div>
			<div class="mt-3"><label class="form-label fw-semibold"><?=gettext('Bind policy to interfaces')?></label><?php foreach ($interfaces as $key => $label): ?><label class="form-check form-check-inline"><input class="form-check-input" type="checkbox" name="geoip_interfaces[]" value="<?=$key?>" <?=in_array($key, threatshield_normalize_list($policy['interfaces'] ?? []), true) ? 'checked' : ''?>> <?=htmlspecialchars($label)?></label><?php endforeach; ?></div>
		</div>
	</div>

	<div class="card shadow-sm mb-4">
		<div class="card-header d-flex justify-content-between align-items-center">
			<h2 class="h5 mb-0"><i class="fa-solid fa-flag text-primary me-2"></i><?=gettext('Country & Region Selection')?></h2>
			<div class="btn-group">
				<button type="button" class="btn btn-sm btn-outline-danger" onclick="selectHighRisk()"><i class="fa-solid fa-triangle-exclamation me-1"></i><?=gettext('High-Risk Preset')?></button>
				<button type="button" class="btn btn-sm btn-outline-secondary" onclick="clearAllCountries()"><?=gettext('Clear All')?></button>
			</div>
		</div>
		<div class="card-body">
			<ul class="nav nav-pills mb-3" id="pills-tab" role="tablist">
				<?php $first = true; foreach ($all_countries as $continent => $c_list): ?>
					<li class="nav-item" role="presentation">
						<button class="nav-link <?=$first ? 'active' : ''?>" id="tab-<?=preg_replace('/[^a-zA-Z]/', '', $continent)?>" data-bs-toggle="pill" data-bs-target="#content-<?=preg_replace('/[^a-zA-Z]/', '', $continent)?>" type="button" role="tab">
							<?=$continent?>
						</button>
					</li>
				<?php $first = false; endforeach; ?>
			</ul>

			<div class="tab-content" id="pills-tabContent">
				<?php $first = true; foreach ($all_countries as $continent => $c_list): ?>
					<div class="tab-pane fade <?=$first ? 'show active' : ''?>" id="content-<?=preg_replace('/[^a-zA-Z]/', '', $continent)?>" role="tabpanel">
						<div class="mb-3">
							<button type="button" class="btn btn-sm btn-outline-primary" onclick="toggleContinent('<?=preg_replace('/[^a-zA-Z]/', '', $continent)?>', true)"><?=gettext('Select All')?> <?=$continent?></button>
							<button type="button" class="btn btn-sm btn-outline-secondary" onclick="toggleContinent('<?=preg_replace('/[^a-zA-Z]/', '', $continent)?>', false)"><?=gettext('Deselect All')?></button>
						</div>
						<div class="row row-cols-1 row-cols-sm-2 row-cols-md-3 row-cols-lg-4 g-2">
							<?php foreach ($c_list as $code => $c_name): ?>
								<div class="col">
									<div class="form-check">
										<input class="form-check-input country-chk cont-<?=preg_replace('/[^a-zA-Z]/', '', $continent)?>" type="checkbox" name="countries[]" value="<?=$code?>" id="cc_<?=$code?>" <?=isset($selected_countries[$code]) ? 'checked' : ''?>>
										<label class="form-check-label small" for="cc_<?=$code?>">
											<span class="fw-bold font-monospace">[<?=$code?>]</span> <?=htmlspecialchars($c_name)?>
										</label>
									</div>
								</div>
							<?php endforeach; ?>
						</div>
					</div>
				<?php $first = false; endforeach; ?>
			</div>
		</div>
		<div class="card-footer">
			<button type="submit" name="save_geoip" value="1" class="btn btn-primary"><i class="fa-solid fa-floppy-disk me-2"></i><?=gettext('Save & Apply GeoIP Rules')?></button>
		</div>
	</div>
</form>

<script>
function toggleContinent(contClass, state) {
	document.querySelectorAll('.cont-' + contClass).forEach(function(el) {
		el.checked = state;
	});
}
function clearAllCountries() {
	document.querySelectorAll('.country-chk').forEach(function(el) {
		el.checked = false;
	});
}
function selectHighRisk() {
	const highRisk = ['RU', 'CN', 'KP', 'IR', 'BY', 'SY'];
	clearAllCountries();
	highRisk.forEach(function(code) {
		const el = document.getElementById('cc_' + code);
		if (el) el.checked = true;
	});
}
</script>

<?php include('foot.inc'); ?>
