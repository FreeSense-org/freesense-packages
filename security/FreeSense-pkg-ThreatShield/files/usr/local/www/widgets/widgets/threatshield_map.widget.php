<?php
/*
 * threatshield_map.widget.php
 * FreeSense Dashboard Widget: Threat Shield live threat map (small)
 *
 * Copyright (c) 2025-2026 The FreeSense Project.
 * Licensed under the Apache License, Version 2.0.
 */

require_once('guiconfig.inc');
require_once('/usr/local/pkg/threatshield.inc');

$cfg = threatshield_config();
$id = 'tsw-map-' . preg_replace('/[^a-z0-9_-]/i', '', (string)($widgetkey ?? 'threatshield_map-0'));
$asset = fn(string $f) => '/threatshield/assets/' . $f . '?v=' . (int)@filemtime('/usr/local/www/threatshield/assets/' . $f);

if (($cfg['enable'] ?? 'off') !== 'on'):
?>
<div class="panel-body"><p class="fs-muted mb-0"><?=gettext('Threat Shield is off.')?> <a href="/threatshield/threatshield_status.php"><?=gettext('Turn it on')?></a></p></div>
<?php
	return;
endif;
?>
<link rel="stylesheet" href="<?=$asset('threatshield_map.css')?>">
<div class="tsw">
	<div id="<?=$id?>"></div>
	<div class="tsw-foot">
		<span class="tsm-key tsm-key--block"><span><?=gettext('Blocked')?> <b data-tsw="block">0</b></span></span>
		<span class="tsm-key tsm-key--pass"><span><?=gettext('Allowed')?> <b data-tsw="pass">0</b></span></span>
		<span class="tsm-key tsm-key--dns"><span><?=gettext('DNS')?> <b data-tsw="dns">0</b></span></span>
		<a class="tsw-open" href="/threatshield/threatshield_map.php"><?=gettext('Open map')?></a>
	</div>
</div>
<style>
.tsw-foot { display: flex; flex-wrap: wrap; align-items: center; gap: .2rem .9rem; padding: .45rem .75rem; font-size: var(--fs-fs-sm); border-top: 1px solid var(--fs-border); }
.tsw-foot b { color: var(--fs-text); font-variant-numeric: tabular-nums; }
.tsw-open { margin-left: auto; }
.tsw .tsm { border-radius: 0; }
</style>
<script src="<?=$asset('ts-world.js')?>"></script>
<script src="<?=$asset('threatshield_map.js')?>"></script>
<script>
//<![CDATA[
events.push(function () {
	var el = document.getElementById(<?=json_encode($id)?>);
	if (!el || !window.TSMap || el.getAttribute('data-ready')) {
		return;
	}
	el.setAttribute('data-ready', '1');
	var map = new TSMap(el, {data: '/threatshield/threatshield_map_data.php', mode: 'widget', lite: true, poll: 10000, window: '1h',
		style: <?=json_encode((string)$cfg['map_style'] === 'hacker' ? 'hacker' : 'freesense')?>, animations: <?=json_encode((string)$cfg['map_animations'])?>,
		mask: <?=json_encode(($cfg['map_mask_ips'] ?? 'off') === 'on')?>,
		t: <?=json_encode(['geoOff' => htmlspecialchars(gettext('Turn on location data in the threat map settings.')), 'geoMissing' => htmlspecialchars(gettext('Location data is downloading.')), 'noHome' => '', 'hits' => gettext('%d connections')])?>});
	var root = el.closest('.tsw');
	map.on(function (d) {
		if (!d.counters) {
			return;
		}
		var c = d.counters, v = {block: (c.block || 0) + (c.listed || 0), pass: (c.pass || 0) + (c.clean || 0), dns: c.dns_block || 0};
		Object.keys(v).forEach(function (k) {
			root.querySelector('[data-tsw="' + k + '"]').textContent = v[k].toLocaleString();
		});
	});
});
//]]>
</script>
