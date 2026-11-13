/*
 * threatshield-map.js — dashboard widget "Threat map" (FreeSense-pkg-ThreatShield)
 *
 * part of FreeSense (https://www.freesense.org)
 * Copyright (c) 2026 The FreeSense Project
 * Licensed under the Apache License, Version 2.0.
 *
 * The threat map (threatshield/assets: TSMap) in a widget. Settings come
 * from GET /api/v1/packages/threatshield/map-config; TSMap polls
 * threatshield_map_data.php itself every 10 seconds, so the widget has no
 * refresh interval of its own.
 */
(function ($, FS, D) {
	'use strict';

	var T = FS.t, el = D.el;
	var loading = null;

	/* The map's stylesheet and scripts, loaded once for every copy of the widget. */
	function assets() {
		if (loading) return loading;
		var base = '/threatshield/assets/';
		$('<link rel="stylesheet">').attr('href', base + 'threatshield_map.css').appendTo('head');
		function script(src) {
			return new Promise(function (resolve, reject) {
				var s = document.createElement('script');
				s.src = base + src;
				s.onload = resolve;
				s.onerror = reject;
				document.head.appendChild(s);
			});
		}
		loading = script('ts-world.js').then(function () { return script('threatshield_map.js'); });
		return loading;
	}

	D.define('threatshield-map', {
		mount: function (w) {
			w.$body.addClass('p-0');
			w.state.$map = el('div', 'tsw-map').attr('id', 'tsw-map-' + w.id);
			var $foot = el('div', 'tsw-foot');
			[['block', 'Blocked'], ['pass', 'Allowed'], ['dns', 'DNS']].forEach(function (k) {
				$foot.append(el('span', 'tsm-key tsm-key--' + k[0]).append(el('span', '', T(k[1]) + ' ').append(el('b', '', '0').attr('data-tsw', k[0]))));
			});
			$foot.append($('<a class="tsw-open" href="/threatshield/threatshield_map.php"></a>').text(T('Open map')));
			w.$body.append(el('div', 'tsw').append(w.state.$map, $foot));
		},
		load: function (w) {
			if (w.state.map) return Promise.resolve();
			return FS.api.get('/packages/threatshield/map-config').then(function (r) {
				var c = r.data;
				if (!c.enabled) {
					w.$body.removeClass('p-0').empty().append(el('p', 'fs-muted mb-0', T('Threat Shield is off.') + ' ')
						.append($('<a href="/threatshield/threatshield_status.php"></a>').text(T('Turn it on'))));
					return;
				}
				return assets().then(function () {
					var map = new window.TSMap(w.state.$map[0], {
						data: '/threatshield/threatshield_map_data.php', mode: 'widget', lite: true, poll: 10000, window: '1h',
						style: c.style, animations: c.animations, mask: c.mask,
						t: { geoOff: T('Turn on location data in the threat map settings.'), geoMissing: T('Location data is downloading.'), noHome: '', hits: T('%d connections') }
					});
					map.on(function (d) {
						if (!d.counters) return;
						var x = d.counters, v = { block: (x.block || 0) + (x.listed || 0), pass: (x.pass || 0) + (x.clean || 0), dns: x.dns_block || 0 };
						Object.keys(v).forEach(function (k) { w.$body.find('[data-tsw="' + k + '"]').text(v[k].toLocaleString()); });
					});
					w.state.map = map;
				});
			});
		},
		destroy: function (w) {
			if (w.state.map && typeof w.state.map.destroy === 'function') w.state.map.destroy();
			w.state.map = null;
		}
	});
})(jQuery, window.FS, window.FSDashboard);
