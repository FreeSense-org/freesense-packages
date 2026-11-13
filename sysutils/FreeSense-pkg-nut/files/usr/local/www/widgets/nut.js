/*
 * nut.js — dashboard widget "UPS" (FreeSense-pkg-nut)
 *
 * part of FreeSense (https://www.freesense.org)
 * Copyright (c) 2026 The FreeSense Project
 * Licensed under the Apache License, Version 2.0.
 *
 * Data: GET /api/v1/packages/nut/status (nut.inc, plugin_restapi).
 */
(function ($, FS, D) {
	'use strict';

	var T = FS.t, el = D.el;

	/* The state from the NUT status words: OL on line, OB on battery, LB low battery, RB replace battery. */
	function state(d) {
		var w = ' ' + d.status + ' ', b = d.battery == null ? 100 : d.battery;
		if (d.alert || /\s(LB|RB|OVER)\s/.test(w)) return ['bad', 'fa-triangle-exclamation'];
		if (/\sOB\s/.test(w)) return [b < 50 ? 'bad' : 'warn', b < 25 ? 'fa-battery-empty' : (b < 50 ? 'fa-battery-quarter' : (b < 75 ? 'fa-battery-half' : 'fa-battery-three-quarters'))];
		if (/\sOL\s/.test(w)) return [b < 75 ? 'warn' : 'ok', 'fa-plug'];
		return ['bad', 'fa-circle-question'];
	}

	function meter(label, pct, sub, inverse) {
		var $r = el('div', 'fs-sysm mt-2');
		$r.append(el('div', 'fs-res-row').append(el('span', 'fs-res-label', label), el('b', 'fs-num', FS.fmt.pct(pct))));
		/* battery: low is bad, so the meter warns on the remaining share */
		$r.append(FS.chart.meter(pct, inverse ? { warn: 101, crit: 101, label: label } : { warn: 95, crit: 99, label: label }));
		if (sub) $r.append(el('small', 'fs-muted', sub));
		return $r;
	}

	D.define('nut', {
		mount: function (w) { w.$body.append(el('div', 'fs-nut')); },
		load: function (w) {
			return FS.api.get('/packages/nut/status').then(function (r) {
				var d = r.data, s = state(d), $b = w.$body.find('.fs-nut').empty();
				$b.append(el('div', 'd-flex align-items-center gap-2').append($('<i class="fa-solid fa-lg" aria-hidden="true"></i>').addClass(s[1] + ' text-' + ({ ok: 'success', warn: 'warning', bad: 'danger' }[s[0]])),
					el('strong', '', d.summary)));
				if (d.model) $b.append(el('small', 'fs-muted d-block', d.model));
				if (d.alert) $b.append(D.tag(T('The UPS requires attention'), 'bad'));
				if (d.alarm) $b.append(el('div', 'small mt-1').append(el('b', '', T('Alarm') + ': '), document.createTextNode(d.alarm)));
				if (d.runtime) $b.append(el('div', 'small mt-1').append(el('b', '', T('Runtime') + ': '), document.createTextNode(d.runtime + ' (H:M:S)')));
				if (d.load != null) {
					$b.append(meter(T('Load'), d.load, [d.input_voltage != null ? T('Vin %s V', d.input_voltage) : '', d.output_voltage != null ? T('Vout %s V', d.output_voltage) : ''].filter(Boolean).join(' · ')));
				}
				if (d.battery != null) {
					var $m = meter(T('Battery'), d.battery, d.battery_voltage != null ? T('%s V', d.battery_voltage) : '', true);
					$m.find('.fs-meter').toggleClass('fs-meter-crit', d.battery < 50).toggleClass('fs-meter-warn', d.battery >= 50 && d.battery < 75);
					$b.append($m);
				}
			});
		}
	});
})(jQuery, window.FS, window.FSDashboard);
