/*
 * fleet-box-stats.js
 *
 * part of FreeSense (https://freesense.org)
 * Copyright (c) 2025-2026 FreeSense
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

/*
 * A firewall's Stats view: charts from the controller's own records (the
 * JSON on the page) and from the firewall's RRD history, read through
 * fleet_box_metrics.php (CPU and memory, traffic per interface, gateways).
 */
(function () {
	'use strict';

	var root = document.getElementById('fs-fleet-bstats');
	if (!root || !window.FleetCharts) {
		return;
	}
	var FC = window.FleetCharts;
	var T = JSON.parse(root.getAttribute('data-strings'));
	var node = root.getAttribute('data-node'), range = root.getAttribute('data-range');
	var d = JSON.parse(root.querySelector('script[data-fleet-json]').textContent);
	var $ = function (k) { return root.querySelector('[data-chart="' + k + '"]'); };
	var esc = function (s) {
		return String(s === null || s === undefined ? '' : s).replace(/[&<>"']/g, function (c) {
			return {'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c];
		});
	};
	var sum = function (k, text) {
		var el = root.querySelector('[data-sum="' + k + '"]');
		if (el) {
			el.textContent = text;
		}
	};
	var vals = function (a) { return (a || []).filter(function (x) { return x !== null && !isNaN(x); }); };
	var avg = function (a) { var v = vals(a); return v.length ? v.reduce(function (p, c) { return p + c; }, 0) / v.length : null; };
	var peak = function (a) { var v = vals(a); return v.length ? Math.max.apply(null, v) : null; };
	var note = function (el, text) { el.innerHTML = '<p class="fs-muted mb-0">' + esc(text) + '</p>'; };
	var days = d.days.map(function (s) {
		var p = s.split('-');
		return new Date(+p[0], +p[1] - 1, +p[2]).toLocaleDateString(undefined, {day: 'numeric', month: 'short'});
	});
	var get = function (what, extra) {
		return fetch('/fleet/fleet_box_metrics.php?what=' + what + '&range=' + range + '&id=' + encodeURIComponent(node) + (extra || ''), {credentials: 'same-origin'})
		    .then(function (r) { return r.json().then(function (j) { return r.ok && !j.error ? j.history : Promise.reject(j.error || T.no_history); }); });
	};

	/* From the controller. */
	var dt = d.days.map(function (s) { var p = s.split('-'); return new Date(+p[0], +p[1] - 1, +p[2]).getTime() / 1000; });
	FC.draw($('days'), {type: 'pulse', t: dt, states: T, label: T.online, rows: [{label: '', link: '#', cells: d.day_cells}]});
	if (vals(d.states).length) {
		FC.draw($('states'), {type: 'line', t: d.t, label: T.states, series: [{name: T.states, data: d.states, fill: true, color: 7}]});
		sum('states', d.states_max ? T.limit.replace('%s', FC.short(d.states_max)) : '');
	} else {
		note($('states'), T.no_samples);
	}
	if (vals(d.temp).length) {
		FC.draw($('temp'), {type: 'line', t: d.t, unit: '°', max: 100, label: T.temp, marks: [{v: 80, label: T.warn_temp}], series: [{name: T.temp, data: d.temp, color: 8}]});
		sum('temp', T.peak.replace('%s', FC.short(peak(d.temp), ' °C')));
	} else {
		note($('temp'), vals(d.states).length ? T.no_temp : T.no_samples);
	}
	FC.draw($('alerts'), {type: 'bars', labels: days, label: T.critical, series: [{name: T.critical, data: d.alerts_day.critical, tone: 'block'},
	    {name: T.warning, data: d.alerts_day.warning, tone: 'warn'}, {name: T.info, data: d.alerts_day.info, tone: 'info'}]});
	FC.draw($('backups'), {type: 'bars', labels: days, label: T.backups, series: [{name: T.backups, data: d.backups_day, tone: 'c4'}]});

	/* From the firewall. */
	get('history').then(function (h) {
		FC.draw($('sys'), {type: 'line', t: h.t, max: 100, unit: '%', label: T.cpu, empty: T.no_history,
		    series: [{name: T.cpu, data: h.cpu, color: 1}, {name: T.memory, data: h.mem, color: 3}]});
		var a = avg(h.cpu);
		sum('sys', a === null ? '' : T.cpu + ' ' + T.avg.replace('%s', FC.short(a, ' %')));
	}, function (e) { note($('sys'), e); });

	get('gateways').then(function (h) {
		var names = Object.keys(h.gateways || {});
		if (!names.length) {
			note($('gw'), T.no_gw);
			return;
		}
		var el = $('gw');
		el.innerHTML = names.map(function (n, k) { return '<div class="fs-fleet-gw" data-gw="' + k + '"><h4 class="fs-fleet-gw-name">' + esc(n) + '</h4><div></div></div>'; }).join('');
		names.forEach(function (n, k) {
			var g = h.gateways[n];
			FC.draw(el.querySelector('[data-gw="' + k + '"] div'), {type: 'line', t: h.t, unit: ' ms', height: 150, label: n, legend: true,
			    series: [{name: T.delay, data: g.delay, color: 3}, {name: T.stddev, data: g.stddev, dash: true, color: 5},
			    {name: T.loss + ' %', data: g.loss, color: 8}]});
		});
		var d0 = h.gateways[names[0]];
		sum('gw', names[0] + ' ' + T.avg.replace('%s', FC.short(avg(d0.delay), ' ms')));
	}, function (e) { note($('gw'), e); });

	var chips = root.querySelector('[data-ifs]');
	var traffic = function (ifn) {
		chips.querySelectorAll('button').forEach(function (b) { b.setAttribute('aria-pressed', b.getAttribute('data-if') === ifn ? 'true' : 'false'); });
		get('traffic', '&if=' + encodeURIComponent(ifn)).then(function (h) {
			FC.draw($('traffic'), {type: 'line', t: h.t, unit: 'b/s', label: ifn, empty: T.no_history,
			    series: [{name: T['in'], data: h.in_bps, fill: true, color: 6}, {name: T.out, data: h.out_bps, fill: true, color: 1}]});
			sum('traffic', T.peak.replace('%s', FC.short(peak((h.in_bps || []).concat(h.out_bps || [])), 'b/s')));
		}, function (e) { note($('traffic'), e); });
	};
	get('ifs').then(function (ifs) {
		ifs.sort(function (a, b) { return (a.name === 'wan' ? -1 : 0) - (b.name === 'wan' ? -1 : 0); });
		chips.innerHTML = ifs.map(function (i) {
			return '<button type="button" class="btn btn-sm btn-outline-secondary" data-if="' + esc(i.name) + '" aria-pressed="false">' + esc(i.label) + '</button>';
		}).join('');
		chips.addEventListener('click', function (ev) {
			var b = ev.target.closest('button[data-if]');
			if (b) {
				traffic(b.getAttribute('data-if'));
			}
		});
		if (ifs.length) {
			traffic(ifs[0].name);
		}
	}, function (e) { note($('traffic'), e); });
}());
