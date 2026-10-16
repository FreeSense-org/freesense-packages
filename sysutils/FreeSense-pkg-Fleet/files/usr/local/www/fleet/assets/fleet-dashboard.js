/*
 * fleet-dashboard.js
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
 * The Overview and Trends views of the Fleet dashboard: draws their
 * charts (fleet-charts.js) from the JSON the page carries, and refreshes
 * the part from the server while the tab is visible.
 */
(function () {
	'use strict';

	var root = document.getElementById('fs-fleet-dash');
	if (!root || !window.FleetCharts) {
		return;
	}
	var FC = window.FleetCharts;
	var T = JSON.parse(root.getAttribute('data-strings'));
	var view = root.getAttribute('data-view');
	var part = root.querySelector('[data-fleet-part]');
	var esc = function (s) {
		return String(s === null || s === undefined ? '' : s).replace(/[&<>"']/g, function (c) {
			return {'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c];
		});
	};
	var fmt = function (f) {
		var a = Array.prototype.slice.call(arguments, 1);
		return f.replace(/%[sd]/g, function () { return a.shift(); });
	};
	var $ = function (k) { return part.querySelector('[data-chart="' + k + '"]'); };
	var sum = function (k, text) {
		var el = part.querySelector('[data-sum="' + k + '"]');
		if (el) {
			el.textContent = text;
		}
	};
	var last = function (a) {
		for (var i = a.length - 1; i >= 0; i--) {
			if (a[i] !== null && a[i] !== undefined) {
				return a[i];
			}
		}
		return null;
	};
	var peak = function (a) {
		var v = a.filter(function (x) { return x !== null; });
		return v.length ? Math.max.apply(null, v) : null;
	};
	var total = function (a) { return a.reduce(function (p, c) { return p + (c || 0); }, 0); };
	/* Day labels: "16 Oct". */
	var days = function (d) {
		return d.map(function (s) {
			var p = s.split('-');
			return new Date(+p[0], +p[1] - 1, +p[2]).toLocaleDateString(undefined, {day: 'numeric', month: 'short'});
		});
	};

	function overview(d) {
		FC.draw($('pulse'), {type: 'pulse', t: d.pulse.t, rows: d.pulse.rows, states: T, nowLabel: T.now, label: T.online, empty: T.nothing});
		var c = d.counts;
		FC.draw($('states'), {type: 'donut', center: d.total, centerLabel: T.sum_firewalls.replace('%d ', ''), label: T.online, parts: [
			{name: T.online, value: c.online, tone: 'pass'}, {name: T.degraded, value: c.degraded, tone: 'warn'},
			{name: T.offline, value: c.offline, tone: 'block'}, {name: T['new'], value: c['new'], tone: 'neutral'}]});
	}

	function trends(d) {
		var L = d.load;
		var any = function (a) { return a.some(function (x) { return x !== null; }); };

		FC.draw($('up'), {type: 'line', t: d.up.t, max: Math.max(1, d.total), label: T.up,
		    series: [{name: T.up, data: d.up.up, fill: true, color: 1}, {name: T['in'], data: d.up['in'], dash: true, color: 8}]});
		sum('up', fmt(T.sum_now, last(d.up.up) + ' / ' + d.total));
		FC.draw($('outages'), {type: 'bars', labels: days(d.days), label: T.outages, series: [{name: T.outages, data: d.outages_day, tone: 'block'}]});
		sum('outages', fmt(T.sum_total, total(d.outages_day)));

		var band = function (med, p90, name, color) {
			return any(med) ? {type: 'line', t: d.t, max: 100, unit: '%', label: name, legend: true,
			    series: [{name: T.median, data: med, color: color, band: {lo: med, hi: p90}}, {name: T.p90, data: p90, dash: true, color: color}]} : {type: 'line', t: [], empty: T.no_samples, series: []};
		};
		FC.draw($('cpu'), band(L.cpu_med, L.cpu_p90, T.cpu, 1));
		sum('cpu', last(L.cpu_med) === null ? '' : fmt(T.sum_now, FC.short(last(L.cpu_med), ' %')));
		FC.draw($('mem'), band(L.mem_med, L.mem_p90, T.memory, 3));
		sum('mem', last(L.mem_med) === null ? '' : fmt(T.sum_now, FC.short(last(L.mem_med), ' %')));

		FC.draw($('heat'), {type: 'heat', t: d.t, max: 100, unit: '%', label: T.cpu, empty: T.no_samples, rows: d.heat.map(function (r) { return {label: r.label, data: r.data}; })});
		sum('heat', d.heat.length ? fmt(T.sum_firewalls, d.heat.length) : '');

		FC.draw($('traffic'), any(L.rx) ? {type: 'line', t: d.t, unit: 'b/s', label: T.rx,
		    series: [{name: T.rx, data: L.rx, fill: true, color: 6}, {name: T.tx, data: L.tx, fill: true, color: 1}]} : {type: 'line', t: [], empty: T.no_samples, series: []});
		sum('traffic', any(L.rx) ? fmt(T.sum_peak, FC.short(peak(L.rx), 'b/s')) : '');

		var tops = function (rows) {
			return rows.map(function (r, k) { return {name: r.label, data: r.data, color: [1, 2, 3, 5, 7][k]}; });
		};
		FC.draw($('states_top'), d.states_top.length ? {type: 'line', t: d.t, unit: '%', label: T.states, legend: true, series: tops(d.states_top)} :
		    {type: 'line', t: [], empty: T.no_states, series: []});
		sum('states', d.states_top.length ? fmt(T.in_use, FC.short(d.states_top[0].peak, ' %')) : '');
		FC.draw($('temp'), d.temp_top.length ? {type: 'line', t: d.t, unit: '°', label: T.warn_temp, legend: true, max: 100, marks: [{v: 80, label: T.warn_temp}],
		    series: tops(d.temp_top)} : {type: 'line', t: [], empty: T.no_temp, series: []});
		sum('temp', d.temp_top.length ? fmt(T.sum_peak, FC.short(d.temp_top[0].peak, ' °C')) : '');

		/* Busiest firewalls: a table with sparklines. */
		var b = $('busiest');
		b.innerHTML = !d.busiest.length ? '<p class="fs-muted mb-0">' + esc(T.none_busy) + '</p>' :
		    '<table class="table fs-table fs-fleet-busy mb-0"><thead><tr><th>' + esc(T.firewall) + '</th><th>' + esc(T.cpu) + '</th><th class="fs-fleet-busy-spark"></th><th>' +
		    esc(T.memory) + '</th><th class="fs-fleet-busy-spark"></th><th>' + esc(T.peak) + '</th></tr></thead><tbody>' + d.busiest.map(function (r) {
			var pct = function (v) { return v === null ? '-' : FC.short(v, ' %'); };
			return '<tr><td><a href="' + esc(r.link) + '">' + esc(r.label) + '</a></td><td>' + pct(r.cpu_now) + '</td><td class="fs-fleet-busy-spark">' +
			    FC.spark(r.cpu, {max: 100, color: 1}) + '</td><td>' + pct(r.mem_now) + '</td><td class="fs-fleet-busy-spark">' + FC.spark(r.mem, {max: 100, color: 3}) +
			    '</td><td>' + pct(r.peak) + '</td></tr>';
		}).join('') + '</tbody></table>';

		var dl = days(d.days);
		FC.draw($('alerts'), {type: 'bars', labels: dl, label: T.critical, series: [{name: T.critical, data: d.alerts_day.critical, tone: 'block'},
		    {name: T.warning, data: d.alerts_day.warning, tone: 'warn'}, {name: T.info, data: d.alerts_day.info, tone: 'info'}]});
		sum('alerts', fmt(T.sum_total, total(d.alerts_day.critical) + total(d.alerts_day.warning) + total(d.alerts_day.info)));
		FC.draw($('ops'), {type: 'bars', labels: dl, label: T.done, series: [{name: T.done, data: d.ops_day.done, tone: 'pass'}, {name: T.failed, data: d.ops_day.failed, tone: 'block'}]});
		sum('ops', fmt(T.sum_total, total(d.ops_day.done) + total(d.ops_day.failed)));
		FC.draw($('backups'), {type: 'bars', labels: dl, label: T.backed_up, series: [{name: T.backed_up, data: d.backups_day.ok, tone: 'c4'}, {name: T.failed, data: d.backups_day.failed, tone: 'block'}]});
		sum('backups', fmt(T.sum_total, total(d.backups_day.ok)));

		FC.draw($('versions'), {type: 'hbar', items: d.versions.map(function (v, k) { return {label: v.label, value: v.value, tone: k === 0 ? 'c1' : 'neutral', text: String(v.value)}; }), empty: T.nothing});
		sum('versions', fmt(T.sum_firewalls, d.total));
		var cc = d.compliance;
		FC.draw($('compliance'), {type: 'donut', center: (cc.pass + cc.fail) ? Math.round(100 * cc.pass / (cc.pass + cc.fail)) + '%' : '-', centerLabel: T.pass, label: T.pass, parts: [
			{name: T.pass, value: cc.pass, tone: 'pass'}, {name: T.fail, value: cc.fail, tone: 'block'}, {name: T.unknown, value: cc.unknown, tone: 'neutral'}]});
		sum('compliance', fmt(T.sum_rules, cc.pass + cc.fail + cc.unknown));
	}

	function draw() {
		var el = part.querySelector('script[data-fleet-json]');
		if (!el) {
			return;
		}
		var d = JSON.parse(el.textContent);
		if (d.pulse) {
			overview(d);
		}
		if (d.trends) {
			trends(d.trends);
		}
	}

	/* Refresh the part: Overview every minute, Trends every five; a hidden tab waits. */
	var busy = false;
	setInterval(function () {
		if (document.hidden || busy) {
			return;
		}
		busy = true;
		fetch(root.getAttribute('data-part'), {credentials: 'same-origin'})
		    .then(function (r) { return r.ok ? r.text() : Promise.reject(r.status); })
		    .then(function (html) {
			part.innerHTML = html;
			draw();
		})
		    .catch(function () {})
		    .then(function () { busy = false; });
	}, (view === 'overview') ? 60000 : 300000);
	draw();
}());
