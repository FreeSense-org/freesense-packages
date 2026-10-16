/*
 * fleet-metrics.js
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
 * A firewall's System view: live tiles every 15 s while the tab is visible,
 * and CPU and memory history as a small SVG chart (no chart library; the
 * colours come from the theme). Data from fleet_box_metrics.php.
 */
(function () {
	'use strict';
	var root = document.querySelector('[data-fleet-metrics]');
	if (!root) {
		return;
	}
	var id = root.getAttribute('data-fleet-metrics');
	var T = JSON.parse(root.getAttribute('data-strings') || '{}');
	var range = '24h';
	var showAll = false;
	var $ = function (sel) { return root.querySelector(sel); };
	var esc = function (s) {
		return String(s === null || s === undefined ? '' : s).replace(/[&<>"']/g, function (c) {
			return {'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c];
		});
	};
	var bytes = function (b) {
		var u = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
		var i = 0;
		while (b >= 1024 && i < u.length - 1) {
			b /= 1024;
			i++;
		}
		return (i ? b.toFixed(1) : b) + ' ' + u[i];
	};
	var uptime = function (s) {
		var d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60);
		return d > 0 ? d + ' ' + (d === 1 ? T.day : T.days) + (h ? ' ' + h + ' h' : '') : (h > 0 ? h + ' h ' + m + ' min' : m + ' min');
	};
	var pct = function (used, total) { return total > 0 ? Math.round(100 * used / total) : 0; };
	var bar = function (p) {
		var lvl = p >= 90 ? ' is-bad' : (p >= 75 ? ' is-warn' : '');
		return '<span class="fs-fleet-meter' + lvl + '" role="img" aria-label="' + p + '%"><span style="width:' + Math.min(100, p) + '%"></span></span>';
	};
	var tile = function (label, value, extra) {
		return '<div class="fs-tile"><span class="fs-tile-label">' + esc(label) + '</span><span class="fs-tile-value">' + value + '</span>' +
		    (extra ? '<span class="fs-fleet-tile-sub">' + extra + '</span>' : '') + '</div>';
	};

	function live() {
		fetch('/fleet/fleet_box_metrics.php?what=live&id=' + encodeURIComponent(id), {credentials: 'same-origin'})
		    .then(function (r) { return r.json(); })
		    .then(function (d) {
			if (d.error || !d.system) {
				$('[data-m="live"]').innerHTML = '<p class="fs-fleet-problem mb-0">' + esc(d.error || T.noData) + '</p>';
				return;
			}
			var s = d.system;
			var mem = pct(s.memory.used_bytes, s.memory.total_bytes);
			var st = pct(s.states.current, s.states.max);
			var load = s.cpu.load ? s.cpu.load.join(' / ') : '-';
			var temp = (s.temperatures || []).length ? Math.max.apply(null, s.temperatures.map(function (t) { return t.celsius; })) + ' °C' : null;
			$('[data-m="hw"]').innerHTML =
			    '<dt>' + esc(T.cpu) + '</dt><dd>' + esc(s.cpu.model) + ' <span class="fs-muted">(' + s.cpu.count + ' ' + esc(T.cores) + ')</span></dd>' +
			    '<dt>' + esc(T.memory) + '</dt><dd>' + bytes(s.memory.total_bytes) + '</dd>' +
			    (s.swap && s.swap.total_bytes ? '<dt>' + esc(T.swap) + '</dt><dd>' + bytes(s.swap.used_bytes) + ' / ' + bytes(s.swap.total_bytes) + '</dd>' : '') +
			    '<dt>' + esc(T.uptime) + '</dt><dd>' + uptime(s.uptime_seconds) + '</dd>' +
			    (temp ? '<dt>' + esc(T.temperature) + '</dt><dd>' + temp + '</dd>' : '');
			$('[data-m="live"]').innerHTML =
			    tile(T.load, esc(load), esc(T.loadHint)) +
			    tile(T.memory, mem + '%', bar(mem) + ' ' + bytes(s.memory.used_bytes)) +
			    tile(T.states, esc(s.states.current.toLocaleString()), bar(st) + ' ' + esc(T.of) + ' ' + esc(s.states.max.toLocaleString())) +
			    tile(T.mbufs, esc(s.mbuf.used.toLocaleString()), bar(pct(s.mbuf.used, s.mbuf.max)));
			/* ZFS datasets share one pool: show the root, other file systems and busy datasets; the rest on request. */
			var disks = (s.disks || []).map(function (k) {
				k.quiet = k.type === 'zfs' && k.mount !== '/' && pct(k.used_bytes, k.total_bytes) < 5;
				return k;
			});
			var quiet = disks.filter(function (k) { return k.quiet; }).length;
			$('[data-m="disks"]').innerHTML = disks.map(function (k) {
				var p = pct(k.used_bytes, k.total_bytes);
				return '<tr' + (k.quiet && !showAll ? ' hidden' : '') + '><td class="fs-mono">' + esc(k.mount) + '</td><td>' + esc(k.type) + '</td><td>' + bar(p) + ' ' + p + '%</td><td class="text-end">' +
				    bytes(k.used_bytes) + ' / ' + bytes(k.total_bytes) + '</td></tr>';
			}).join('') + (quiet && !showAll ? '<tr><td colspan="4"><button type="button" class="btn btn-sm btn-link p-0" data-m="disks-all">' +
			    esc(T.showAll.replace('%d', quiet)) + '</button></td></tr>' : '') || '<tr><td colspan="4" class="fs-muted">-</td></tr>';
			var more = $('[data-m="disks-all"]');
			if (more) {
				more.addEventListener('click', function () { showAll = true; live(); });
			}
			$('[data-m="ifs"]').innerHTML = (d.interfaces || []).map(function (i) {
				var up = i.status === 'up' || i.status === 'associated';
				return '<tr><td><strong>' + esc(i.name) + '</strong> <span class="fs-muted fs-mono small">' + esc(i.if) + '</span></td><td>' +
				    '<span class="fs-badge fs-badge--' + (up ? 'pass' : 'block') + '">' + esc(up ? T.up : (i.status || T.down)) + '</span></td><td class="fs-mono">' +
				    esc(i.ip || '-') + '</td><td class="fs-mono small">' + esc(i.mac) + '</td><td class="text-end' + (i.errors ? ' fs-fleet-problem' : '') + '">' + i.errors + '</td></tr>';
			}).join('') || '<tr><td colspan="5" class="fs-muted">-</td></tr>';
			$('[data-m="checked"]').textContent = T.checked + ' ' + new Date(d.time * 1000).toLocaleTimeString();
		})
		    .catch(function () { $('[data-m="live"]').innerHTML = '<p class="fs-fleet-problem mb-0">' + esc(T.noData) + '</p>'; });
	}

	/* A line chart of one or more series (0-100 %) over t, as SVG. */
	function chart(t, series) {
		/* Drawn at the panel's own width, so it fills it and the text stays sharp. */
		var hb = $('[data-m="history"]'), hs = getComputedStyle(hb);
		var W = Math.max(320, Math.round((hb.clientWidth || 720) - parseFloat(hs.paddingLeft) - parseFloat(hs.paddingRight))), H = 200, P = {l: 38, r: 8, t: 8, b: 22};
		var n = t.length;
		if (n < 2) {
			return '<p class="fs-muted mb-0">' + esc(T.noHistory) + '</p>';
		}
		var x = function (i) { return P.l + (W - P.l - P.r) * i / (n - 1); };
		var y = function (v) { return P.t + (H - P.t - P.b) * (1 - Math.max(0, Math.min(100, v)) / 100); };
		var out = '<svg class="fs-fleet-chart" width="' + W + '" height="' + H + '" viewBox="0 0 ' + W + ' ' + H + '" role="img" aria-label="' +
		    esc(series.map(function (s) { return s.name; }).join(', ')) + '">';
		[0, 25, 50, 75, 100].forEach(function (g) {
			out += '<line class="fs-fleet-chart-grid" x1="' + P.l + '" x2="' + (W - P.r) + '" y1="' + y(g) + '" y2="' + y(g) + '"/>' +
			    '<text class="fs-fleet-chart-axis" x="' + (P.l - 6) + '" y="' + (y(g) + 4) + '" text-anchor="end">' + g + '%</text>';
		});
		var fmt = function (ts) {
			var dt = new Date(ts * 1000);
			return (range === '7d' || range === '30d') ? dt.toLocaleDateString(undefined, {month: 'short', day: 'numeric'}) :
			    dt.toLocaleTimeString(undefined, {hour: '2-digit', minute: '2-digit'});
		};
		[0, Math.floor((n - 1) / 2), n - 1].forEach(function (i, k) {
			out += '<text class="fs-fleet-chart-axis" x="' + x(i) + '" y="' + (H - 6) + '" text-anchor="' + ['start', 'middle', 'end'][k] + '">' + esc(fmt(t[i])) + '</text>';
		});
		series.forEach(function (s, k) {
			var d = '', pen = false;
			s.data.forEach(function (v, i) {
				if (v === null || isNaN(v)) {
					pen = false;
					return;
				}
				d += (pen ? 'L' : 'M') + x(i).toFixed(1) + ' ' + y(v).toFixed(1);
				pen = true;
			});
			out += '<path class="fs-fleet-chart-line fs-fleet-chart-s' + (k + 1) + '" d="' + d + '"/>';
		});
		return out + '</svg>';
	}

	function history() {
		var box = $('[data-m="history"]');
		box.setAttribute('aria-busy', 'true');
		fetch('/fleet/fleet_box_metrics.php?what=history&range=' + range + '&id=' + encodeURIComponent(id), {credentials: 'same-origin'})
		    .then(function (r) { return r.json(); })
		    .then(function (d) {
			box.removeAttribute('aria-busy');
			if (d.error || !d.history) {
				box.innerHTML = '<p class="fs-muted mb-0">' + esc(d.error || T.noHistory) + '</p>';
				return;
			}
			var h = d.history;
			var avg = function (a) {
				var v = a.filter(function (x) { return x !== null && !isNaN(x); });
				return v.length ? Math.round(v.reduce(function (p, c) { return p + c; }, 0) / v.length) : null;
			};
			var peak = function (a) {
				var v = a.filter(function (x) { return x !== null && !isNaN(x); });
				return v.length ? Math.round(Math.max.apply(null, v)) : null;
			};
			box.innerHTML = chart(h.t, [{name: T.cpu, data: h.cpu}, {name: T.memory, data: h.mem}]) +
			    '<p class="fs-fleet-chart-legend small mb-0"><span class="fs-fleet-chart-key fs-fleet-chart-s1"></span>' + esc(T.cpu) + ' ' +
			    esc(T.avg) + ' ' + avg(h.cpu) + '%, ' + esc(T.peak) + ' ' + peak(h.cpu) + '%' +
			    ' <span class="fs-fleet-chart-key fs-fleet-chart-s2"></span>' + esc(T.memory) + ' ' + esc(T.avg) + ' ' + avg(h.mem) + '%, ' + esc(T.peak) + ' ' + peak(h.mem) + '%</p>';
		})
		    .catch(function () { box.removeAttribute('aria-busy'); box.innerHTML = '<p class="fs-muted mb-0">' + esc(T.noHistory) + '</p>'; });
	}

	root.querySelectorAll('[data-range]').forEach(function (b) {
		b.addEventListener('click', function () {
			range = b.getAttribute('data-range');
			root.querySelectorAll('[data-range]').forEach(function (o) { o.setAttribute('aria-pressed', o === b ? 'true' : 'false'); });
			history();
		});
	});
	var resized;
	window.addEventListener('resize', function () {
		clearTimeout(resized);
		resized = setTimeout(history, 300);
	});
	live();
	history();
	setInterval(function () {
		if (!document.hidden) {
			live();
		}
	}, 15000);
}());
