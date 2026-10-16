/*
 * fleet-charts.js
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
 * The Fleet charts: small, dependency-free SVG drawn at the container's
 * width (sharp text, no scaling) with the WebUI series and state colours.
 *
 *   FleetCharts.draw(el, spec)   draws spec into el and redraws on resize
 *   FleetCharts.spark(data, o)   an inline sparkline (SVG string)
 *
 * spec.type: line | bars | heat | donut | hbar | pulse. Every chart has a
 * hover readout; nothing moves unless the pointer asks.
 */
(function (global) {
	'use strict';

	var drawn = [];
	var esc = function (s) {
		return String(s === null || s === undefined ? '' : s).replace(/[&<>"']/g, function (c) {
			return {'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c];
		});
	};
	var num = function (v) { return (v !== null && v !== undefined && !isNaN(v)) ? +v : null; };

	/* Numbers for axes and readouts: 1.2k, 3.4M, 5G (bits, states) or plain. */
	function short(v, unit) {
		if (v === null) {
			return '-';
		}
		var a = Math.abs(v), s;
		if (a >= 1e9) {
			s = (v / 1e9).toFixed(a >= 1e10 ? 0 : 1) + 'G';
		} else if (a >= 1e6) {
			s = (v / 1e6).toFixed(a >= 1e7 ? 0 : 1) + 'M';
		} else if (a >= 1e4) {
			s = (v / 1e3).toFixed(0) + 'k';
		} else if (a >= 100 || v === Math.round(v)) {
			s = String(Math.round(v));
		} else {
			s = v.toFixed(1);
		}
		return s.replace('.0', '') + (unit || '');
	}

	/* Time labels: hours within two days, dates beyond. */
	function tlabel(ts, span) {
		var d = new Date(ts * 1000);
		return (span > 172800) ? d.toLocaleDateString(undefined, {month: 'short', day: 'numeric'}) :
		    d.toLocaleTimeString(undefined, {hour: '2-digit', minute: '2-digit'});
	}

	/* A nice axis maximum: 1, 2 or 5 times a power of ten above v. */
	function nice(v) {
		if (!(v > 0)) {
			return 1;
		}
		var p = Math.pow(10, Math.floor(Math.log10(v))), m = v / p;
		return (m <= 1 ? 1 : m <= 2 ? 2 : m <= 5 ? 5 : 10) * p;
	}

	function width(el) {
		var cs = getComputedStyle(el);
		return Math.max(240, Math.round((el.clientWidth || 600) - parseFloat(cs.paddingLeft) - parseFloat(cs.paddingRight)));
	}

	function svg(W, H, label, body) {
		return '<svg class="fs-fleet-chart" width="' + W + '" height="' + H + '" viewBox="0 0 ' + W + ' ' + H + '" role="img" aria-label="' + esc(label) + '">' + body + '</svg>';
	}

	/* The readout box under the pointer. */
	function tip(el) {
		var t = el.querySelector('.fs-fc-tip');
		if (!t) {
			t = document.createElement('div');
			t.className = 'fs-fc-tip';
			t.setAttribute('role', 'status');
			el.appendChild(t);
		}
		return t;
	}

	function place(el, t, x, y) {
		var r = el.getBoundingClientRect();
		t.hidden = false;
		var left = Math.min(Math.max(0, x - r.left + 12), r.width - t.offsetWidth - 4);
		t.style.left = left + 'px';
		t.style.top = Math.max(0, y - r.top - t.offsetHeight - 10) + 'px';
	}

	/* ---------------------------------------------------------------- line / area */
	function line(el, o) {
		var W = width(el), H = o.height || 190, P = {l: 44, r: 10, t: 10, b: 22};
		var t = o.t || [], n = t.length;
		if (n < 2) {
			return '<p class="fs-muted mb-0">' + esc(o.empty || '-') + '</p>';
		}
		var max = o.max;
		if (max === undefined) {
			max = 0;
			o.series.forEach(function (s) {
				(s.band ? s.band.hi : s.data).forEach(function (v) { v = num(v); max = (v !== null && v > max) ? v : max; });
				s.data.forEach(function (v) { v = num(v); max = (v !== null && v > max) ? v : max; });
			});
			max = nice(max * 1.1);
		}
		var x = function (i) { return P.l + (W - P.l - P.r) * i / (n - 1); };
		var y = function (v) { return P.t + (H - P.t - P.b) * (1 - Math.max(0, Math.min(max, v)) / max); };
		var body = '';
		[0, .25, .5, .75, 1].forEach(function (g) {
			var v = max * g;
			body += '<line class="fs-fleet-chart-grid" x1="' + P.l + '" x2="' + (W - P.r) + '" y1="' + y(v) + '" y2="' + y(v) + '"/>' +
			    '<text class="fs-fleet-chart-axis" x="' + (P.l - 6) + '" y="' + (y(v) + 4) + '" text-anchor="end">' + esc(short(v, o.unit)) + '</text>';
		});
		var span = t[n - 1] - t[0];
		[0, Math.floor((n - 1) / 2), n - 1].forEach(function (i, k) {
			body += '<text class="fs-fleet-chart-axis" x="' + x(i) + '" y="' + (H - 6) + '" text-anchor="' + ['start', 'middle', 'end'][k] + '">' + esc(tlabel(t[i], span)) + '</text>';
		});
		(o.marks || []).forEach(function (m) {
			body += '<line class="fs-fc-mark" x1="' + P.l + '" x2="' + (W - P.r) + '" y1="' + y(m.v) + '" y2="' + y(m.v) + '"/>' +
			    '<text class="fs-fleet-chart-axis fs-fc-mark-label" x="' + (W - P.r) + '" y="' + (y(m.v) - 4) + '" text-anchor="end">' + esc(m.label) + '</text>';
		});
		var path = function (data) {
			var d = '', pen = false;
			data.forEach(function (v, i) {
				v = num(v);
				if (v === null) {
					pen = false;
					return;
				}
				d += (pen ? 'L' : 'M') + x(i).toFixed(1) + ' ' + y(v).toFixed(1);
				pen = true;
			});
			return d;
		};
		o.series.forEach(function (s, k) {
			var c = 'fs-fc-c' + (s.color || (k + 1));
			if (s.band) {
				var up = '', down = '';
				s.band.hi.forEach(function (v, i) { if (num(v) !== null) { up += (up ? 'L' : 'M') + x(i).toFixed(1) + ' ' + y(v).toFixed(1); } });
				for (var i = n - 1; i >= 0; i--) {
					if (num(s.band.lo[i]) !== null) {
						down += 'L' + x(i).toFixed(1) + ' ' + y(s.band.lo[i]).toFixed(1);
					}
				}
				body += '<path class="fs-fc-band ' + c + '" d="' + up + down + 'Z"/>';
			}
			if (s.fill) {
				var first = s.data.findIndex(function (v) { return num(v) !== null; });
				var last = n - 1 - s.data.slice().reverse().findIndex(function (v) { return num(v) !== null; });
				if (first >= 0) {
					body += '<path class="fs-fc-fill ' + c + '" d="' + path(s.data) + 'L' + x(last).toFixed(1) + ' ' + y(0) + 'L' + x(first).toFixed(1) + ' ' + y(0) + 'Z"/>';
				}
			}
			body += '<path class="fs-fleet-chart-line ' + c + (s.dash ? ' fs-fc-dash' : '') + '" d="' + path(s.data) + '"/>';
		});
		body += '<line class="fs-fc-cross" x1="0" x2="0" y1="' + P.t + '" y2="' + (H - P.b) + '" visibility="hidden"/>';
		var legend = (o.legend !== false && (o.series.length > 1 || o.legend)) ? '<p class="fs-fleet-chart-legend small mb-0">' + o.series.map(function (s, k) {
			return '<span class="fs-fc-key fs-fc-c' + (s.color || (k + 1)) + (s.dash ? ' fs-fc-dash' : '') + '"></span>' + esc(s.name);
		}).join(' ') + '</p>' : '';
		el._hover = function (ev) {
			var r = el.querySelector('svg').getBoundingClientRect();
			var i = Math.round((ev.clientX - r.left - P.l) / (W - P.l - P.r) * (n - 1));
			var cross = el.querySelector('.fs-fc-cross'), tt = tip(el);
			if (i < 0 || i >= n) {
				cross.setAttribute('visibility', 'hidden');
				tt.hidden = true;
				return;
			}
			cross.setAttribute('x1', x(i));
			cross.setAttribute('x2', x(i));
			cross.setAttribute('visibility', 'visible');
			tt.innerHTML = '<strong>' + esc(new Date(t[i] * 1000).toLocaleString(undefined, {month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit'})) + '</strong>' +
			    o.series.map(function (s, k) {
				return '<span><i class="fs-fc-key fs-fc-c' + (s.color || (k + 1)) + '"></i>' + esc(s.name) + ' ' + esc(short(num(s.data[i]), o.unit)) + '</span>';
			}).join('');
			place(el, tt, ev.clientX, r.top + P.t + 10);
		};
		return svg(W, H, o.label || '', body) + legend;
	}

	/* ---------------------------------------------------------------- bars (stacked) */
	function bars(el, o) {
		var W = width(el), H = o.height || 170, P = {l: 36, r: 6, t: 8, b: 22};
		var n = o.labels.length;
		if (!n) {
			return '<p class="fs-muted mb-0">' + esc(o.empty || '-') + '</p>';
		}
		var tot = o.labels.map(function (_, i) {
			return o.series.reduce(function (a, s) { return a + (num(s.data[i]) || 0); }, 0);
		});
		var max = nice(Math.max.apply(null, tot.concat([1])));
		var bw = (W - P.l - P.r) / n, gap = Math.min(6, bw * .25);
		var y = function (v) { return P.t + (H - P.t - P.b) * (1 - v / max); };
		var body = '';
		[0, .5, 1].forEach(function (g) {
			body += '<line class="fs-fleet-chart-grid" x1="' + P.l + '" x2="' + (W - P.r) + '" y1="' + y(max * g) + '" y2="' + y(max * g) + '"/>' +
			    '<text class="fs-fleet-chart-axis" x="' + (P.l - 6) + '" y="' + (y(max * g) + 4) + '" text-anchor="end">' + esc(short(max * g)) + '</text>';
		});
		o.labels.forEach(function (lab, i) {
			var base = 0, x0 = P.l + i * bw + gap / 2;
			o.series.forEach(function (s, k) {
				var v = num(s.data[i]) || 0;
				if (v > 0) {
					body += '<rect class="fs-fc-bar fs-fc-' + (s.tone || ('c' + (k + 1))) + '" x="' + x0.toFixed(1) + '" width="' + Math.max(1, bw - gap).toFixed(1) +
					    '" y="' + y(base + v).toFixed(1) + '" height="' + (y(base) - y(base + v)).toFixed(1) + '"/>';
				}
				base += v;
			});
			body += '<rect class="fs-fc-hit" data-i="' + i + '" x="' + (P.l + i * bw).toFixed(1) + '" width="' + bw.toFixed(1) + '" y="' + P.t + '" height="' + (H - P.t - P.b) + '"/>';
			if (n <= 8 || i % Math.ceil(n / 8) === 0 || i === n - 1) {
				body += '<text class="fs-fleet-chart-axis" x="' + (x0 + (bw - gap) / 2).toFixed(1) + '" y="' + (H - 6) + '" text-anchor="middle">' + esc(lab) + '</text>';
			}
		});
		el._hover = function (ev) {
			var hit = ev.target.closest && ev.target.closest('.fs-fc-hit'), tt = tip(el);
			if (!hit) {
				tt.hidden = true;
				return;
			}
			var i = +hit.getAttribute('data-i');
			tt.innerHTML = '<strong>' + esc(o.labels[i]) + '</strong>' + o.series.map(function (s, k) {
				return '<span><i class="fs-fc-key fs-fc-' + (s.tone || ('c' + (k + 1))) + '"></i>' + esc(s.name) + ' ' + esc(short(num(s.data[i]) || 0)) + '</span>';
			}).join('');
			place(el, tt, ev.clientX, ev.clientY);
		};
		var legend = (o.series.length > 1) ? '<p class="fs-fleet-chart-legend small mb-0">' + o.series.map(function (s, k) {
			return '<span class="fs-fc-key fs-fc-' + (s.tone || ('c' + (k + 1))) + '"></span>' + esc(s.name);
		}).join(' ') + '</p>' : '';
		return svg(W, H, o.label || '', body) + legend;
	}

	/* ---------------------------------------------------------------- heat map (rows x time) */
	function heat(el, o) {
		var W = width(el), rows = o.rows || [], n = (o.t || []).length;
		if (!rows.length || n < 2) {
			return '<p class="fs-muted mb-0">' + esc(o.empty || '-') + '</p>';
		}
		var L = Math.min(150, Math.round(W * .28)), rh = 14, H = rows.length * (rh + 2) + 22;
		var cw = (W - L - 4) / n, max = o.max || 100, body = '';
		rows.forEach(function (r, j) {
			var y0 = j * (rh + 2);
			body += '<text class="fs-fleet-chart-axis" x="' + (L - 8) + '" y="' + (y0 + rh - 3) + '" text-anchor="end">' + esc(r.label.length > 22 ? r.label.slice(0, 21) + '…' : r.label) + '</text>';
			r.data.forEach(function (v, i) {
				v = num(v);
				var lvl = (v === null) ? 'none' : Math.min(5, Math.floor(5 * v / max + 0.5));
				body += '<rect class="fs-fc-heat l' + lvl + '" data-j="' + j + '" data-i="' + i + '" x="' + (L + i * cw).toFixed(1) + '" y="' + y0 + '" width="' + Math.max(1, cw - 1).toFixed(1) +
				    '" height="' + rh + '" rx="2"/>';
			});
		});
		var span = o.t[n - 1] - o.t[0];
		[0, Math.floor((n - 1) / 2), n - 1].forEach(function (i, k) {
			body += '<text class="fs-fleet-chart-axis" x="' + (L + i * cw + (k === 2 ? cw : 0)).toFixed(1) + '" y="' + (H - 6) + '" text-anchor="' + ['start', 'middle', 'end'][k] + '">' + esc(tlabel(o.t[i], span)) + '</text>';
		});
		el._hover = function (ev) {
			var c = ev.target.closest && ev.target.closest('.fs-fc-heat'), tt = tip(el);
			if (!c) {
				tt.hidden = true;
				return;
			}
			var r = rows[+c.getAttribute('data-j')], i = +c.getAttribute('data-i');
			tt.innerHTML = '<strong>' + esc(r.label) + '</strong><span>' + esc(tlabel(o.t[i], 0)) + ': ' + esc(short(num(r.data[i]), o.unit)) + '</span>';
			place(el, tt, ev.clientX, ev.clientY);
		};
		return svg(W, H, o.label || '', body);
	}

	/* ---------------------------------------------------------------- donut */
	function donut(el, o) {
		var parts = o.parts.filter(function (p) { return p.value > 0; });
		var total = parts.reduce(function (a, p) { return a + p.value; }, 0);
		var S = 132, R = 56, w = 16, c = S / 2, a0 = -Math.PI / 2, body = '';
		if (!total) {
			body = '<circle class="fs-fc-donut-empty" cx="' + c + '" cy="' + c + '" r="' + R + '" stroke-width="' + w + '"/>';
		}
		parts.forEach(function (p) {
			var a1 = a0 + 2 * Math.PI * p.value / total;
			if (p.value === total) {
				body += '<circle class="fs-fc-arc fs-fc-' + p.tone + '" cx="' + c + '" cy="' + c + '" r="' + R + '" stroke-width="' + w + '"/>';
			} else {
				var big = (a1 - a0) > Math.PI ? 1 : 0;
				body += '<path class="fs-fc-arc fs-fc-' + p.tone + '" stroke-width="' + w + '" d="M' + (c + R * Math.cos(a0)).toFixed(2) + ' ' + (c + R * Math.sin(a0)).toFixed(2) +
				    'A' + R + ' ' + R + ' 0 ' + big + ' 1 ' + (c + R * Math.cos(a1)).toFixed(2) + ' ' + (c + R * Math.sin(a1)).toFixed(2) + '"/>';
			}
			a0 = a1;
		});
		body += '<text class="fs-fc-donut-n" x="' + c + '" y="' + (c + 4) + '" text-anchor="middle">' + esc(o.center !== undefined ? o.center : total) + '</text>' +
		    '<text class="fs-fleet-chart-axis" x="' + c + '" y="' + (c + 22) + '" text-anchor="middle">' + esc(o.centerLabel || '') + '</text>';
		return '<div class="fs-fc-donut">' + svg(S, S, o.label || '', body) + '<ul class="fs-fc-donut-keys">' + o.parts.map(function (p) {
			return '<li><span class="fs-fc-key fs-fc-' + p.tone + '"></span>' + esc(p.name) + ' <strong>' + esc(p.value) + '</strong></li>';
		}).join('') + '</ul></div>';
	}

	/* ---------------------------------------------------------------- horizontal bars */
	function hbar(el, o) {
		var items = o.items || [];
		if (!items.length) {
			return '<p class="fs-muted mb-0">' + esc(o.empty || '-') + '</p>';
		}
		var max = o.max || Math.max.apply(null, items.map(function (i) { return i.value; }).concat([1]));
		return '<ul class="fs-fc-hbar">' + items.map(function (i) {
			var pct = Math.max(0, Math.min(100, 100 * i.value / max));
			var label = i.link ? '<a href="' + esc(i.link) + '">' + esc(i.label) + '</a>' : esc(i.label);
			return '<li><span class="fs-fc-hbar-label">' + label + '</span><span class="fs-fc-hbar-track"><span class="fs-fc-hbar-fill fs-fc-' + (i.tone || 'c1') + '" style="width:' +
			    pct.toFixed(1) + '%"></span></span><span class="fs-fc-hbar-v">' + esc(i.text !== undefined ? i.text : short(i.value, o.unit)) + '</span></li>';
		}).join('') + '</ul>';
	}

	/* ---------------------------------------------------------------- the Fleet pulse (firewalls x time, by state) */
	function pulse(el, o) {
		var W = width(el), rows = o.rows || [], n = (o.t || []).length;
		if (!rows.length || n < 2) {
			return '<p class="fs-muted mb-0">' + esc(o.empty || '-') + '</p>';
		}
		var L = Math.min(170, Math.round(W * .26)), rh = 12, gap = 3, H = rows.length * (rh + gap) + 24;
		var cw = (W - L - 4) / n, body = '';
		rows.forEach(function (r, j) {
			var y0 = j * (rh + gap);
			var name = r.label.length > 24 ? r.label.slice(0, 23) + '…' : r.label;
			body += '<a href="' + esc(r.link) + '" class="fs-fc-pulse-row"><text class="fs-fc-pulse-label" x="' + (L - 10) + '" y="' + (y0 + rh - 2) + '" text-anchor="end">' + esc(name) + '</text>';
			r.cells.forEach(function (s, i) {
				body += '<rect class="fs-fc-pulse s-' + (s || 'none') + '" data-j="' + j + '" data-i="' + i + '" x="' + (L + i * cw).toFixed(1) + '" y="' + y0 + '" width="' + Math.max(1, cw - 1.5).toFixed(1) +
				    '" height="' + rh + '" rx="2"/>';
			});
			body += '</a>';
		});
		var span = o.t[n - 1] - o.t[0];
		[0, Math.floor(n / 4), Math.floor(n / 2), Math.floor(3 * n / 4), n - 1].forEach(function (i, k) {
			body += '<text class="fs-fleet-chart-axis" x="' + (L + i * cw + (k === 4 ? cw : 0)).toFixed(1) + '" y="' + (H - 6) + '" text-anchor="' + (k === 0 ? 'start' : k === 4 ? 'end' : 'middle') + '">' +
			    esc(k === 4 ? (o.nowLabel || tlabel(o.t[n - 1] + (o.t[1] - o.t[0]), span)) : tlabel(o.t[i], span)) + '</text>';
		});
		el._hover = function (ev) {
			var c = ev.target.closest && ev.target.closest('.fs-fc-pulse'), tt = tip(el);
			if (!c) {
				tt.hidden = true;
				return;
			}
			var r = rows[+c.getAttribute('data-j')], i = +c.getAttribute('data-i'), step = o.t[1] - o.t[0];
			var st = r.cells[i] || 'none';
			tt.innerHTML = '<strong>' + esc(r.label) + '</strong><span>' + esc(tlabel(o.t[i], 0) + '–' + tlabel(o.t[i] + step, 0)) + ': ' + esc((o.states || {})[st] || st) + '</span>';
			place(el, tt, ev.clientX, ev.clientY);
		};
		return svg(W, H, o.label || '', body);
	}

	/* ---------------------------------------------------------------- sparkline */
	function spark(data, o) {
		o = o || {};
		var W = o.width || 90, H = o.height || 22, v = data.map(num), max = o.max || Math.max.apply(null, v.filter(function (x) { return x !== null; }).concat([1]));
		var n = v.length, d = '', pen = false;
		if (n < 2) {
			return '';
		}
		v.forEach(function (x, i) {
			if (x === null) {
				pen = false;
				return;
			}
			d += (pen ? 'L' : 'M') + (1 + (W - 2) * i / (n - 1)).toFixed(1) + ' ' + (1 + (H - 2) * (1 - Math.min(max, x) / max)).toFixed(1);
			pen = true;
		});
		return '<svg class="fs-fc-spark" width="' + W + '" height="' + H + '" viewBox="0 0 ' + W + ' ' + H + '" aria-hidden="true"><path class="fs-fleet-chart-line fs-fc-c' + (o.color || 1) + '" d="' + d + '"/></svg>';
	}

	var types = {line: line, bars: bars, heat: heat, donut: donut, hbar: hbar, pulse: pulse};

	function draw(el, spec) {
		if (!el) {
			return;
		}
		el.classList.add('fs-fc');
		el._spec = spec;
		el._hover = null;
		el.innerHTML = (types[spec.type] || line)(el, spec);
		if (!el._wired) {
			el._wired = true;
			el.addEventListener('mousemove', function (ev) { if (el._hover) { el._hover(ev); } });
			el.addEventListener('mouseleave', function () {
				var t = el.querySelector('.fs-fc-tip'), c = el.querySelector('.fs-fc-cross');
				if (t) {
					t.hidden = true;
				}
				if (c) {
					c.setAttribute('visibility', 'hidden');
				}
			});
			drawn.push(el);
		}
	}

	var resized;
	window.addEventListener('resize', function () {
		clearTimeout(resized);
		resized = setTimeout(function () {
			drawn.forEach(function (el) {
				if (el.isConnected && el._spec && el._spec.type !== 'donut' && el._spec.type !== 'hbar') {
					draw(el, el._spec);
				}
			});
		}, 250);
	});

	global.FleetCharts = {draw: draw, spark: spark, short: short};
}(window));
