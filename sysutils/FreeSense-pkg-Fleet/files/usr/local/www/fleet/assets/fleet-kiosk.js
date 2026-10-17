/*
 * fleet-kiosk.js: the NOC screen. A wall screen (kiosk.php) reads its
 * kiosk key from the URL fragment and asks kiosk_data.php; the live view
 * (noc.php) uses the WebUI session and noc_data.php. Every 10 seconds it
 * redraws: on the left the panels (fleet health, HA pairs, the fleet
 * server, charts), on the right the firewall list. Both page by
 * themselves when they do not fit, each at the pace the screen's
 * settings give (data.layout); the list holds its first page while a
 * firewall is offline. It beeps for what the settings name once sound is
 * on. The look is a style class and data-theme on <html>
 * (fleet-kiosk.css); a screen follows the style saved for it unless its
 * URL pins one. Nothing here writes inline style markup (the CSP): sizes
 * go through the CSSOM.
 */
(function () {
	'use strict';
	var live = document.body.getAttribute('data-mode') === 'live';
	var fixed = document.body.getAttribute('data-fixed') === '1';
	var root = document.documentElement;
	var key = live ? '' : decodeURIComponent((location.hash || '').replace(/^#/, ''));
	var $ = function (id) { return document.getElementById(id); };
	var dark = window.matchMedia('(prefers-color-scheme: dark)');
	var charts = window.FleetCharts || null;
	var body = $('k-body');
	var grid = $('k-grid');
	var list = $('k-list');
	var panels = $('k-panels');
	var data = null;
	var cfg = null;
	var page = 0;
	var ppage = 0;
	var lastOk = 0;
	var known = {};
	var haWas = 0;
	var inetKnown = {};
	var first = true;
	var sound = false;
	var soundSet = false;
	var audio = null;
	var turnTimer = null;
	var panelTimer = null;
	var POLL = 10000;
	var STATES = {
		online: ['Online', '<svg viewBox="0 0 16 16" aria-hidden="true"><path fill="currentColor" d="M6.2 11.6 2.8 8.2l1.1-1.1 2.3 2.3 5.9-5.9 1.1 1.1z"/></svg>'],
		degraded: ['Late', '<svg viewBox="0 0 16 16" aria-hidden="true"><path fill="currentColor" d="M8 1 15 14H1zm-.8 5v4h1.6V6zm0 5v1.6h1.6V11z"/></svg>'],
		offline: ['Offline', '<svg viewBox="0 0 16 16" aria-hidden="true"><path fill="currentColor" d="m4.1 3 3.9 3.9L11.9 3 13 4.1 9.1 8l3.9 3.9-1.1 1.1L8 9.1 4.1 13 3 11.9 6.9 8 3 4.1z"/></svg>'],
		'new': ['Not seen yet', '<svg viewBox="0 0 16 16" aria-hidden="true"><circle cx="8" cy="8" r="5" fill="none" stroke="currentColor" stroke-width="1.6"/></svg>']
	};
	/* Columns: heading, smallest width (em), share of the rest, and how late it is dropped when the list is narrow (higher stays longer). */
	var COLS = {
		state: ['State', 6, .7, 99], name: ['Firewall', 8, 1.8, 99], host: ['Hostname', 8, 1.2, 1],
		groups: ['Groups', 6, 1, 4], version: ['Version', 5.5, .7, 3], seen: ['Seen', 4.5, .5, 2],
		cpu: ['CPU', 6, .8, 7], mem: ['Memory', 6, .8, 6], states: ['States', 4.5, .5, 2],
		traffic: ['Traffic', 10, 1.1, 5], uptime: ['Up 24 h', 4.5, .5, 5], inet: ['Internet', 9, 1, 8], ha: ['HA', 5, .5, 8], flags: ['Notes', 6, 1, 9]
	};
	var cols = [];

	/* ------------------------------------------------------------ the look */

	function look(style, theme) {
		root.className = root.className.replace(/\bk--\S+/g, '').trim() + ' k--' + style;
		root.setAttribute('data-theme-choice', theme);
		root.setAttribute('data-theme', theme === 'auto' ? (dark.matches ? 'dark' : 'light') : theme);
		var t = $('k-theme');
		if (t) { t.textContent = theme === 'auto' ? 'Auto' : (theme === 'dark' ? 'Dark' : 'Light'); }
	}

	/* The live view keeps its look in the URL, so a bookmark or a second screen opens the same. */
	function keep(style, theme) {
		var u = new URL(location.href);
		u.searchParams.set('style', style);
		u.searchParams.set('theme', theme);
		history.replaceState(null, '', u.toString());
	}

	function el(tag, cls, text) {
		var e = document.createElement(tag);
		if (cls) { e.className = cls; }
		if (text !== undefined && text !== null) { e.textContent = text; }
		return e;
	}

	function blocked(text) {
		if (text) { $('k-blocked-text').textContent = text; }
		$('k-blocked').hidden = false;
		data = null;
		document.title = 'FreeSense Fleet: not connected';
	}

	/* ------------------------------------------------------------ numbers */

	function short(v, unit) { return charts ? charts.short(v, unit) : (v === null || v === undefined ? '-' : String(v) + (unit || '')); }
	function pct(v) { return (v === null || v === undefined) ? '-' : (Math.round(v * 10) / 10) + '%'; }
	function ago(ts) {
		if (!ts) { return '-'; }
		var s = Math.max(0, Math.round(Date.now() / 1000 - ts));
		if (s < 90) { return s + ' s ago'; }
		if (s < 5400) { return Math.round(s / 60) + ' min ago'; }
		if (s < 172800) { return Math.round(s / 3600) + ' h ago'; }
		return Math.round(s / 86400) + ' days ago';
	}
	function span(s) {
		if (s === null || s === undefined) { return '-'; }
		var d = Math.floor(s / 86400), h = Math.floor(s % 86400 / 3600), m = Math.floor(s % 3600 / 60);
		return d ? d + ' d ' + h + ' h' : (h ? h + ' h ' + m + ' min' : m + ' min');
	}
	function bytes(b) { return short(b) + 'B'; }
	function day(d) {
		var x = new Date(d + 'T12:00:00');
		return isNaN(x) ? d : x.toLocaleDateString([], { weekday: 'short', day: 'numeric' });
	}

	/* A small bar with its value: CPU, memory, a share. Width through the CSSOM. */
	function meter(v, warn, bad) {
		var m = el('span', 'k-meter' + (v === null || v === undefined ? ' k-none' : (v >= bad ? ' k-m-bad' : (v >= warn ? ' k-m-warn' : ''))));
		var track = el('span', 'k-meter-track');
		var fill = el('span', 'k-meter-fill');
		fill.style.width = Math.max(0, Math.min(100, v || 0)) + '%';
		track.appendChild(fill);
		m.appendChild(track);
		m.appendChild(el('span', 'k-meter-v', pct(v)));
		return m;
	}

	/* ------------------------------------------------------------ clock, sound */

	function clock() {
		var d = new Date();
		$('k-clock').textContent = d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
		if (lastOk) {
			var age = Math.round((Date.now() - lastOk) / 1000);
			var f = $('k-fresh');
			f.classList.toggle('k-stale', age > 60);
			f.textContent = age > 60 ? 'No new data for ' + Math.round(age / 60) + ' min' : 'Updated ' + (age < 15 ? 'just now' : age + ' s ago');
		}
	}

	function beep() {
		if (!sound) { return; }
		try {
			audio = audio || new (window.AudioContext || window.webkitAudioContext)();
			[0, 0.35].forEach(function (at, i) {
				var o = audio.createOscillator();
				var g = audio.createGain();
				o.frequency.value = i ? 660 : 880;
				g.gain.setValueAtTime(0.0001, audio.currentTime + at);
				g.gain.exponentialRampToValueAtTime(0.25, audio.currentTime + at + 0.02);
				g.gain.exponentialRampToValueAtTime(0.0001, audio.currentTime + at + 0.3);
				o.connect(g).connect(audio.destination);
				o.start(audio.currentTime + at);
				o.stop(audio.currentTime + at + 0.32);
			});
		} catch (e) { /* no sound on this screen */ }
	}

	function soundButton() {
		var b = $('k-sound');
		b.setAttribute('aria-pressed', String(sound));
		b.textContent = sound ? 'Sound is on' : 'Turn sound on';
	}

	/* ------------------------------------------------------------ header */

	function counts(d) {
		var ul = $('k-counts');
		ul.textContent = '';
		var cs = [['online', 'Online'], ['degraded', 'Late'], ['offline', 'Offline']];
		if (d.counts.policy) { cs.push(['policy', 'Policy fails']); }
		if (d.ha_problems) { cs.push(['ha', 'HA problems']); }
		/* Internet: the share of the firewalls with a working internet connection. */
		var inetN = null, inetBad = 0;
		if (d.inet_on) {
			inetN = 0;
			d.boxes.forEach(function (b) {
				if (b.inet && b.inet.state !== 'down' && b.inet.state !== 'unknown') { inetN++; }
				if (b.inet && b.inet.state === 'down') { inetBad++; }
			});
			cs.push(['inet', 'Internet']);
		}
		var total = Math.max(1, d.total || 0);
		var NS = 'http://www.w3.org/2000/svg';
		cs.forEach(function (c) {
			var n = c[0] === 'ha' ? d.ha_problems : (c[0] === 'inet' ? inetN : (d.counts[c[0]] || 0));
			var li = el('li', 'k-c-' + c[0] + (n ? '' : ' k-zero') + (c[0] === 'inet' && inetBad ? ' k-inet-bad' : ''));
			/* A ring filled to this state's share of the fleet, the number inside. */
			var svg = document.createElementNS(NS, 'svg');
			svg.setAttribute('viewBox', '0 0 36 36');
			svg.setAttribute('aria-hidden', 'true');
			var track = document.createElementNS(NS, 'circle');
			track.setAttribute('class', 'k-ring-track');
			var arc = document.createElementNS(NS, 'circle');
			arc.setAttribute('class', 'k-ring-arc');
			[track, arc].forEach(function (k) { k.setAttribute('cx', '18'); k.setAttribute('cy', '18'); k.setAttribute('r', '15.9155'); svg.appendChild(k); });
			var share = (c[0] === 'ha' || c[0] === 'policy') ? (n ? 100 : 0) : Math.round(100 * n / total);
			arc.setAttribute('stroke-dasharray', share + ' ' + (100 - share));
			var ring = el('span', 'k-ring');
			ring.appendChild(svg);
			ring.appendChild(el('b', '', String(n)));
			li.appendChild(ring);
			li.appendChild(el('span', 'k-ring-label', c[1]));
			li.title = n + ' ' + c[1].toLowerCase();
			ul.appendChild(li);
		});
		$('k-headline').textContent = d.headline;
		var lay = d.layout || {};
		$('k-title').textContent = lay.heading || d.title || 'FreeSense Fleet';
		var sub = $('k-sub');
		sub.textContent = lay.subheading || '';
		sub.hidden = !lay.subheading;
		document.title = (d.counts.offline ? '(' + d.counts.offline + ' offline) ' : '') + (d.title || 'FreeSense Fleet');
	}

	function ops(d) {
		var box = $('k-ops');
		box.textContent = '';
		box.hidden = !d.ops.length;
		d.ops.forEach(function (o) {
			var row = el('div', 'k-op');
			row.appendChild(el('span', '', o.title + ' ' + o.done + '/' + o.total));
			var bar = el('div', 'k-op-bar');
			var fill = el('span');
			fill.style.width = Math.max(0, Math.min(100, o.percent)) + '%';
			bar.appendChild(fill);
			row.appendChild(bar);
			box.appendChild(row);
		});
	}

	/* ------------------------------------------------------------ layout */

	function layout() {
		var c = cfg;
		body.className = 'k-body k-l-' + c.layout + (c.side === 'right' ? ' k-swap' : '') + (c.view === 'tiles' ? ' k-v-tiles' : ' k-v-list');
		body.style.setProperty('--k-left', c.left + '%');
		fitColumns();
	}

	/* The columns that fit the list's width: the least needed go first. */
	function fitColumns() {
		var em = parseFloat(getComputedStyle(list).fontSize) || 16;
		var gap = 0.9 * em;
		var room = list.clientWidth - 2 * em;
		cols = cfg.columns.slice();
		var need = function () { return cols.reduce(function (a, k) { return a + COLS[k][1] * em + gap; }, 0); };
		while (room > 0 && need() > room && cols.length > 2) {
			var drop = cols.reduce(function (a, k) { return COLS[k][3] < COLS[a][3] ? k : a; }, cols[cols.length - 1]);
			cols.splice(cols.indexOf(drop), 1);
		}
		list.style.setProperty('--k-cols', cols.map(function (k) { return 'minmax(' + COLS[k][1] + 'em, ' + COLS[k][2] + 'fr)'; }).join(' '));
	}

	/* ------------------------------------------------------------ the firewall list */

	function stateCell(b) {
		var s = STATES[b.state] || STATES['new'];
		var st = el('span', 'k-state');
		st.innerHTML = s[1];
		st.appendChild(document.createTextNode(s[0]));
		return st;
	}

	function flags(b) {
		var f = el('span', 'k-flags');
		if (b.breakglass) { f.appendChild(el('span', 'k-flag k-f-bad', 'Lock off')); }
		if (b.policy) { f.appendChild(el('span', 'k-flag k-f-warn', b.policy === 1 ? '1 policy fail' : b.policy + ' policy fails')); }
		if (b.update) { f.appendChild(el('span', 'k-flag', 'Update')); }
		if (b.op) {
			var o = el('span', 'k-flag k-f-op');
			o.title = b.op.text;
			var bar = el('span', 'k-op-bar');
			var fill = el('span');
			fill.style.width = (b.op.progress === null ? 100 : b.op.progress) + '%';
			bar.appendChild(fill);
			o.appendChild(el('span', '', b.op.text || 'Working'));
			o.appendChild(bar);
			f.appendChild(o);
		}
		return f;
	}

	function cell(k, b) {
		var c = el('span', 'k-cell k-col-' + k);
		c.setAttribute('role', 'cell');
		switch (k) {
		case 'state': c.appendChild(stateCell(b)); break;
		case 'name':
			c.appendChild(el('span', 'k-name', b.name));
			if (b.problem) { c.appendChild(el('span', 'k-problem', b.problem)); }
			break;
		case 'host': c.textContent = b.host || ''; break;
		case 'groups': c.textContent = (b.groups || []).join(', '); break;
		case 'version': c.textContent = (b.version || '-').replace('-DEVELOPMENT', ' dev').replace('-RELEASE', ''); c.title = b.version || ''; break;
		case 'seen': c.textContent = b.seen ? ago(b.seen) : '-'; break;
		case 'cpu': c.appendChild(meter(b.cpu, 70, 90)); break;
		case 'mem': c.appendChild(meter(b.mem, 80, 92)); break;
		case 'states':
			c.textContent = b.states === null ? '-' : short(b.states);
			if (b.states !== null && b.states_max) { c.appendChild(el('small', 'k-sub', pct(100 * b.states / b.states_max))); }
			break;
		case 'traffic':
			c.textContent = (b.rx === null && b.tx === null) ? '-' : '↓ ' + short(b.rx, ' b/s') + '  ↑ ' + short(b.tx, ' b/s');
			break;
		case 'uptime':
			c.textContent = pct(b.up);
			if (b.up !== null && b.up < 99) { c.classList.add(b.up < 95 ? 'k-t-bad' : 'k-t-warn'); }
			break;
		case 'ha': if (b.ha) { c.appendChild(el('span', 'k-role k-role-' + b.ha.toLowerCase(), b.ha)); } break;
		case 'inet':
			if (!b.inet) { c.textContent = '-'; break; }
			c.appendChild(el('span', 'k-dot k-inet-' + b.inet.state, ''));
			if (b.inet.score !== null && b.inet.score !== undefined) {
				c.appendChild(el('span', 'k-score k-score-' + scoreTone(b.inet.score), 'Q ' + b.inet.score));
			}
			/* Compact for the list: "0.6 ms · 0%". */
			c.appendChild(el('span', 'k-inet-text', (b.inet.text || INET[b.inet.state]).replace(' % loss', '%')));
			c.title = INET[b.inet.state] + (b.inet.gw ? ' · ' + b.inet.gw : '');
			if (b.inet.state === 'down') { c.classList.add('k-t-bad'); } else if (b.inet.state === 'degraded') { c.classList.add('k-t-warn'); }
			break;
		case 'flags': c.appendChild(flags(b)); break;
		}
		return c;
	}

	function row(b) {
		var r = el(live && b.id ? 'a' : 'div', 'k-lrow k-' + b.state);
		r.setAttribute('role', 'row');
		if (live && b.id) {
			r.href = '/fleet/fleet_box.php?id=' + encodeURIComponent(b.id);
			r.target = '_blank';
			r.rel = 'noopener';
		}
		cols.forEach(function (k) { r.appendChild(cell(k, b)); });
		return r;
	}

	function rowsPerPage() {
		if (cfg.rows) { return cfg.rows; }
		if (window.matchMedia('(max-width: 1100px)').matches) { return 1e6; }
		var probe = list.querySelector('.k-lrow:not(.k-lhead)');
		var head = list.querySelector('.k-lhead');
		var rh = probe ? probe.offsetHeight + (parseFloat(getComputedStyle(list).rowGap) || 0) : 48;
		return Math.max(1, Math.floor((list.clientHeight - (head ? head.offsetHeight : 0)) / Math.max(24, rh)));
	}

	function drawList() {
		var boxes = data.boxes;
		list.textContent = '';
		var head = el('div', 'k-lrow k-lhead');
		head.setAttribute('role', 'row');
		fitColumns();
		cols.forEach(function (k) {
			var h = el('span', 'k-cell k-col-' + k, COLS[k][0]);
			h.setAttribute('role', 'columnheader');
			head.appendChild(h);
		});
		list.appendChild(head);
		if (!boxes.length) {
			list.appendChild(el('p', 'k-empty', 'No firewalls to show.'));
			pager(1, $('k-pager'), page);
			return;
		}
		/* One row first to measure, then as many as fit. */
		list.appendChild(row(boxes[0]));
		var per = rowsPerPage();
		var pages = Math.max(1, Math.ceil(boxes.length / per));
		if (page >= pages) { page = 0; }
		list.removeChild(list.lastChild);
		boxes.slice(page * per, page * per + per).forEach(function (b) { list.appendChild(row(b)); });
		pager(pages, $('k-pager'), page, data.counts.offline && cfg.hold ? 'held while a firewall is offline' : '');
		return pages;
	}

	function pager(pages, at, current, note) {
		at.textContent = '';
		if (pages <= 1) { return; }
		var dots = el('span', 'k-dots');
		for (var i = 0; i < pages; i++) { dots.appendChild(el('i', i === current ? 'k-on' : '')); }
		at.appendChild(dots);
		at.appendChild(el('span', '', 'Page ' + (current + 1) + ' of ' + pages + (note ? ' (' + note + ')' : '')));
	}

	/* The tiles, for a screen that wants them. */
	function tile(b) {
		var t = el(live && b.id ? 'a' : 'article', 'k-tile k-' + b.state);
		if (live && b.id) {
			t.href = '/fleet/fleet_box.php?id=' + encodeURIComponent(b.id);
			t.target = '_blank';
			t.rel = 'noopener';
		}
		t.appendChild(el('div', 'k-name', b.name));
		if (b.host) { t.appendChild(el('div', 'k-host', b.host)); }
		var r = el('div', 'k-row');
		r.appendChild(stateCell(b));
		r.appendChild(flags(b));
		t.appendChild(r);
		if (b.problem) {
			t.appendChild(el('div', 'k-problem', b.problem));
		} else if (b.groups.length || b.version) {
			t.appendChild(el('div', 'k-meta', [b.groups.join(', '), b.version].filter(Boolean).join(' · ')));
		}
		if (b.cpu !== null || b.mem !== null) {
			var m = el('div', 'k-tmeters');
			m.appendChild(el('span', 'k-sub', 'CPU'));
			m.appendChild(meter(b.cpu, 70, 90));
			m.appendChild(el('span', 'k-sub', 'Mem'));
			m.appendChild(meter(b.mem, 80, 92));
			t.appendChild(m);
		}
		return t;
	}

	function capacity() {
		if (window.matchMedia('(max-width: 1100px)').matches) { return 1e6; }
		if (cfg.rows) { return cfg.rows; }
		var cs = getComputedStyle(grid);
		var cols = cs.gridTemplateColumns.split(' ').length;
		var gap = parseFloat(cs.rowGap) || 12;
		var rowH = parseFloat(cs.gridAutoRows) || 115;
		return Math.max(1, cols * Math.max(1, Math.floor((grid.clientHeight + gap) / (rowH + gap))));
	}

	function drawTiles() {
		var per = capacity();
		var pages = Math.max(1, Math.ceil(data.boxes.length / per));
		if (page >= pages) { page = 0; }
		grid.textContent = '';
		if (!data.boxes.length) { grid.appendChild(el('p', 'k-empty', 'No firewalls to show.')); }
		data.boxes.slice(page * per, page * per + per).forEach(function (b) { grid.appendChild(tile(b)); });
		pager(pages, $('k-pager'), page, data.counts.offline && cfg.hold ? 'held while a firewall is offline' : '');
		return pages;
	}

	function drawRight() {
		if (cfg.layout === 'panels') { return 1; }
		return cfg.view === 'tiles' ? drawTiles() : drawList();
	}

	/* ------------------------------------------------------------ panels */

	function card(id, title, size) {
		var c = el('article', 'k-p k-p-' + id + ' k-p-s' + size);
		var h = el('header', 'k-p-head');
		h.appendChild(el('h2', '', title));
		c.appendChild(h);
		c.appendChild(el('div', 'k-p-body'));
		return c;
	}

	function stat(label, value, tone) {
		var s = el('div', 'k-stat' + (tone ? ' k-t-' + tone : ''));
		s.appendChild(el('b', '', value));
		s.appendChild(el('span', '', label));
		return s;
	}

	/* Bars drawn here (the chart library's bar list sets inline style markup). */
	function hbars(items, unit, tone) {
		var ul = el('ul', 'k-hbars');
		var max = Math.max.apply(null, items.map(function (i) { return i.value || 0; }).concat([1]));
		items.forEach(function (i) {
			var li = el('li');
			li.appendChild(el('span', 'k-hb-label', i.label));
			var tr = el('span', 'k-hb-track');
			var fill = el('span', 'k-hb-fill k-t-' + (i.tone || tone || 'info'));
			fill.style.width = (100 * (i.value || 0) / max) + '%';
			tr.appendChild(fill);
			li.appendChild(tr);
			li.appendChild(el('span', 'k-hb-v', i.text !== undefined ? i.text : short(i.value, unit)));
			ul.appendChild(li);
		});
		return ul;
	}

	function chartBox(b, spec) {
		var c = el('div', 'k-chart');
		b.appendChild(c);
		return function () {
			if (!charts) { return; }
			/* Draw, then give the legend the room it took. */
			spec.height = Math.max(70, c.clientHeight - 24);
			charts.draw(c, spec);
			var over = c.scrollHeight - c.clientHeight;
			if (over > 0) {
				spec.height = Math.max(60, spec.height - over - 2);
				charts.draw(c, spec);
			}
		};
	}

	function seriesTop(top, unit) {
		return top.map(function (r, i) { return { name: r.label, data: r.data, color: i + 1 }; });
	}

	function scoreTone(s) { return s >= 90 ? 'ok' : (s >= 75 ? 'info' : (s >= 50 ? 'warn' : 'bad')); }
	function scoreWord(s) { return s >= 90 ? 'excellent' : (s >= 75 ? 'good' : (s >= 50 ? 'unstable' : 'bad')); }
	var INET = { up: 'Internet up', degraded: 'Internet poor', down: 'No internet', unknown: 'Internet unknown' };

	var PANELS = {
		health: function (p, b) {
			var c = data.counts;
			var row1 = el('div', 'k-stats k-stats-col');
			row1.appendChild(stat('up over 24 h', pct(p.up), p.up !== null && p.up < 99 ? 'warn' : 'ok'));
			row1.appendChild(stat('outages (24 h)', String(p.outages), p.outages ? 'warn' : ''));
			row1.appendChild(stat('longest', p.longest ? span(p.longest) : '-'));
			b.appendChild(row1);
			var d = el('div', 'k-chart k-donut');
			b.appendChild(d);
			return function () {
				if (charts) {
					charts.draw(d, { type: 'donut', label: 'Firewalls by state', center: String(data.total), parts: [
						{ name: 'Online', value: c.online || 0, tone: 'pass' }, { name: 'Late', value: c.degraded || 0, tone: 'warn' },
						{ name: 'Offline', value: c.offline || 0, tone: 'block' }, { name: 'Not seen', value: c['new'] || 0, tone: 'neutral' }] });
				}
			};
		},
		ha: function (p, b) {
			if (!p.pairs.length) {
				b.appendChild(el('p', 'k-quiet', 'No HA pairs in the fleet.'));
				return null;
			}
			var ul = el('ul', 'k-pairs');
			p.pairs.forEach(function (pair) {
				var li = el('li', 'k-pair' + (pair.problem ? ' k-pair-bad' : ''));
				var h = el('div', 'k-pair-head');
				h.appendChild(el('strong', '', pair.name));
				h.appendChild(el('span', 'k-badge ' + (pair.problem ? 'k-b-bad' : 'k-b-ok'), pair.problem || 'Healthy'));
				li.appendChild(h);
				var m = el('div', 'k-pair-members');
				pair.members.forEach(function (x) {
					var s = el('span', 'k-member');
					s.appendChild(el('span', 'k-role k-role-' + x.role.toLowerCase(), x.role === 'down' ? 'DOWN' : x.role));
					s.appendChild(el('span', '', x.label));
					m.appendChild(s);
				});
				li.appendChild(m);
				li.appendChild(el('span', 'k-sub', pair.vips + (pair.vips === 1 ? ' shared address' : ' shared addresses') + (pair.last ? ' · last change ' + ago(pair.last) : '')));
				ul.appendChild(li);
			});
			b.appendChild(ul);
			return null;
		},
		controller: function (p, b) {
			var g = el('div', 'k-stats k-stats-grid');
			var lag = p.poll_at ? Math.round(Date.now() / 1000 - p.poll_at) : null;
			g.appendChild(stat('up', span(p.uptime)));
			g.appendChild(stat('load (' + p.cpus + ' CPU)', p.load.length ? p.load.map(function (v) { return v.toFixed(1); }).join(' ') : '-', p.load[0] > p.cpus ? 'warn' : ''));
			g.appendChild(stat('memory', pct(p.mem_pct), p.mem_pct > 90 ? 'bad' : (p.mem_pct > 80 ? 'warn' : '')));
			g.appendChild(stat('disk free', p.disk_free === null ? '-' : bytes(p.disk_free), p.disk_pct > 90 ? 'bad' : (p.disk_pct > 80 ? 'warn' : '')));
			g.appendChild(stat('database', bytes(p.db_bytes)));
			g.appendChild(stat('poll round', p.poll_at ? p.poll_secs + ' s for ' + p.poll_boxes : '-', lag !== null && lag > 3 * Math.max(15, p.poll_interval) + 60 ? 'bad' : ''));
			g.appendChild(stat('tunnel peers active', p.tunnel_recent + ' / ' + p.tunnel_peers, p.tunnel_recent < p.tunnel_peers ? 'warn' : 'ok'));
			g.appendChild(stat('standby', p.standby_role === 'primary' ? (p.standby_seen ? 'seen ' + ago(p.standby_seen) : 'not seen') : (p.standby_role || 'none'),
			    p.standby_role === 'primary' && (!p.standby_seen || Date.now() / 1000 - p.standby_seen > 900) ? 'warn' : ''));
			g.appendChild(stat('waiting to join', String(p.pending), p.pending ? 'warn' : ''));
			b.appendChild(g);
			b.appendChild(el('p', 'k-sub k-p-foot', [p.host, p.version, p.fleet_version ? 'Fleet ' + p.fleet_version : ''].filter(Boolean).join(' · ')));
			return null;
		},
		pulse: function (p, b) {
			return chartBox(b, { type: 'pulse', rows: p.rows || [], t: p.t || [], nowLabel: 'now', empty: 'No firewalls yet.',
			    states: { online: 'online', degraded: 'late', offline: 'offline', 'new': 'not seen yet', none: 'not in the fleet yet' } });
		},
		load: function (p, b) {
			return chartBox(b, { type: 'line', t: p.t, unit: '%', max: 100, empty: 'No load samples yet.', series: [
				{ name: 'CPU', data: p.cpu, color: 1 }, { name: 'CPU 90%', data: p.cpu_p90, color: 1, dash: true },
				{ name: 'Memory', data: p.mem, color: 2 }, { name: 'Memory 90%', data: p.mem_p90, color: 2, dash: true }] });
		},
		traffic: function (p, b) {
			return chartBox(b, { type: 'line', t: p.t, unit: 'b', empty: 'No traffic samples yet.', series: [{ name: 'In', data: p.rx, color: 3, fill: true }, { name: 'Out', data: p.tx, color: 4 }] });
		},
		states: function (p, b) {
			return chartBox(b, { type: 'line', t: p.t, unit: '%', max: 100, empty: 'No samples yet.', series: seriesTop(p.top) });
		},
		temp: function (p, b) {
			return chartBox(b, { type: 'line', t: p.t, unit: '°', empty: 'No temperature reported.', series: seriesTop(p.top) });
		},
		alerts: function (p, b) {
			var draw = chartBox(b, { type: 'bars', labels: p.days.map(day), series: [
				{ name: 'Critical', data: p.day.critical, tone: 'block' }, { name: 'Warning', data: p.day.warning, tone: 'warn' }, { name: 'Info', data: p.day.info, tone: 'info' }] });
			var ul = el('ul', 'k-feed');
			p.latest.forEach(function (a) {
				var li = el('li', 'k-sev-' + a.severity);
				li.appendChild(el('time', '', ago(a.time)));
				li.appendChild(el('span', '', a.title + (a.box ? ': ' + a.box : '')));
				ul.appendChild(li);
			});
			if (!p.latest.length) { ul.appendChild(el('li', 'k-quiet', 'No alerts yet.')); }
			b.appendChild(ul);
			return draw;
		},
		ops: function (p, b) {
			var s = el('div', 'k-stats');
			s.appendChild(stat('running now', String(data.ops.length), data.ops.length ? 'info' : ''));
			s.appendChild(stat('failed (24 h)', String(p.failed_24h), p.failed_24h ? 'bad' : ''));
			b.appendChild(s);
			return chartBox(b, { type: 'bars', labels: p.days.map(day), series: [{ name: 'Done', data: p.day.done, tone: 'pass' }, { name: 'Failed', data: p.day.failed, tone: 'block' }] });
		},
		backups: function (p, b) {
			var s = el('div', 'k-stats');
			s.appendChild(stat('with a backup', p['with'] + ' / ' + p.total, p['with'] < p.total ? 'warn' : 'ok'));
			s.appendChild(stat('oldest newest backup', p.oldest ? ago(p.oldest) : '-', p.oldest && Date.now() / 1000 - p.oldest > 7 * 86400 ? 'warn' : ''));
			s.appendChild(stat('made (24 h)', String(p.ok_24h)));
			b.appendChild(s);
			return chartBox(b, { type: 'bars', labels: p.days.map(day), series: [{ name: 'Made', data: p.day.ok, tone: 'pass' }, { name: 'Failed', data: p.day.failed, tone: 'block' }] });
		},
		compliance: function (p, b) {
			var all = p.pass + p.fail + p.unknown;
			var s = el('div', 'k-stats');
			s.appendChild(stat('rules passing', all ? pct(100 * p.pass / all) : '-', p.fail ? 'warn' : 'ok'));
			s.appendChild(stat('failing checks', String(p.fail), p.fail ? 'bad' : ''));
			b.appendChild(s);
			if (p.rules.length) {
				b.appendChild(hbars(p.rules.map(function (r) { return { label: r.label, value: r.value, text: r.value + (r.value === 1 ? ' firewall' : ' firewalls') }; }), '', 'block'));
			} else {
				b.appendChild(el('p', 'k-quiet', all ? 'Every firewall passes its rules.' : 'No policies yet.'));
			}
			return null;
		},
		versions: function (p, b) {
			var s = el('div', 'k-stats');
			s.appendChild(stat('versions', String(p.versions.length), p.versions.length > 2 ? 'warn' : ''));
			s.appendChild(stat('can update', String(p.updates), p.updates ? 'info' : ''));
			b.appendChild(s);
			b.appendChild(hbars(p.versions.slice(0, 5).map(function (v) {
				return { label: v.label.replace('-DEVELOPMENT', ' dev').replace('-RELEASE', ''), value: v.value, text: String(v.value) };
			}), '', 'info'));
			return null;
		},
		busiest: function (p, b) {
			if (!p.busiest.length) {
				b.appendChild(el('p', 'k-quiet', 'No load samples yet.'));
				return null;
			}
			b.appendChild(hbars(p.busiest.map(function (r) {
				return { label: r.label, value: r.cpu || 0, text: pct(r.cpu) + ' CPU · ' + pct(r.mem) + ' mem', tone: r.cpu >= 90 ? 'block' : (r.cpu >= 70 ? 'warn' : 'info') };
			}), '%'));
			return null;
		},
		outages: function (p, b) {
			return chartBox(b, { type: 'bars', labels: p.days.map(day), series: [{ name: 'Outages', data: p.day, tone: 'block' }] });
		},
		inet: function (p, b) {
			var s = el('div', 'k-stats k-stats-col');
			s.appendChild(stat('with internet now', p.total ? (p.up + p.degraded) + ' / ' + p.total : '-', p.down ? 'bad' : (p.degraded ? 'warn' : 'ok')));
			s.appendChild(stat('internet up over 24 h', pct(p.avail), p.avail !== null && p.avail < 99 ? 'warn' : ''));
			s.appendChild(stat('on a backup WAN', String(p.backup), p.backup ? 'warn' : ''));
			b.appendChild(s);
			var d = el('div', 'k-chart k-donut');
			b.appendChild(d);
			return function () {
				if (charts) {
					charts.draw(d, { type: 'donut', label: 'Internet by state', center: String(p.down ? p.down : p.up), parts: [
						{ name: 'Up', value: p.up, tone: 'pass' }, { name: 'Poor', value: p.degraded, tone: 'warn' },
						{ name: 'Down', value: p.down, tone: 'block' }, { name: 'Unknown', value: p.unknown, tone: 'neutral' }] });
				}
			};
		},
		inet_quality: function (p, b) {
			var s = el('div', 'k-stats');
			var last = function (a) { for (var i = a.length - 1; i >= 0; i--) { if (a[i] !== null) { return a[i]; } } return null; };
			var dl = last(p.delay), ll = last(p.loss);
			s.appendChild(stat('median latency', dl === null ? '-' : dl + ' ms'));
			s.appendChild(stat('median loss', ll === null ? '-' : ll + '%', ll ? 'warn' : ''));
			b.appendChild(s);
			/* Latency and packet loss in their own charts: milliseconds and percent do not share an axis. */
			var two = el('div', 'k-charts-2');
			b.appendChild(two);
			var d1 = chartBox(two, { type: 'line', t: p.t, unit: ' ms', empty: 'No internet checks yet.', series: [
				{ name: 'Latency', data: p.delay, color: 1 }, { name: 'Latency 90%', data: p.delay_p90, color: 1, dash: true }] });
			var d2 = chartBox(two, { type: 'line', t: p.t, unit: '%', empty: 'No loss measured.', series: [
				{ name: 'Loss', data: p.loss, color: 5, fill: true }, { name: 'Loss 90%', data: p.loss_p90, color: 5, dash: true }] });
			return function () { d1(); d2(); };
		},
		inet_worst: function (p, b) {
			b.appendChild(hbars(p.top.map(function (r) {
				return { label: r.label, value: r.value, text: r.text, tone: r.state === 'down' ? 'block' : (r.state === 'degraded' ? 'warn' : 'info') };
			}), ''));
			return null;
		},
		inet_score: function (p, b) {
			var f = p.fleet || {};
			var s = el('div', 'k-stats');
			s.appendChild(stat('fleet quality', f.score === null || f.score === undefined ? '-' : String(f.score), f.score < 75 ? 'warn' : 'ok'));
			s.appendChild(stat('average loss', f.loss === null || f.loss === undefined ? '-' : Math.round(f.loss * 10) / 10 + '%', f.loss ? 'warn' : ''));
			s.appendChild(stat('flaps', String(f.flaps || 0), f.flaps ? 'warn' : ''));
			s.appendChild(stat('minutes with loss', String(f.loss_min || 0), f.loss_min ? 'warn' : ''));
			b.appendChild(s);
			b.appendChild(hbars((p.top || []).map(function (r) {
				return { label: r.label, value: 100 - r.score, text: 'Q ' + r.score + ' · ' + (r.loss === null ? '-' : Math.round(r.loss * 10) / 10 + '%') + ' loss · ' + r.flaps + ' flaps',
				    tone: scoreTone(r.score) === 'ok' ? 'pass' : (scoreTone(r.score) === 'bad' ? 'block' : scoreTone(r.score)) };
			}), ''));
			return null;
		},
		inet_pulse: function (p, b) {
			return chartBox(b, { type: 'pulse', rows: p.rows || [], t: p.t || [], nowLabel: 'now', empty: 'No internet checks yet.',
			    states: { online: 'internet up', degraded: 'internet poor', offline: 'no internet', 'new': 'not checked', none: 'not checked' } });
		},
		inet_events: function (p, b) {
			var ul = el('ul', 'k-feed');
			p.latest.forEach(function (a) {
				var li = el('li', 'k-sev-' + a.severity);
				li.appendChild(el('time', '', ago(a.time)));
				li.appendChild(el('span', '', a.title + (a.box ? ': ' + a.box : '')));
				ul.appendChild(li);
			});
			if (!p.latest.length) { ul.appendChild(el('li', 'k-quiet', 'No failovers or internet outages.')); }
			b.appendChild(ul);
			return null;
		}
	};
	var TITLES = {
		health: 'Fleet health', ha: 'HA pairs', controller: 'Fleet server', pulse: 'Availability, last 24 hours', load: 'CPU and memory', traffic: 'Traffic, whole fleet',
		states: 'State tables, fullest', temp: 'Temperature, warmest', alerts: 'Alerts', ops: 'Operations', backups: 'Backups', compliance: 'Policy compliance',
		versions: 'Versions', busiest: 'Busiest firewalls', outages: 'Outages per day',
		inet: 'Internet now', inet_quality: 'Internet quality', inet_worst: 'Worst internet connections', inet_score: 'Connection quality (lowest first)', inet_pulse: 'Internet, last 24 hours',
		inet_events: 'Failovers and internet outages'
	};
	var SIZES = { ha: 2, controller: 2, pulse: 2, alerts: 2, inet_quality: 2 };
	function size(id) {
		if (id === 'ha') { return (data.panels.ha && data.panels.ha.pairs.length > 1) ? 2 : 1; }
		if (id === 'pulse' || id === 'inet_pulse') { return ((data.panels[id] || {}).rows || []).length > 8 ? 2 : 1; }
		return SIZES[id] || 1;
	}

	/* Which panels go on which page: whole cards, in order, as many as the panel grid holds. */
	function panelPages(ids) {
		if (window.matchMedia('(max-width: 1100px)').matches) { return [ids]; }
		var cs = getComputedStyle(panels);
		var cols = Math.max(1, cs.gridTemplateColumns.split(' ').length);
		var gap = parseFloat(cs.rowGap) || 12;
		var rowH = parseFloat(cs.gridAutoRows) || 200;
		var rows = Math.max(2, Math.floor((panels.clientHeight + gap) / (rowH + gap)));
		var cap = cols * rows, pages = [], cur = [], used = 0;
		ids.forEach(function (id) {
			var sz = Math.min(rows, size(id));
			if (used + sz > cap && cur.length) {
				pages.push(cur);
				cur = [];
				used = 0;
			}
			cur.push(id);
			used += sz;
		});
		if (cur.length) { pages.push(cur); }
		return pages.length ? pages : [[]];
	}

	function drawPanels() {
		if (cfg.layout === 'list') { return 1; }
		/* A panel with nothing to show (no temperature sensors, no samples yet) gives its place to the next. */
		var empty = function (id) {
			var p = data.panels[id];
			return ((id === 'temp' || id === 'states' || id === 'inet_worst' || id === 'inet_score') && !(p.top || []).length) || (id === 'busiest' && !(p.busiest || []).length);
		};
		var ids = cfg.panels.filter(function (id) { return data.panels && data.panels[id] && PANELS[id] && !empty(id); });
		var pages = panelPages(ids);
		if (ppage >= pages.length) { ppage = 0; }
		panels.textContent = '';
		var later = [];
		pages[ppage].forEach(function (id) {
			var c = card(id, TITLES[id], size(id));
			panels.appendChild(c);
			try {
				var d = PANELS[id](data.panels[id], c.querySelector('.k-p-body'));
				if (d) { later.push(d); }
			} catch (e) {
				c.querySelector('.k-p-body').appendChild(el('p', 'k-quiet', 'Not available.'));
			}
		});
		later.forEach(function (d) {
			try { d(); } catch (e) { /* one chart that cannot draw leaves the others */ }
		});
		pager(pages.length, $('k-ppager'), ppage);
		return pages.length;
	}

	/* ------------------------------------------------------------ turning pages */

	function fade(n) {
		n.classList.remove('k-turn');
		void n.offsetWidth;
		n.classList.add('k-turn');
	}

	function turn() {
		if (!data) { return; }
		if (cfg.hold && data.counts.offline) {
			if (page !== 0) {
				page = 0;
				drawRight();
			}
			return;
		}
		page++;
		drawRight();
		fade(cfg.view === 'tiles' ? grid : list);
	}

	function turnPanels() {
		if (!data) { return; }
		ppage++;
		drawPanels();
		fade(panels);
	}

	function timers() {
		clearInterval(turnTimer);
		clearInterval(panelTimer);
		turnTimer = setInterval(turn, cfg.flip * 1000);
		panelTimer = setInterval(turnPanels, cfg.panel_flip * 1000);
	}

	function draw() {
		if (!data) { return; }
		drawPanels();
		drawRight();
	}

	/* ------------------------------------------------------------ data */

	function poll() {
		var req = live ? fetch('/fleet/noc_data.php', { cache: 'no-store', credentials: 'same-origin', redirect: 'manual' }) :
		    fetch('/fleet/kiosk_data.php', { headers: { 'X-Kiosk-Key': key }, cache: 'no-store', credentials: 'omit' });
		req.then(function (r) {
			/* A wall screen whose key is refused, or a live view whose session ended (the WebUI answers with its login page). */
			if (r.status === 403 || r.status === 405 || r.type === 'opaqueredirect' || (r.headers.get('Content-Type') || '').indexOf('json') < 0) {
				blocked();
				throw new Error('blocked');
			}
			return r.json();
		}).then(function (d) {
			if (!live && !fixed && d.style) {
				look(d.style, d.theme || 'auto');
			}
			$('k-blocked').hidden = true;
			var was = JSON.stringify(cfg);
			cfg = d.layout;
			if (JSON.stringify(cfg) !== was) {
				layout();
				timers();
			}
			if (!soundSet) {
				soundSet = true;
				sound = !!cfg.sound;
				soundButton();
			}
			var beepNow = false;
			var now = {};
			d.boxes.forEach(function (b) {
				now[b.name] = b.state;
				if (!first && b.state !== known[b.name] && cfg.beep.indexOf(b.state) >= 0) { beepNow = true; }
			});
			if (!first && cfg.beep.indexOf('ha') >= 0 && (d.ha_problems || 0) > haWas) { beepNow = true; }
			haWas = d.ha_problems || 0;
			var inetNow = {};
			d.boxes.forEach(function (b) {
				if (!b.inet) { return; }
				inetNow[b.name] = b.inet.state;
				if (!first && cfg.beep.indexOf('inet') >= 0 && b.inet.state === 'down' && inetKnown[b.name] !== 'down') { beepNow = true; }
			});
			inetKnown = inetNow;
			known = now;
			first = false;
			data = d;
			lastOk = Date.now();
			counts(d);
			ops(d);
			draw();
			clock();
			if (beepNow) { beep(); }
		}).catch(function () { clock(); });
	}

	$('k-sound').addEventListener('click', function () {
		sound = !sound;
		soundButton();
		if (sound) { beep(); }
	});
	/* A browser lets a page play sound only after a click on it; a screen set to sound gets it at the first touch. */
	document.addEventListener('click', function () { if (audio && audio.state === 'suspended') { audio.resume(); } });
	$('k-full').addEventListener('click', function () {
		if (document.fullscreenElement) { document.exitFullscreen(); } else if (document.documentElement.requestFullscreen) { document.documentElement.requestFullscreen(); }
	});
	var resized = null;
	window.addEventListener('resize', function () {
		clearTimeout(resized);
		resized = setTimeout(draw, 200);
	});
	dark.addEventListener('change', function () {
		if (root.getAttribute('data-theme-choice') === 'auto') { look((root.className.match(/\bk--(\S+)/) || [0, 'freesense'])[1], 'auto'); }
	});
	look((root.className.match(/\bk--(\S+)/) || [0, 'freesense'])[1], root.getAttribute('data-theme-choice') || 'auto');
	if (live) {
		$('k-style').addEventListener('change', function () {
			look(this.value, root.getAttribute('data-theme-choice'));
			keep(this.value, root.getAttribute('data-theme-choice'));
			draw();
		});
		$('k-theme').addEventListener('click', function () {
			var order = ['auto', 'dark', 'light'];
			var next = order[(order.indexOf(root.getAttribute('data-theme-choice')) + 1) % 3];
			look($('k-style').value, next);
			keep($('k-style').value, next);
			draw();
		});
	}

	if (!live && key.indexOf('fkk_') !== 0) {
		blocked('This link has no kiosk key. Open the full link an administrator made for this screen.');
		return;
	}
	clock();
	poll();
	setInterval(poll, POLL);
	setInterval(clock, 1000);
})();
