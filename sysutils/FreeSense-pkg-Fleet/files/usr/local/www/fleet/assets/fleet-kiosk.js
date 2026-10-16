/*
 * fleet-kiosk.js: the NOC screen. Reads the kiosk key from the URL
 * fragment, asks kiosk_data.php every 10 seconds, draws the tiles, turns
 * pages every 15 seconds when they do not fit (and holds page one while
 * a firewall is offline), and beeps for a newly offline firewall once
 * sound has been turned on with a click.
 */
(function () {
	'use strict';
	var key = decodeURIComponent((location.hash || '').replace(/^#/, ''));
	var $ = function (id) { return document.getElementById(id); };
	var grid = $('k-grid');
	var data = null;
	var page = 0;
	var lastOk = 0;
	var known = {};
	var first = true;
	var sound = false;
	var audio = null;
	var POLL = 10000;
	var TURN = 15000;
	var STATES = {
		online: ['Online', '<svg viewBox="0 0 16 16" aria-hidden="true"><path fill="currentColor" d="M6.2 11.6 2.8 8.2l1.1-1.1 2.3 2.3 5.9-5.9 1.1 1.1z"/></svg>'],
		degraded: ['Late answering', '<svg viewBox="0 0 16 16" aria-hidden="true"><path fill="currentColor" d="M8 1 15 14H1zm-.8 5v4h1.6V6zm0 5v1.6h1.6V11z"/></svg>'],
		offline: ['Offline', '<svg viewBox="0 0 16 16" aria-hidden="true"><path fill="currentColor" d="m4.1 3 3.9 3.9L11.9 3 13 4.1 9.1 8l3.9 3.9-1.1 1.1L8 9.1 4.1 13 3 11.9 6.9 8 3 4.1z"/></svg>'],
		'new': ['Not seen yet', '<svg viewBox="0 0 16 16" aria-hidden="true"><circle cx="8" cy="8" r="5" fill="none" stroke="currentColor" stroke-width="1.6"/></svg>']
	};

	function el(tag, cls, text) {
		var e = document.createElement(tag);
		if (cls) { e.className = cls; }
		if (text !== undefined) { e.textContent = text; }
		return e;
	}

	function blocked(text) {
		if (text) { $('k-blocked-text').textContent = text; }
		$('k-blocked').hidden = false;
		data = null;
		document.title = 'FreeSense Fleet: not connected';
	}

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

	function counts(d) {
		var ul = $('k-counts');
		ul.textContent = '';
		[['online', 'Online'], ['degraded', 'Late'], ['offline', 'Offline']].forEach(function (c) {
			var n = d.counts[c[0]] || 0;
			var li = el('li', 'k-c-' + c[0] + (n ? '' : ' k-zero'));
			li.appendChild(el('b', '', String(n)));
			li.appendChild(el('span', '', c[1]));
			ul.appendChild(li);
		});
		var h = $('k-headline');
		h.textContent = d.headline;
		h.className = 'k-headline' + (d.counts.offline ? ' k-bad' : (d.counts.degraded ? ' k-warn' : ''));
		$('k-title').textContent = d.title || 'FreeSense Fleet';
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

	function tile(b) {
		var t = el('article', 'k-tile k-' + b.state);
		var s = STATES[b.state] || STATES['new'];
		t.appendChild(el('div', 'k-name', b.name));
		if (b.host) { t.appendChild(el('div', 'k-host', b.host)); }
		var st = el('div', 'k-state');
		st.innerHTML = s[1];
		st.appendChild(document.createTextNode(s[0]));
		var row = el('div', 'k-row');
		row.appendChild(st);
		t.appendChild(row);
		if (b.problem) {
			t.appendChild(el('div', 'k-problem', b.problem));
		} else if (b.groups.length || b.version) {
			t.appendChild(el('div', 'k-meta', [b.groups.join(', '), b.version].filter(Boolean).join('  ')));
		}
		var flags = el('div', 'k-flags');
		if (b.breakglass) { flags.appendChild(el('span', 'k-flag k-f-bad', 'Lock off')); }
		if (b.policy) { flags.appendChild(el('span', 'k-flag', b.policy + ' policy')); }
		if (b.update) { flags.appendChild(el('span', 'k-flag', 'Update')); }
		if (flags.childNodes.length) { row.appendChild(flags); }
		if (b.op) {
			var bar = el('div', 'k-op-bar');
			bar.title = b.op.text;
			var fill = el('span');
			fill.style.width = (b.op.progress === null ? 100 : b.op.progress) + '%';
			bar.appendChild(fill);
			t.appendChild(bar);
		}
		return t;
	}

	/* How many tiles fit on the screen: columns from the grid, rows from the height left. */
	function capacity() {
		if (window.matchMedia('(max-width: 900px)').matches) { return 1e6; }
		var cs = getComputedStyle(grid);
		var cols = cs.gridTemplateColumns.split(' ').length;
		var gap = parseFloat(cs.rowGap) || 12;
		var rowH = parseFloat(cs.gridAutoRows) || 115;
		var h = grid.clientHeight - parseFloat(cs.paddingTop) - parseFloat(cs.paddingBottom);
		return Math.max(1, cols * Math.max(1, Math.floor((h + gap) / (rowH + gap))));
	}

	function draw() {
		if (!data) { return; }
		var per = capacity();
		var pages = Math.max(1, Math.ceil(data.boxes.length / per));
		if (page >= pages) { page = 0; }
		grid.textContent = '';
		if (!data.boxes.length) {
			grid.appendChild(el('p', 'k-empty', 'No firewalls in the fleet yet.'));
		}
		data.boxes.slice(page * per, page * per + per).forEach(function (b) { grid.appendChild(tile(b)); });
		$('k-page').textContent = pages > 1 ? 'Page ' + (page + 1) + ' of ' + pages + (data.counts.offline ? ' (held while a firewall is offline)' : '') : '';
	}

	function turn() {
		if (!data || data.counts.offline) {
			page = 0;
			return;
		}
		var pages = Math.max(1, Math.ceil(data.boxes.length / capacity()));
		if (pages > 1) {
			page = (page + 1) % pages;
			draw();
			grid.classList.remove('k-turn');
			void grid.offsetWidth;
			grid.classList.add('k-turn');
		}
	}

	function poll() {
		fetch('/fleet/kiosk_data.php', { headers: { 'X-Kiosk-Key': key }, cache: 'no-store', credentials: 'omit' }).then(function (r) {
			if (r.status === 403 || r.status === 405) {
				blocked();
				throw new Error('blocked');
			}
			return r.json();
		}).then(function (d) {
			$('k-blocked').hidden = true;
			var newly = false;
			var now = {};
			d.boxes.forEach(function (b, i) {
				now[b.name] = b.state;
				if (!first && b.state === 'offline' && known[b.name] !== 'offline') { newly = true; }
			});
			known = now;
			first = false;
			data = d;
			lastOk = Date.now();
			counts(d);
			ops(d);
			draw();
			clock();
			if (newly) { beep(); }
		}).catch(function () { clock(); });
	}

	$('k-sound').addEventListener('click', function () {
		sound = !sound;
		this.setAttribute('aria-pressed', String(sound));
		this.textContent = sound ? 'Sound is on' : 'Turn sound on';
		if (sound) { beep(); }
	});
	$('k-full').addEventListener('click', function () {
		if (document.fullscreenElement) { document.exitFullscreen(); } else if (document.documentElement.requestFullscreen) { document.documentElement.requestFullscreen(); }
	});
	window.addEventListener('resize', draw);

	if (key.indexOf('fkk_') !== 0) {
		blocked('This link has no kiosk key. Open the full link an administrator made for this screen.');
		return;
	}
	clock();
	poll();
	setInterval(poll, POLL);
	setInterval(clock, 1000);
	setInterval(turn, TURN);
})();
