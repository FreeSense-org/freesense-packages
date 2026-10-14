/*
 * threatshield_map.js
 * FreeSense Threat Shield - live threat map and its panels
 *
 * Copyright (c) 2025-2026 The FreeSense Project.
 * Licensed under the Apache License, Version 2.0.
 *
 * Needs ts-world.js (window.TSWorld). No other library: two canvases (the
 * land and the effects), colours from CSS custom properties so every style
 * follows the light and dark theme.
 *
 *   var map = new TSMap(element, {data: 'threatshield_map_data.php', mode: 'page', ...});
 *   new TSPanels(container, map, {...});
 */
(function (global) {
	'use strict';

	var W = global.TSWorld;
	var DPR = Math.min(global.devicePixelRatio || 1, 2);
	var BLOCKS = {block: 1, listed: 1};
	var KIND_KEYS = ['geoip', 'iplist', 'dnsbl', 'reputation', 'bypass', 'flood', 'fw_block', 'dns', 'service', 'safebrowsing'];

	/* Equal Earth, the same constants as tools/threatshield/build_world.py */
	function project(lat, lon) {
		var A1 = 1.340264, A2 = -0.081106, A3 = 0.000893, A4 = 0.003796, M = Math.sqrt(3) / 2;
		var lam = lon * Math.PI / 180, phi = lat * Math.PI / 180;
		var th = Math.asin(M * Math.sin(phi)), t2 = th * th, t6 = t2 * t2 * t2;
		var x = 2 * Math.sqrt(3) * lam * Math.cos(th) / (3 * (9 * A4 * t6 * t2 + 7 * A3 * t6 + 3 * A2 * t2 + A1));
		var y = th * (A4 * t6 * t2 + A3 * t6 + A2 * t2 + A1);
		return [W.proj.tx + W.proj.k * x, W.proj.ty - W.proj.k * y];
	}

	function cssVar(el, name, fallback) {
		var v = global.getComputedStyle(el).getPropertyValue(name).trim();
		return v || fallback;
	}

	/* any CSS colour → [r, g, b] (resolves var(), color-mix and names) */
	var probe = null;
	function rgb(color) {
		if (!probe) {
			probe = document.createElement('canvas').getContext('2d');
		}
		probe.fillStyle = '#000';
		probe.fillStyle = color;
		var c = probe.fillStyle;
		if (c.charAt(0) === '#') {
			return [parseInt(c.substr(1, 2), 16), parseInt(c.substr(3, 2), 16), parseInt(c.substr(5, 2), 16)];
		}
		var m = c.match(/[\d.]+/g) || [0, 0, 0];
		return [+m[0], +m[1], +m[2]];
	}
	function rgba(c, a) {
		return 'rgba(' + c[0] + ',' + c[1] + ',' + c[2] + ',' + a.toFixed(3) + ')';
	}

	function fmt(n) {
		n = +n || 0;
		if (n >= 1e6) {
			return (n / 1e6).toFixed(n >= 1e7 ? 0 : 1) + 'M';
		}
		if (n >= 1e4) {
			return (n / 1e3).toFixed(n >= 1e5 ? 0 : 1) + 'k';
		}
		return n.toLocaleString();
	}

	function esc(s) {
		return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
			return {'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c];
		});
	}

	function clock(t) {
		var d = new Date(t * 1000);
		return ('0' + d.getHours()).slice(-2) + ':' + ('0' + d.getMinutes()).slice(-2) + ':' + ('0' + d.getSeconds()).slice(-2);
	}

	function reducedMotion() {
		return global.matchMedia && global.matchMedia('(prefers-reduced-motion: reduce)').matches;
	}

	/* =================================================================== TSMap */

	function TSMap(root, opts) {
		var self = this;
		this.root = root;
		this.o = Object.assign({
			data: 'threatshield_map_data.php', mode: 'page', style: 'freesense', window: '1h',
			filters: {block: true, pass: true, dns: true, ts: false}, poll: 3000, animations: 'full',
			mask: false, maxArcs: 40, canAct: false, t: {}, lite: false
		}, opts || {});
		this.t = this.o.t;
		this.cursor = 0;
		this.dots = {};          // id → dot
		this.particles = [];
		this.rings = [];
		this.queue = [];
		this.countries = {};     // cc → blocked count (shading)
		this.data = null;
		this.listeners = [];
		this.paused = false;
		this.failures = 0;
		this.lastFrame = 0;
		this.fps = (this.o.mode === 'mini' || this.o.mode === 'widget') ? 24 : 30;

		root.classList.add('tsm', 'tsm--' + this.o.style, 'tsm--' + this.o.mode);
		root.innerHTML = '<canvas class="tsm-land" aria-hidden="true"></canvas><canvas class="tsm-fx" aria-hidden="true"></canvas>' +
			'<div class="tsm-scan" aria-hidden="true"></div><div class="tsm-tip" role="tooltip" hidden></div>' +
			'<div class="tsm-empty" hidden></div>' +
			'<aside class="tsm-drawer" hidden aria-label="' + esc(this.t.details || 'Details') + '"><button type="button" class="btn-close tsm-drawer-close" aria-label="' +
			esc(this.t.close || 'Close') + '"></button><div class="tsm-drawer-body"></div></aside>';
		this.land = root.querySelector('.tsm-land');
		this.fx = root.querySelector('.tsm-fx');
		this.tip = root.querySelector('.tsm-tip');
		this.empty = root.querySelector('.tsm-empty');
		this.drawer = root.querySelector('.tsm-drawer');
		this.paths = {};
		Object.keys(W.c).forEach(function (cc) {
			self.paths[cc] = new Path2D(W.c[cc]);
		});

		this.readColors();
		this.resize();
		if (global.ResizeObserver) {
			new ResizeObserver(function () {
				self.resize();
			}).observe(root);
		} else {
			global.addEventListener('resize', function () {
				self.resize();
			});
		}
		/* theme switches (WebUI or kiosk) re-read the palette */
		new MutationObserver(function () {
			self.readColors();
			self.drawLand();
		}).observe(document.documentElement, {attributes: true, attributeFilter: ['data-bs-theme', 'class']});
		if (global.matchMedia) {
			global.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', function () {
				self.readColors();
				self.drawLand();
			});
		}

		this.fx.addEventListener('mousemove', function (e) {
			self.hover(e);
		});
		this.fx.addEventListener('mouseleave', function () {
			self.tip.hidden = true;
		});
		this.fx.addEventListener('click', function (e) {
			var d = self.pick(e);
			if (d) {
				self.select(d);
			}
		});
		this.drawer.querySelector('.tsm-drawer-close').addEventListener('click', function () {
			self.closeDrawer();
		});
		document.addEventListener('keydown', function (e) {
			if (e.key === 'Escape') {
				self.closeDrawer();
			}
		});
		document.addEventListener('visibilitychange', function () {
			if (!document.hidden) {
				self.poll(true);
			}
		});

		this.loop = this.loop.bind(this);
		global.requestAnimationFrame(this.loop);
		this.poll(true);
	}

	TSMap.prototype.on = function (fn) {
		this.listeners.push(fn);
		if (this.data) {
			fn(this.data, true);
		}
	};

	TSMap.prototype.setOptions = function (o) {
		var reload = ('window' in o && o.window !== this.o.window) || ('filters' in o) || ('mask' in o && o.mask !== this.o.mask);
		if ('style' in o && o.style !== this.o.style) {
			this.root.classList.remove('tsm--' + this.o.style);
			this.root.classList.add('tsm--' + o.style);
		}
		Object.assign(this.o, o);
		this.readColors();
		this.drawLand();
		if (reload) {
			this.cursor = 0;
			this.dots = {};
			this.particles = [];
			this.queue = [];
			this.poll(true);
		}
	};

	TSMap.prototype.readColors = function () {
		var r = this.root;
		this.c = {
			sea: cssVar(r, '--tsm-sea', '#fff'),
			land: cssVar(r, '--tsm-land', '#ddd'),
			border: cssVar(r, '--tsm-border', '#ccc'),
			heat: rgb(cssVar(r, '--tsm-heat', '#ea4f2d')),
			block: rgb(cssVar(r, '--tsm-block', '#e34948')),
			pass: rgb(cssVar(r, '--tsm-pass', '#1baf7a')),
			dns: rgb(cssVar(r, '--tsm-dns', '#eda100')),
			out: rgb(cssVar(r, '--tsm-out', '#2a78d6')),
			home: rgb(cssVar(r, '--tsm-home', '#ea4f2d')),
			dot: rgb(cssVar(r, '--tsm-landdot', '#1d4d33')),
			glow: parseFloat(cssVar(r, '--tsm-glow', '0')) || 0,
			matrix: cssVar(r, '--tsm-matrix', '0') === '1',
			radar: cssVar(r, '--tsm-radar', '0') === '1'
		};
	};

	TSMap.prototype.resize = function () {
		var rect = this.root.getBoundingClientRect();
		var w = Math.max(200, rect.width), h = rect.height;
		if (this.o.mode !== 'kiosk' || h < 50) {
			h = Math.round(w * W.h / W.w);
			if (this.o.mode === 'mini') {
				h = Math.min(h, 340, Math.max(180, Math.round(w * 0.26)));
			}
			this.root.style.height = h + 'px';
		}
		/* contain the map in the box, centred; the small banner crops the
		 * polar rows (the top 15 % and bottom 10 %) to stay low */
		var s = Math.min(w / W.w, h / W.h), oy;
		if (this.o.mode === 'mini') {
			s = Math.min(w / W.w, h / (W.h * 0.75));
			oy = -W.h * s * 0.15 + (h - W.h * s * 0.75) / 2;
		} else {
			oy = (h - W.h * s) / 2;
		}
		this.view = {w: w, h: h, s: s, ox: (w - W.w * s) / 2, oy: oy};
		[this.land, this.fx].forEach(function (cv) {
			cv.width = Math.round(w * DPR);
			cv.height = Math.round(h * DPR);
			cv.style.width = w + 'px';
			cv.style.height = h + 'px';
		});
		this.drawLand();
	};

	TSMap.prototype.xy = function (lat, lon) {
		var p = project(lat, lon), v = this.view;
		return [v.ox + p[0] * v.s, v.oy + p[1] * v.s];
	};

	TSMap.prototype.drawLand = function () {
		if (!this.view) {
			return;
		}
		var ctx = this.land.getContext('2d'), v = this.view, c = this.c, self = this;
		ctx.setTransform(DPR, 0, 0, DPR, 0, 0);
		ctx.clearRect(0, 0, v.w, v.h);
		ctx.fillStyle = c.sea;
		ctx.fillRect(0, 0, v.w, v.h);
		var max = 0;
		Object.keys(this.countries).forEach(function (cc) {
			max = Math.max(max, self.countries[cc]);
		});
		if (c.matrix) {
			/* dot-matrix land */
			var d = W.dots, k = v.s / W.s, r = Math.max(0.8, 1.6 * v.s);
			ctx.fillStyle = rgba(c.dot, 0.9);
			for (var i = 0; i < d.length; i += 2) {
				ctx.beginPath();
				ctx.arc(v.ox + d[i] * k, v.oy + d[i + 1] * k, r, 0, 6.2832);
				ctx.fill();
			}
		} else {
			ctx.save();
			ctx.translate(v.ox, v.oy);
			ctx.scale(v.s / W.s, v.s / W.s);
			ctx.lineWidth = W.s * 0.6 / v.s;
			ctx.strokeStyle = c.border;
			Object.keys(this.paths).forEach(function (cc) {
				ctx.fillStyle = c.land;
				ctx.fill(self.paths[cc]);
				var n = self.countries[cc];
				if (n && max > 0) {
					var a = 0.12 + 0.55 * Math.log(1 + n) / Math.log(1 + max);
					ctx.fillStyle = rgba(c.heat, a);
					ctx.fill(self.paths[cc]);
				}
				ctx.stroke(self.paths[cc]);
			});
			ctx.restore();
		}
		/* heat on the dot-matrix: glow over countries with blocks */
		if (c.matrix && max > 0 && this.data && this.data.top) {
			(this.data.top.countries || []).forEach(function (row) {
				var dot = self.anyDotOf(row.cc);
				if (!dot) {
					return;
				}
				var p = self.xy(dot.p[0], dot.p[1]);
				var g = ctx.createRadialGradient(p[0], p[1], 0, p[0], p[1], 40 * v.s + 10);
				var a = 0.15 + 0.35 * Math.log(1 + row.n) / Math.log(1 + max);
				g.addColorStop(0, rgba(c.heat, a));
				g.addColorStop(1, rgba(c.heat, 0));
				ctx.fillStyle = g;
				ctx.fillRect(p[0] - 60, p[1] - 60, 120, 120);
			});
		}
	};

	TSMap.prototype.anyDotOf = function (cc) {
		for (var id in this.dots) {
			if (this.dots[id].cc === cc) {
				return this.dots[id];
			}
		}
		return null;
	};

	/* ------------------------------------------------------------- data */

	TSMap.prototype.query = function () {
		var f = this.o.filters, acts = [];
		if (f.block) {
			acts.push('block', 'listed');
		}
		if (f.pass) {
			acts.push('pass', 'clean');
		}
		if (f.dns) {
			acts.push('dns_block', 'dns_allow');
		}
		var q = 'what=events&window=' + encodeURIComponent(this.o.window) + '&after=' + this.cursor + '&f=' + acts.join(',') +
			(f.ts ? '&ts=1' : '') + (f.cc ? '&cc=' + f.cc : '') + (this.o.lite ? '&lite=1' : '') + (this.o.mask ? '&mask=1' : '');
		return this.o.data + (this.o.data.indexOf('?') < 0 ? '?' : '&') + q;
	};

	TSMap.prototype.poll = function (now) {
		var self = this;
		clearTimeout(this.timer);
		if (document.hidden && !now) {
			this.timer = setTimeout(function () {
				self.poll();
			}, this.o.poll);
			return;
		}
		if (this.inflight) {
			return;
		}
		this.inflight = true;
		fetch(this.query(), {credentials: 'same-origin', headers: {Accept: 'application/json'}}).then(function (r) {
			if (r.status === 403 || (r.headers.get('content-type') || '').indexOf('json') < 0) {
				throw new Error('signed-out');
			}
			return r.json();
		}).then(function (d) {
			self.failures = 0;
			self.ingest(d);
			self.root.classList.remove('is-offline');
		}).catch(function (e) {
			self.failures++;
			self.root.classList.add('is-offline');
			self.emit({error: e.message === 'signed-out' ? 'signed-out' : 'offline'});
		}).finally(function () {
			self.inflight = false;
			var wait = self.failures ? Math.min(30000, self.o.poll * Math.pow(2, self.failures)) : self.o.poll;
			self.timer = setTimeout(function () {
				self.poll();
			}, wait);
		});
	};

	TSMap.prototype.emit = function (d, first) {
		this.listeners.forEach(function (fn) {
			fn(d, first);
		});
	};

	TSMap.prototype.ingest = function (d) {
		var self = this, first = (this.cursor === 0);
		this.data = d;
		this.home = d.home ? this.xy(d.home.lat, d.home.lon) : null;
		this.homeLL = d.home;
		if (d.dots) {
			this.dots = {};
			d.dots.forEach(function (x) {
				self.dots[x.id] = {id: x.id, ip: x.ip, cc: x.cc, a: x.a, n: x.n, last: x.last * 1000, hit: 0, p: x.p};
			});
		}
		/* country shading from the top list (limited) plus dots */
		this.countries = {};
		(d.top && d.top.countries || []).forEach(function (r) {
			self.countries[r.cc] = r.n;
		});
		this.drawLand();
		this.showEmpty(d);
		var evs = d.events || [];
		if (!first && evs.length) {
			/* replay the poll's events spread over the next interval */
			var span = this.o.poll * 0.9, step = span / Math.max(1, evs.length);
			var start = performance.now();
			evs.forEach(function (e, i) {
				self.queue.push({at: start + i * step, e: e});
			});
			if (this.queue.length > 400) {
				this.queue.splice(0, this.queue.length - 400);
			}
		} else {
			evs.forEach(function (e) {
				self.touchDot(e, false);
			});
		}
		if (d.cursor) {
			this.cursor = d.cursor;
		}
		this.emit(d, first);
		if (this.o.animations === 'off' || this.paused) {
			this.drawFx(performance.now());
		}
	};

	TSMap.prototype.showEmpty = function (d) {
		var msg = '';
		if (d.geodb && d.geodb.state !== 'ok') {
			msg = (d.geodb.state === 'off') ? (this.t.geoOff || '') : (this.t.geoMissing || '');
		} else if (!d.home) {
			msg = this.t.noHome || '';
		}
		this.empty.hidden = (msg === '');
		this.empty.innerHTML = msg;
	};

	TSMap.prototype.touchDot = function (e, live) {
		if (!e.p || !e.id) {
			return null;
		}
		var d = this.dots[e.id];
		if (!d) {
			d = this.dots[e.id] = {id: e.id, ip: e.ip, cc: e.cc, a: e.a, n: 0, last: 0, hit: 0, p: e.p};
		}
		d.n++;
		d.a = BLOCKS[e.a] ? e.a : (BLOCKS[d.a] ? d.a : e.a);
		d.last = e.t * 1000;
		if (live) {
			d.hit = performance.now();
		}
		return d;
	};

	/* --------------------------------------------------------- animation */

	TSMap.prototype.spawn = function (e) {
		var now = performance.now();
		this.touchDot(e, true);
		var anim = this.o.animations === 'full' && !reducedMotion();
		var col = BLOCKS[e.a] ? this.c.block : (e.a === 'dns_block' ? this.c.dns : (e.a === 'dns_allow' ? this.c.out : this.c.pass));
		if (e.a === 'dns_block') {
			if (this.home) {
				this.rings.push({x: this.home[0], y: this.home[1], t0: now, dur: anim ? 1100 : 600, col: col, r: 22});
			}
			return;
		}
		if (!e.p || !this.home) {
			return;
		}
		var src = this.xy(e.p[0], e.p[1]), dst = this.home;
		if (e.a === 'dns_allow') {
			var tmp = src;
			src = dst;
			dst = tmp;
		}
		if (this.particles.length >= this.o.maxArcs) {
			this.particles.shift();
		}
		var dx = dst[0] - src[0], dy = dst[1] - src[1], dist = Math.sqrt(dx * dx + dy * dy);
		var lift = Math.min(160, dist * 0.32);
		this.particles.push({
			x0: src[0], y0: src[1], x1: dst[0], y1: dst[1],
			cx: (src[0] + dst[0]) / 2 + (dy / (dist || 1)) * lift * (dx > 0 ? -1 : 1) * 0.25, cy: (src[1] + dst[1]) / 2 - lift,
			t0: now, dur: anim ? 900 + Math.min(900, dist * 2.2) : 1, col: col, block: !!BLOCKS[e.a], static: !anim
		});
	};

	function bez(p, t) {
		var u = 1 - t;
		return [u * u * p.x0 + 2 * u * t * p.cx + t * t * p.x1, u * u * p.y0 + 2 * u * t * p.cy + t * t * p.y1];
	}

	TSMap.prototype.loop = function (ts) {
		global.requestAnimationFrame(this.loop);
		if (document.hidden || this.o.animations === 'off' || this.paused) {
			return;
		}
		if (ts - this.lastFrame < 1000 / this.fps) {
			return;
		}
		this.lastFrame = ts;
		while (this.queue.length && this.queue[0].at <= ts) {
			this.spawn(this.queue.shift().e);
		}
		this.drawFx(ts);
	};

	TSMap.prototype.drawFx = function (now) {
		var ctx = this.fx.getContext('2d'), v = this.view, c = this.c, self = this;
		ctx.setTransform(DPR, 0, 0, DPR, 0, 0);
		ctx.clearRect(0, 0, v.w, v.h);
		var anim = this.o.animations !== 'off' && !this.paused && !reducedMotion();
		var wall = Date.now();
		var winMs = {'15m': 9e5, '1h': 36e5, '6h': 216e5, '24h': 864e5, '7d': 6048e5}[this.o.window] || 36e5;
		var glow = c.glow;

		/* source dots: size by hits, fade with age, blink on a new hit */
		var scale = Math.max(0.7, v.s * 1.1);
		Object.keys(this.dots).forEach(function (id) {
			var d = self.dots[id];
			var p = self.xy(d.p[0], d.p[1]);
			var age = Math.max(0, wall - d.last);
			var alpha = Math.max(0.25, 1 - age / winMs);
			var col = BLOCKS[d.a] ? c.block : (d.a === 'dns_allow' ? c.out : c.pass);
			var r = (1.6 + Math.min(5, Math.log(1 + d.n) * 1.1)) * scale;
			var since = now - d.hit;
			if (anim && since < 1400) {
				var k = since / 1400;
				ctx.beginPath();
				ctx.arc(p[0], p[1], r + 14 * k * scale, 0, 6.2832);
				ctx.fillStyle = rgba(col, 0.35 * (1 - k));
				ctx.fill();
				r *= 1 + 0.6 * (1 - k);
			} else if (anim && age < 60000) {
				/* recently active dots keep breathing */
				r *= 1 + 0.12 * Math.sin(now / 300 + d.n);
			}
			if (glow > 0) {
				ctx.shadowColor = rgba(col, 0.9);
				ctx.shadowBlur = 8 * glow;
			}
			ctx.beginPath();
			ctx.arc(p[0], p[1], r, 0, 6.2832);
			ctx.fillStyle = rgba(col, alpha);
			ctx.fill();
			ctx.shadowBlur = 0;
		});

		/* arcs */
		var keep = [];
		this.particles.forEach(function (p) {
			var t = (now - p.t0) / p.dur;
			if (p.static) {
				/* reduced motion: a faint line that fades out */
				var f = (now - p.t0) / 2500;
				if (f >= 1) {
					return;
				}
				ctx.beginPath();
				ctx.moveTo(p.x0, p.y0);
				ctx.quadraticCurveTo(p.cx, p.cy, p.x1, p.y1);
				ctx.strokeStyle = rgba(p.col, 0.5 * (1 - f));
				ctx.lineWidth = 1;
				ctx.stroke();
				keep.push(p);
				return;
			}
			var end = p.block ? 0.93 : 1;
			if (t >= end) {
				var hit = bez(p, end);
				self.rings.push({x: hit[0], y: hit[1], t0: now, dur: 700, col: p.col, r: p.block ? 16 : 10, burst: p.block});
				return;
			}
			var tail = Math.max(0, t - 0.28), n = 14;
			for (var i = 0; i < n; i++) {
				var a = tail + (t - tail) * i / n, b = tail + (t - tail) * (i + 1) / n;
				var pa = bez(p, a), pb = bez(p, b);
				ctx.beginPath();
				ctx.moveTo(pa[0], pa[1]);
				ctx.lineTo(pb[0], pb[1]);
				ctx.strokeStyle = rgba(p.col, 0.9 * (i + 1) / n);
				ctx.lineWidth = 0.6 + 1.6 * (i + 1) / n;
				ctx.stroke();
			}
			var head = bez(p, t);
			if (glow > 0) {
				ctx.shadowColor = rgba(p.col, 1);
				ctx.shadowBlur = 12 * glow;
			}
			ctx.beginPath();
			ctx.arc(head[0], head[1], 2.4, 0, 6.2832);
			ctx.fillStyle = rgba(p.col, 1);
			ctx.fill();
			ctx.shadowBlur = 0;
			keep.push(p);
		});
		this.particles = keep;

		/* impacts and DNS pulses */
		this.rings = this.rings.filter(function (r) {
			var k = (now - r.t0) / r.dur;
			if (k >= 1) {
				return false;
			}
			ctx.beginPath();
			ctx.arc(r.x, r.y, 2 + r.r * k, 0, 6.2832);
			ctx.strokeStyle = rgba(r.col, 0.9 * (1 - k));
			ctx.lineWidth = r.burst ? 2 : 1.5;
			ctx.stroke();
			if (r.burst) {
				for (var i = 0; i < 6; i++) {
					var ang = i * 1.0472 + r.t0;
					ctx.beginPath();
					ctx.moveTo(r.x + Math.cos(ang) * r.r * k * 0.6, r.y + Math.sin(ang) * r.r * k * 0.6);
					ctx.lineTo(r.x + Math.cos(ang) * r.r * k * 1.1, r.y + Math.sin(ang) * r.r * k * 1.1);
					ctx.strokeStyle = rgba(r.col, 0.7 * (1 - k));
					ctx.stroke();
				}
			}
			return true;
		});

		/* home: the firewall */
		if (this.home) {
			var h = this.home, hr = Math.max(5, 7 * v.s);
			if (c.radar && anim) {
				var ang = (now / 1600) % 6.2832, R = 80 * v.s + 30;
				var g = ctx.createRadialGradient(h[0], h[1], 0, h[0], h[1], R);
				g.addColorStop(0, rgba(c.home, 0.25));
				g.addColorStop(1, rgba(c.home, 0));
				ctx.beginPath();
				ctx.moveTo(h[0], h[1]);
				ctx.arc(h[0], h[1], R, ang - 0.6, ang);
				ctx.closePath();
				ctx.fillStyle = g;
				ctx.fill();
				ctx.beginPath();
				ctx.arc(h[0], h[1], R, 0, 6.2832);
				ctx.strokeStyle = rgba(c.home, 0.25);
				ctx.lineWidth = 1;
				ctx.stroke();
			}
			var pulse = anim ? (now % 2400) / 2400 : 0;
			ctx.beginPath();
			ctx.arc(h[0], h[1], hr + 10 * pulse, 0, 6.2832);
			ctx.strokeStyle = rgba(c.home, 0.6 * (1 - pulse));
			ctx.lineWidth = 2;
			ctx.stroke();
			if (glow > 0) {
				ctx.shadowColor = rgba(c.home, 1);
				ctx.shadowBlur = 14 * glow;
			}
			/* shield */
			ctx.beginPath();
			ctx.moveTo(h[0], h[1] - hr);
			ctx.quadraticCurveTo(h[0] + hr, h[1] - hr, h[0] + hr * 0.9, h[1] - hr * 0.2);
			ctx.quadraticCurveTo(h[0] + hr * 0.7, h[1] + hr * 0.7, h[0], h[1] + hr);
			ctx.quadraticCurveTo(h[0] - hr * 0.7, h[1] + hr * 0.7, h[0] - hr * 0.9, h[1] - hr * 0.2);
			ctx.quadraticCurveTo(h[0] - hr, h[1] - hr, h[0], h[1] - hr);
			ctx.fillStyle = rgba(c.home, 1);
			ctx.fill();
			ctx.shadowBlur = 0;
		}
	};

	/* ------------------------------------------------------ interaction */

	TSMap.prototype.pick = function (e) {
		var rect = this.fx.getBoundingClientRect(), x = e.clientX - rect.left, y = e.clientY - rect.top;
		var best = null, bd = 12 * 12, self = this;
		Object.keys(this.dots).forEach(function (id) {
			var d = self.dots[id], p = self.xy(d.p[0], d.p[1]);
			var dd = (p[0] - x) * (p[0] - x) + (p[1] - y) * (p[1] - y);
			if (dd < bd) {
				bd = dd;
				best = d;
			}
		});
		return best;
	};

	TSMap.prototype.hover = function (e) {
		var d = this.pick(e);
		this.fx.style.cursor = d ? 'pointer' : '';
		if (!d) {
			this.tip.hidden = true;
			return;
		}
		var rect = this.root.getBoundingClientRect();
		var name = (W.n[d.cc] || d.cc);
		this.tip.innerHTML = '<strong class="fs-mono">' + esc(d.ip) + '</strong><span>' + esc(name) + '</span><span>' +
			esc((this.t.hits || '%d connections').replace('%d', fmt(d.n))) + ' · ' + esc(clock(d.last / 1000)) + '</span>';
		this.tip.hidden = false;
		var x = e.clientX - rect.left + 14, y = e.clientY - rect.top + 14;
		if (x + 220 > rect.width) {
			x -= 240;
		}
		this.tip.style.transform = 'translate(' + x + 'px,' + y + 'px)';
	};

	TSMap.prototype.select = function (d) {
		var self = this, body = this.drawer.querySelector('.tsm-drawer-body');
		this.tip.hidden = true;
		if (this.o.mode === 'widget') {
			global.location.href = '/threatshield/threatshield_map.php';
			return;
		}
		body.innerHTML = '<p class="fs-muted">' + esc(this.t.loading || 'Loading…') + '</p>';
		this.drawer.hidden = false;
		var q = this.o.mask ? 'id=' + encodeURIComponent(d.id) + '&mask=1' : 'ip=' + encodeURIComponent(d.ip);
		fetch(this.o.data + '?what=ip&' + q, {credentials: 'same-origin'}).then(function (r) {
			return r.text();
		}).then(function (html) {
			body.innerHTML = html;
			self.wireCard(body);
		});
	};

	TSMap.prototype.openIp = function (ip, id) {
		this.select({ip: ip, id: id || '', cc: ''});
	};

	TSMap.prototype.closeDrawer = function () {
		this.drawer.hidden = true;
	};

	TSMap.prototype.wireCard = function (body) {
		var self = this, card = body.querySelector('.tsm-card');
		if (!card) {
			return;
		}
		var ip = card.getAttribute('data-ip');
		var look = body.querySelector('[data-tsm-lookup]');
		if (look) {
			look.addEventListener('click', function () {
				look.disabled = true;
				fetch(self.o.data + '?what=ptr&ip=' + encodeURIComponent(ip), {credentials: 'same-origin'}).then(function (r) {
					return r.json();
				}).then(function (j) {
					look.parentNode.textContent = j.ptr || (self.t.noPtr || 'No host name');
				});
			});
		}
		body.querySelectorAll('[data-tsm-act]').forEach(function (btn) {
			btn.addEventListener('click', function () {
				var fd = new FormData();
				fd.append('act', btn.getAttribute('data-tsm-act'));
				fd.append('ip', ip);
				if (global.csrfMagicName && global.csrfMagicToken) {
					fd.append(global.csrfMagicName, global.csrfMagicToken);
				}
				btn.disabled = true;
				fetch(self.o.data, {method: 'POST', body: fd, credentials: 'same-origin'}).then(function (r) {
					return r.json();
				}).then(function (j) {
					var note = document.createElement('p');
					note.className = 'tsm-note ' + (j.ok ? 'is-ok' : 'is-error');
					note.textContent = j.message || '';
					card.appendChild(note);
				}).catch(function () {
					btn.disabled = false;
				});
			});
		});
	};

	/* ----------------------------------------------------------- replay */

	TSMap.prototype.replay = function (seconds, speed, done) {
		var self = this, to = Math.floor(Date.now() / 1000), from = to - seconds;
		fetch(this.o.data + '?what=replay&from=' + from + '&to=' + to + (this.o.mask ? '&mask=1' : ''), {credentials: 'same-origin'}).then(function (r) {
			return r.json();
		}).then(function (j) {
			var evs = j.events || [];
			if (!evs.length) {
				if (done) {
					done(0);
				}
				return;
			}
			self.replaying = true;
			self.dots = {};
			var start = performance.now(), t0 = evs[0].t;
			self.queue = evs.map(function (e) {
				return {at: start + (e.t - t0) * 1000 / speed, e: e};
			});
			var total = (evs[evs.length - 1].t - t0) * 1000 / speed + 1500;
			setTimeout(function () {
				self.replaying = false;
				self.cursor = 0;
				self.poll(true);
				if (done) {
					done(evs.length);
				}
			}, total);
		});
	};

	/* ================================================================ TSPanels */

	function TSPanels(root, map, opts) {
		var self = this;
		this.root = root;
		this.map = map;
		this.o = Object.assign({panels: [], alerts: {on: true, factor: 4, sound: false}, t: {}}, opts || {});
		this.t = this.o.t;
		this.shown = {};
		this.feedRows = 0;
		this.spot = 0;
		this.alerted = 0;
		map.on(function (d, first) {
			self.render(d, first);
		});
		setInterval(function () {
			self.rotateSpot();
		}, 8000);
	}

	TSPanels.prototype.el = function (name) {
		return this.root.querySelector('[data-tsm-panel="' + name + '"]');
	};

	TSPanels.prototype.render = function (d, first) {
		if (d.error) {
			var off = this.el('status');
			this.root.classList.toggle('is-signed-out', d.error === 'signed-out');
			if (off) {
				off.setAttribute('data-state', 'offline');
			}
			return;
		}
		this.data = d;
		this.kpis(d);
		this.mix(d);
		this.timeline(d);
		this.list('countries', (d.top.countries || []).map(function (r) {
			return {label: r.name, sub: r.cc, n: r.n, cc: r.cc};
		}));
		this.list('sources', (d.top.ips || []).map(function (r) {
			return {label: r.ip, sub: [r.cc, r.org].filter(Boolean).join(' · '), n: r.n, ip: r.ip, id: r.id, mono: true};
		}));
		this.list('asns', (d.top.asns || []).map(function (r) {
			return {label: r.org || ('AS' + r.asn), sub: 'AS' + r.asn, n: r.n};
		}));
		this.list('ports', (d.top.ports || []).map(function (r) {
			return {label: r.proto.toUpperCase() + ' ' + r.port, sub: r.service, n: r.n, mono: true};
		}));
		this.list('rules', (d.top.rules || []).map(function (r) {
			return {label: r.rule, n: r.n};
		}));
		this.list('domains', (d.top.domains || []).map(function (r) {
			return {label: r.dom, n: r.n, mono: true};
		}));
		this.feed(d.events || [], first);
		this.status(d);
		this.alerts(d);
		if (first) {
			this.rotateSpot(true);
		}
	};

	TSPanels.prototype.countUp = function (el, value) {
		var from = +(el.getAttribute('data-v') || 0), to = +value || 0;
		el.setAttribute('data-v', to);
		if (from === to || reducedMotion()) {
			el.textContent = fmt(to);
			return;
		}
		var t0 = performance.now();
		function step(ts) {
			var k = Math.min(1, (ts - t0) / 700);
			el.textContent = fmt(Math.round(from + (to - from) * (1 - Math.pow(1 - k, 3))));
			if (k < 1) {
				global.requestAnimationFrame(step);
			}
		}
		global.requestAnimationFrame(step);
	};

	TSPanels.prototype.kpis = function (d) {
		var box = this.el('kpis');
		if (!box) {
			return;
		}
		var c = d.counters || {}, self = this;
		var vals = {block: (c.block || 0) + (c.listed || 0), pass: (c.pass || 0) + (c.clean || 0), dns: c.dns_block || 0, sources: c.sources || 0};
		/* events per second over the last two buckets */
		var r = d.rate || [], last = r[r.length - 2] || r[r.length - 1];
		vals.rate = last ? ((last.block + last.pass + last.dns) / (d.bucket || 60)).toFixed(1) : '0';
		box.querySelectorAll('[data-k]').forEach(function (el) {
			var k = el.getAttribute('data-k');
			if (k === 'rate') {
				el.textContent = vals.rate;
			} else {
				self.countUp(el, vals[k]);
			}
		});
	};

	TSPanels.prototype.mix = function (d) {
		var box = this.el('mix');
		if (!box) {
			return;
		}
		var names = this.t.kinds || {}, rows = [], total = 0;
		Object.keys(d.mix || {}).forEach(function (k) {
			rows.push([k, d.mix[k]]);
			total += d.mix[k];
		});
		rows.sort(function (a, b) {
			return b[1] - a[1];
		});
		var donut = box.querySelector('.tsm-donut'), legend = box.querySelector('.tsm-legend-list');
		if (!total) {
			donut.style.background = '';
			legend.innerHTML = '<li class="fs-muted">' + esc(this.t.nothing || 'Nothing yet') + '</li>';
			return;
		}
		var stops = [], at = 0;
		rows.forEach(function (r, i) {
			var col = 'var(--fs-series-' + ((KIND_KEYS.indexOf(r[0]) % 8) + 1) + ')';
			var to = at + r[1] / total * 100;
			stops.push(col + ' ' + at.toFixed(2) + '% ' + to.toFixed(2) + '%');
			at = to;
			r.push(col);
		});
		donut.style.background = 'conic-gradient(' + stops.join(',') + ')';
		donut.querySelector('span').textContent = fmt(total);
		legend.innerHTML = rows.slice(0, 7).map(function (r) {
			return '<li><i style="background:' + r[2] + '"></i><span>' + esc(names[r[0]] || r[0]) + '</span><b>' + Math.round(r[1] / total * 100) + '%</b></li>';
		}).join('');
	};

	TSPanels.prototype.timeline = function (d) {
		var box = this.el('timeline');
		if (!box) {
			return;
		}
		var cv = box.querySelector('canvas'), rect = cv.getBoundingClientRect();
		var w = Math.max(100, rect.width), h = Math.max(40, rect.height);
		cv.width = w * DPR;
		cv.height = h * DPR;
		var ctx = cv.getContext('2d');
		ctx.setTransform(DPR, 0, 0, DPR, 0, 0);
		ctx.clearRect(0, 0, w, h);
		var rows = d.rate || [], max = 1;
		rows.forEach(function (r) {
			max = Math.max(max, r.block + r.pass + r.dns);
		});
		var bw = w / Math.max(1, rows.length), m = this.map.c;
		rows.forEach(function (r, i) {
			var y = h;
			[['block', m.block], ['dns', m.dns], ['pass', m.pass]].forEach(function (s) {
				var bh = r[s[0]] / max * (h - 4);
				if (bh > 0) {
					ctx.fillStyle = rgba(s[1], 0.85);
					ctx.fillRect(i * bw + 1, y - bh, Math.max(1, bw - 2), bh);
					y -= bh;
				}
			});
		});
		var peak = box.querySelector('[data-k="peak"]');
		if (peak) {
			peak.textContent = fmt(max);
		}
	};

	TSPanels.prototype.list = function (name, rows) {
		var box = this.el(name);
		if (!box) {
			return;
		}
		var ul = box.querySelector('ul'), max = 0, self = this;
		rows.forEach(function (r) {
			max = Math.max(max, r.n);
		});
		if (!rows.length) {
			ul.innerHTML = '<li class="tsm-none">' + esc(this.t.nothing || 'Nothing yet') + '</li>';
			return;
		}
		ul.innerHTML = rows.slice(0, +(box.getAttribute('data-rows') || 8)).map(function (r) {
			var flag = r.cc ? '<span class="tsm-cc">' + esc(r.cc) + '</span>' : '';
			return '<li' + (r.ip ? ' data-ip="' + esc(r.ip) + '" data-id="' + esc(r.id || '') + '" tabindex="0" role="button"' : '') + '>' +
				'<span class="tsm-row-label' + (r.mono ? ' fs-mono' : '') + '">' + (name === 'countries' ? flag : '') + esc(r.label) +
				(r.sub && name !== 'countries' ? '<small>' + esc(r.sub) + '</small>' : '') + '</span>' +
				'<b>' + fmt(r.n) + '</b><span class="tsm-bar"><i style="width:' + Math.max(2, Math.round(r.n / max * 100)) + '%"></i></span></li>';
		}).join('');
		ul.querySelectorAll('[data-ip]').forEach(function (li) {
			var open = function () {
				self.map.openIp(li.getAttribute('data-ip'), li.getAttribute('data-id'));
			};
			li.addEventListener('click', open);
			li.addEventListener('keydown', function (e) {
				if (e.key === 'Enter') {
					open();
				}
			});
		});
	};

	TSPanels.prototype.feed = function (events, first) {
		var box = this.el('feed');
		if (!box || !events.length) {
			return;
		}
		var list = box.querySelector('.tsm-feed-list'), self = this, hacker = this.map.o.style === 'hacker';
		var kinds = this.t.kinds || {};
		var html = events.slice(-30).reverse().map(function (e) {
			var blocked = BLOCKS[e.a] || e.a === 'dns_block';
			var what = e.dom ? e.dom : (e.ip || '');
			var where = e.port ? (e.proto ? e.proto.toUpperCase() + ' ' : '') + e.port : '';
			if (hacker) {
				return '<li class="' + (blocked ? 'is-block' : 'is-pass') + (first ? '' : ' is-new') + '"' + (e.ip ? ' data-ip="' + esc(e.ip) + '" data-id="' + esc(e.id) + '"' : '') +
					'><code>[' + clock(e.t) + '] ' + (blocked ? 'DROP' : 'PASS') + ' ' + esc(what) + (where ? ' → :' + esc(e.port) : '') +
					' ' + esc((kinds[e.k] || e.k).toUpperCase()) + (e.cc ? ' ' + esc(e.cc) : '') + '</code></li>';
			}
			return '<li class="' + (blocked ? 'is-block' : 'is-pass') + (first ? '' : ' is-new') + '"' + (e.ip ? ' data-ip="' + esc(e.ip) + '" data-id="' + esc(e.id) + '"' : '') + '>' +
				'<span class="tsm-feed-time fs-mono">' + clock(e.t) + '</span>' +
				'<span class="tsm-feed-act">' + esc(blocked ? (self.t.blocked || 'Blocked') : (self.t.allowed || 'Allowed')) + '</span>' +
				'<span class="tsm-feed-what' + (e.dom ? '' : ' fs-mono') + '">' + esc(what) + (e.cc ? ' <span class="tsm-cc">' + esc(e.cc) + '</span>' : '') + '</span>' +
				'<span class="tsm-feed-why">' + esc(kinds[e.k] || e.k) + (where ? ' · ' + esc(where) : '') + '</span></li>';
		}).join('');
		list.insertAdjacentHTML('afterbegin', html);
		while (list.children.length > (hacker ? 60 : 40)) {
			list.removeChild(list.lastChild);
		}
		list.querySelectorAll('li.is-new').forEach(function (li) {
			setTimeout(function () {
				li.classList.remove('is-new');
			}, 50);
		});
		list.querySelectorAll('[data-ip]:not([data-wired])').forEach(function (li) {
			li.setAttribute('data-wired', '1');
			li.addEventListener('click', function () {
				self.map.openIp(li.getAttribute('data-ip'), li.getAttribute('data-id'));
			});
		});
	};

	TSPanels.prototype.rotateSpot = function (reset) {
		var box = this.el('spotlight');
		if (!box || !this.data) {
			return;
		}
		var ips = (this.data.top && this.data.top.ips) || [];
		if (!ips.length) {
			box.querySelector('.tsm-spot-body').innerHTML = '<p class="tsm-none">' + esc(this.t.nothing || 'Nothing yet') + '</p>';
			return;
		}
		this.spot = reset ? 0 : (this.spot + 1) % Math.min(5, ips.length);
		var r = ips[this.spot], name = W.n[r.cc] || r.cc || '';
		box.querySelector('.tsm-spot-body').innerHTML =
			'<div class="tsm-spot-rank">#' + (this.spot + 1) + '</div>' +
			'<div class="tsm-spot-ip fs-mono">' + esc(r.ip) + '</div>' +
			'<div class="tsm-spot-where">' + (r.cc ? '<span class="tsm-cc">' + esc(r.cc) + '</span> ' : '') + esc(name) + '</div>' +
			'<div class="tsm-spot-org">' + esc(r.org || (r.asn ? 'AS' + r.asn : '')) + '</div>' +
			'<div class="tsm-spot-n"><b>' + fmt(r.n) + '</b> ' + esc(this.t.blockedConn || 'blocked connections') + '</div>';
		box.onclick = function () {
			this.map.openIp(r.ip, r.id);
		}.bind(this);
	};

	TSPanels.prototype.status = function (d) {
		var box = this.el('status');
		if (!box || !d.status) {
			return;
		}
		var s = d.status, t = this.t, items = [];
		items.push([s.running ? (s.paused ? 'warn' : 'ok') : 'fail', s.running ? (s.paused ? (t.paused || 'Paused') : (t.protecting || 'Protecting')) : (t.stopped || 'Stopped')]);
		items.push([s.health === 'ok' ? 'ok' : (s.health === 'fail' ? 'fail' : 'warn'), (t.health || 'Health') + ': ' + (t['h_' + s.health] || s.health)]);
		if (d.sources && d.sources.dnsbl === 'ok') {
			items.push([s.breaker === 'open' ? 'fail' : 'ok', (t.reputation || 'Reputation') + ': ' + (s.breaker === 'open' ? (t.failing || 'failing') : (t.working || 'working'))]);
		}
		items.push([s.flood ? 'warn' : 'ok', (t.flood || 'Flood offenders') + ': ' + s.flood]);
		box.setAttribute('data-state', 'online');
		box.querySelector('ul').innerHTML = items.map(function (i) {
			return '<li class="is-' + i[0] + '"><i></i>' + esc(i[1]) + '</li>';
		}).join('');
	};

	/* a spike: the last full bucket far above the usual level */
	TSPanels.prototype.alerts = function (d) {
		var box = this.el('alert');
		if (!box || !this.o.alerts.on) {
			return;
		}
		var r = (d.rate || []).map(function (x) {
			return x.block;
		});
		if (r.length < 6) {
			return;
		}
		var last = r[r.length - 2], prev = r.slice(0, r.length - 2).slice().sort(function (a, b) {
			return a - b;
		});
		var median = prev[Math.floor(prev.length / 2)] || 0;
		var history = prev.filter(function (x) {
			return x > 0;
		}).length;
		var msg = '';
		if (history >= Math.min(10, prev.length / 2) && last >= 20 && last > this.o.alerts.factor * Math.max(1, median)) {
			msg = (this.t.spike || 'Spike: %1 blocked in one interval, %2× the usual level').replace('%1', fmt(last)).replace('%2', Math.round(last / Math.max(1, median)));
		} else if (d.status && d.status.breaker === 'open') {
			msg = this.t.breakerOpen || 'Reputation lookups are failing';
		}
		box.hidden = (msg === '');
		box.querySelector('span').textContent = msg;
		if (msg && this.o.alerts.sound && Date.now() - this.alerted > 60000) {
			this.alerted = Date.now();
			try {
				var ac = new (global.AudioContext || global.webkitAudioContext)(), o = ac.createOscillator(), g = ac.createGain();
				o.frequency.value = 880;
				g.gain.value = 0.05;
				o.connect(g).connect(ac.destination);
				o.start();
				o.stop(ac.currentTime + 0.25);
			} catch (e) { /* no audio */ }
		}
	};

	global.TSMap = TSMap;
	global.TSPanels = TSPanels;
})(window);
