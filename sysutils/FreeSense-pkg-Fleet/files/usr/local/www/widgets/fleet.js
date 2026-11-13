/*
 * fleet.js — dashboard widget "FreeSense Fleet" (FreeSense-pkg-Fleet)
 *
 * part of FreeSense (https://www.freesense.org)
 * Copyright (c) 2026 The FreeSense Project
 * Licensed under the Apache License, Version 2.0.
 *
 * Health tiles, the firewalls that need attention, availability over 24
 * hours and the controller with its standby; each part can be turned off
 * and the widget can focus on one group.
 * Data: GET /api/v1/packages/fleet/widget (fleet_widget.inc, plugin_restapi).
 * Styles: /fleet/assets/fleet.css (fs-fleet-widget-*).
 */
(function ($, FS, D) {
	'use strict';

	var T = FS.t, el = D.el;
	var PARTS = ['health', 'problems', 'availability', 'controller'];
	var groups = [];
	var cssLoaded = false;

	function link(href, cls) { return $('<a></a>').attr('href', href).addClass(cls || ''); }
	function icon(name) { return $('<i class="fa-solid" aria-hidden="true"></i>').addClass(name); }
	function hhmm(t) { return new Date(t * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', hour12: false }); }
	/* The fs_badge() states of the old widget as dashboard tags. */
	function badge(state, text) { return D.tag(text, { pass: 'ok', block: 'bad', warn: 'warn', info: 'info' }[state] || ''); }

	function pulse(p) {
		var n = p.cols.length, max = 1, w = 4, h = 40;
		p.cols.forEach(function (c) { max = Math.max(max, c[0] + c[1] + c[2]); });
		var svg = '<svg class="fs-fleet-widget-pulse" viewBox="0 0 ' + (n * w) + ' ' + h + '" preserveAspectRatio="none" role="img" aria-label="' +
			FS.esc(T('Firewalls online, degraded and offline per half hour, last 24 hours')) + '">';
		p.cols.forEach(function (c, i) {
			var y = h;
			['online', 'degraded', 'offline'].forEach(function (cls, k) {
				var bh = h * c[k] / max;
				if (bh > 0) {
					y -= bh;
					svg += '<rect class="s-' + cls + '" x="' + (i * w + 0.5) + '" y="' + y.toFixed(2) + '" width="' + (w - 1) + '" height="' + bh.toFixed(2) + '"><title>' +
						FS.esc(hhmm(p.t[i]) + ': ' + T('%1$s online, %2$s degraded, %3$s offline', c[0], c[1], c[2])) + '</title></rect>';
				}
			});
		});
		return svg + '</svg>';
	}

	function render(w, d) {
		var $b = w.state.$box.empty(), parts = d.parts || PARTS;
		if (!d.ready) {
			var $p = el('p', 'fs-fleet-widget-note');
			if (d.standby) {
				var ok = +(d.standby.last_ok || 0);
				$p.text(T('This server is the Fleet standby.') + ' ' + (ok > 0 ? T('Last copy %s.', FS.fmt.datetime(ok * 1000)) : T('No copy yet.')) + ' ')
					.append(link('/fleet/fleet.php?tab=settings&view=standby').text(T('Standby status')));
			} else {
				$p.text(T('FreeSense Fleet is not set up on this firewall.') + ' ').append(link('/fleet/fleet.php?tab=settings').text(T('Settings')));
			}
			$b.append($p);
			return;
		}
		var c = d.counts || {};
		if (parts.indexOf('health') >= 0) {
			var tone = c.offline > 0 ? 'block' : (c.degraded > 0 ? 'warn' : 'pass');
			var $head = link('/fleet/fleet_dashboard.php', 'fs-fleet-widget-head');
			$head.append(el('span', 'fs-fleet-ov-state fs-fc-' + tone).append(icon(tone === 'pass' ? 'fa-circle-check' : 'fa-triangle-exclamation')));
			var $t = el('span', '').append(el('strong', '', T(d.headline)));
			if (d.group) $t.append(el('span', 'fs-muted', ' ' + T('in %s', d.group)));
			$b.append($head.append($t));
			var wall = '/fleet/fleet_dashboard.php?view=firewalls';
			var tiles = [['fa-server', 'Firewalls', d.total, wall, 'c1'], ['fa-circle-check', 'Online', c.online, wall, 'pass'],
				['fa-triangle-exclamation', 'Degraded', c.degraded, wall, c.degraded > 0 ? 'warn' : 'neutral'],
				['fa-plug-circle-xmark', 'Offline', c.offline, wall, c.offline > 0 ? 'block' : 'neutral'],
				['fa-circle-up', 'Updates', d.updates, '/fleet/fleet_updates.php', d.updates > 0 ? 'info' : 'neutral'],
				['fa-hourglass-half', 'Waiting', c.pending, '/fleet/fleet.php', c.pending > 0 ? 'warn' : 'neutral']];
			var $tiles = el('div', 'fs-fleet-widget-tiles');
			tiles.forEach(function (x) {
				var hot = (+x[2] > 0) && (x[4] === 'warn' || x[4] === 'block');
				$tiles.append(link(x[3], 'fs-fleet-widget-tile fs-fc-' + x[4] + (hot ? ' is-hot' : '')).append(icon(x[0]),
					el('span', 'fs-fleet-widget-n', String(+x[2] || 0)), el('span', 'fs-fleet-widget-l', T(x[1]))));
			});
			$b.append($tiles);
		}
		if (parts.indexOf('problems') >= 0) {
			var $part = el('div', 'fs-fleet-widget-part');
			if (!(d.problems || []).length) {
				$part.append(el('p', 'fs-fleet-widget-ok').append(icon('fa-circle-check'), ' ' +
					(d.total === 0 ? T('No firewalls yet.') : (d.total === 1 ? T('The firewall is fine.') : T('All %s firewalls are fine.', d.total)))));
			} else {
				$part.append(el('h4', 'fs-fleet-widget-sub').append(icon('fa-triangle-exclamation'), document.createTextNode(T('Needs attention'))));
				var $ul = el('ul', 'fs-fleet-widget-list');
				d.problems.forEach(function (p) {
					$ul.append(el('li', '').append(badge(p.badge[0], T(p.badge[1])), link(p.link).text(p.label), el('span', 'fs-fleet-widget-why', T(p.text)).attr('title', T(p.text))));
				});
				$part.append($ul);
				if (d.problem_count > d.problems.length) {
					$part.append(link('/fleet/fleet_dashboard.php', 'fs-fleet-widget-more').text(T('and %s more', d.problem_count - d.problems.length)));
				}
			}
			$b.append($part);
		}
		if (parts.indexOf('availability') >= 0 && d.stats) {
			var pct = (d.stats.percent === null) ? '-' : String(+Number(d.stats.percent).toFixed(2)) + ' %';
			var $av = link('/fleet/fleet_dashboard.php?view=trends', 'fs-fleet-widget-part fs-fleet-widget-avail');
			$av.append(el('span', 'fs-fleet-widget-sub').append(icon('fa-wave-square'), document.createTextNode(T('Last 24 hours')),
				el('span', 'fs-fleet-widget-sum').append(el('strong', '', pct), ' ' + T('available') + ', ' + T(+d.stats.outages === 1 ? '%s outage' : '%s outages', +d.stats.outages))));
			if (d.pulse) $av.append(pulse(d.pulse));
			$av.append(el('span', 'fs-fleet-widget-axis').append(el('span', '', hhmm(d.pulse && d.pulse.t.length ? d.pulse.t[0] : Date.now() / 1000 - 86400)), el('span', '', T('Now'))));
			$b.append($av);
		}
		if (parts.indexOf('controller') >= 0 && d.controller) {
			var $dl = el('dl', 'fs-fleet-widget-part fs-fleet-widget-facts');
			function fact(ic, label, $dd) { $dl.append(el('dt', '').append(icon(ic), document.createTextNode(label)), $dd); }
			fact('fa-tower-broadcast', T('Controller'), el('dd', '', d.controller.version + (d.controller.uptime_text ? ', ' + T('up %s', d.controller.uptime_text) : '')));
			if (d.standby && d.standby.role === 'primary') {
				var $sd = el('dd', '');
				if (d.standby.addr) $sd.append(badge(d.standby_late ? 'warn' : 'pass', d.standby_late ? T('Late') : T('Up to date')), ' ' + d.standby.addr);
				else $sd.append(el('span', 'fs-muted', T('waiting for it to connect')));
				fact('fa-clone', T('Standby'), $sd);
			}
			fact('fa-bell', T('Alerts (24 h)'), el('dd', '').append(link('/fleet/fleet_alerts.php').text(String(+d.alerts || 0))));
			if (d.blocked > 0) fact('fa-ban', T('Blocked'), el('dd', '').append(link('/fleet/fleet.php?tab=settings&view=access&section=allowed').text(T('%s addresses (wrong keys)', d.blocked))));
			$b.append($dl);
		}
		if (!$b.children().length) $b.append(el('p', 'fs-fleet-widget-note', T('Every part is turned off. Open the widget settings to choose what it shows.')));
	}

	D.define('fleet', {
		mount: function (w) {
			if (!cssLoaded) {
				$('<link rel="stylesheet" href="/fleet/assets/fleet.css">').appendTo('head');
				cssLoaded = true;
			}
			w.state.$box = el('div', 'fs-fleet-widget');
			w.$body.append(w.state.$box);
		},
		load: function (w) {
			var parts = PARTS.filter(function (p) { return w.settings[p] !== false; });
			return FS.api.get('/packages/fleet/widget', { parts: parts.join(','), group: w.settings.group || 0, rows: w.settings.rows || 5 }).then(function (r) {
				groups = r.data.groups || [];
				render(w, r.data);
			});
		},
		/* The groups the controller knows, for the Firewalls setting. */
		options: function (w, key) {
			return key === 'group' ? groups.map(function (g) { return [String(g.id), T('Group %s', g.name)]; }) : [];
		}
	});
})(jQuery, window.FS, window.FSDashboard);
