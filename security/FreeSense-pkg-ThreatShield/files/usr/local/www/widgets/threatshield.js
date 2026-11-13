/*
 * threatshield.js — dashboard widget "Threat Shield" (FreeSense-pkg-ThreatShield)
 *
 * part of FreeSense (https://www.freesense.org)
 * Copyright (c) 2026 The FreeSense Project
 * Licensed under the Apache License, Version 2.0.
 *
 * Data: GET /api/v1/packages/threatshield/status (threatshield.inc, plugin_restapi).
 */
(function ($, FS, D) {
	'use strict';

	var T = FS.t, F = FS.fmt, el = D.el;
	var STATE = { off: ['Off', ''], stopped: ['Stopped', 'bad'], paused: ['Paused', 'warn'], fail: ['Needs attention', 'bad'], warn: ['Check', 'warn'], ok: ['Protecting', 'ok'] };

	function row($kv, label, value, extra) {
		var $dd = el('dd', '', value);
		if (extra) $dd.append(' ', extra);
		$kv.append(el('div', '').append(el('dt', '', label), $dd));
	}

	D.define('threatshield', {
		mount: function (w) {
			w.$body.append(el('div', 'fs-nic-tags mb-2'), el('ul', 'fs-wlist fs-ts-problems'), el('dl', 'fs-kv'));
			var $links = el('div', 'fs-nicd-links');
			$links.append($('<a class="btn btn-sm btn-outline-secondary" href="/threatshield/threatshield_status.php"></a>').text(T('Overview')));
			$links.append($('<a class="btn btn-sm btn-outline-secondary" href="/threatshield/threatshield_querylog.php"></a>').text(T('Query log')));
			w.$body.append($links);
		},
		load: function (w) {
			return FS.api.get('/packages/threatshield/status').then(function (r) {
				var d = r.data, st = STATE[d.state] || STATE.off;
				var label = (d.state === 'paused' && d.paused_until) ? T('Paused until %s', new Date(d.paused_until * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })) : T(st[0]);
				w.$body.find('.fs-nic-tags').empty().append(D.tag(label, st[1], d.state === 'ok' ? 'fa-shield-halved' : null));
				var $p = w.$body.find('.fs-ts-problems').empty();
				d.problems.forEach(function (c) {
					$p.append(el('li', 'fs-svc').append(D.dot(c.state === 'fail' ? 'down' : 'warn'), el('div', '').append(el('strong', '', c.label), el('small', '', c.detail)), el('span', '')));
				});
				var $kv = w.$body.find('.fs-kv').empty();
				row($kv, T('DNS queries (24 h)'), F.num(d.dns_queries));
				row($kv, T('Blocked'), F.num(d.dns_blocked) + ' (' + d.dns_blocked_pct + '%)');
				row($kv, T('GeoIP'), d.geoip_countries ? T('%s countries', d.geoip_countries) : T('Off'));
				if (d.reputation) row($kv, T('Reputation'), T('%s sources blocked', F.num(d.reputation.listed)), d.reputation.failing ? D.tag(T('Lookups failing'), 'warn') : null);
				if (d.flood) row($kv, T('Flood offenders'), F.num(d.flood));
			});
		}
	});
})(jQuery, window.FS, window.FSDashboard);
