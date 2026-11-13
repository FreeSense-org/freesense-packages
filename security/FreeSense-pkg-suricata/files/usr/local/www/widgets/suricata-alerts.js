/*
 * suricata-alerts.js — dashboard widget "Suricata alerts" (FreeSense-pkg-suricata)
 *
 * part of FreeSense (https://www.freesense.org)
 * Copyright (c) 2026 The FreeSense Project
 * Licensed under the Apache License, Version 2.0.
 *
 * Data: GET /api/v1/packages/suricata/alerts?limit= (suricata.inc, plugin_restapi).
 */
(function ($, FS, D) {
	'use strict';

	var T = FS.t, el = D.el;

	function hp(host, port) {
		if (!host) return '';
		var h = (host.indexOf(':') >= 0) ? '[' + host + ']' : host;
		return port !== '' ? h + ':' + port : h;
	}

	D.define('suricata-alerts', {
		mount: function (w) { w.$body.append(el('ul', 'fs-wlist fs-sur-list')); },
		load: function (w) {
			return FS.api.get('/packages/suricata/alerts', { limit: +w.settings.rows || 8 }).then(function (r) {
				var $l = w.$body.find('.fs-sur-list').empty();
				if (!r.data.length) {
					$l.append(el('li', '').append(D.empty('fa-shield-halved', T('No alerts.'))));
					return;
				}
				r.data.forEach(function (a) {
					var kind = a.priority <= 1 ? 'bad' : (a.priority === 2 ? 'warn' : '');
					var $li = el('li', 'fs-notice');
					$li.append($('<i class="fa-solid fa-triangle-exclamation" aria-hidden="true"></i>').addClass(kind === 'bad' ? 'text-danger' : (kind === 'warn' ? 'text-warning' : 'fs-muted')));
					var where = a.src ? hp(a.src, a.sport) + ' → ' + hp(a.dst, a.dport) : T('Decoder event');
					$li.append(el('div', '').append(el('strong', '', a.msg), el('p', 'fs-mono small', where),
						el('small', '', [new Date(a.time * 1000).toLocaleString(), a.interface_descr, a.class].filter(Boolean).join(' · '))));
					$li.append(D.tag(T('Priority %s', a.priority), kind));
					$l.append($li);
				});
			});
		}
	});
})(jQuery, window.FS, window.FSDashboard);
