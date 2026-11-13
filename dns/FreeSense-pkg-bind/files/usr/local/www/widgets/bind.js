/*
 * bind.js — dashboard widget "BIND" (FreeSense-pkg-bind)
 *
 * part of FreeSense (https://www.freesense.org)
 * Copyright (c) 2026 The FreeSense Project
 * Licensed under the Apache License, Version 2.0.
 *
 * Data: GET /api/v1/packages/bind/status (bind.inc, plugin_restapi).
 */
(function ($, FS, D) {
	'use strict';

	var T = FS.t, el = D.el;

	D.define('bind', {
		mount: function (w) { w.$body.append(el('div', 'fs-nic-tags mb-2'), el('dl', 'fs-kv')); },
		load: function (w) {
			return FS.api.get('/packages/bind/status').then(function (r) {
				var d = r.data;
				w.$body.find('.fs-nic-tags').empty().append(d.running ? D.tag(T('Running'), 'ok', 'fa-circle-check') : D.tag(T('Stopped'), 'bad'));
				var $kv = w.$body.find('.fs-kv').empty();
				if (!d.status.length) {
					$kv.append(D.empty('fa-server', T('BIND does not report a status.')));
					return;
				}
				d.status.forEach(function (s) { $kv.append(el('div', '').append(el('dt', '', s.key), el('dd', '', s.value))); });
			});
		}
	});
})(jQuery, window.FS, window.FSDashboard);
