/*
 * haproxy.js — dashboard widget "HAProxy" (FreeSense-pkg-haproxy)
 *
 * part of FreeSense (https://www.freesense.org)
 * Copyright (c) 2026 The FreeSense Project
 * Licensed under the Apache License, Version 2.0.
 *
 * Data: GET /api/v1/packages/haproxy/status; enable or disable a server:
 * POST /packages/haproxy/servers/{backend}/{server}/{action} (haproxy.inc).
 */
(function ($, FS, D) {
	'use strict';

	var T = FS.t, el = D.el;

	function st(s) {
		s = String(s || '').toUpperCase();
		if (s === 'UP' || s === 'OPEN' || s.indexOf('UP ') === 0) return 'ok';
		if (s === 'MAINT' || s === 'NO CHECK' || s === 'DRAIN') return 'off';
		return 'down';
	}

	D.define('haproxy', {
		mount: function (w) {
			w.$body.append(el('div', 'fs-hap'));
			w.$body.on('click', '[data-hap]', function () {
				var $b = $(this).prop('disabled', true).addClass('is-busy');
				var be = $b.attr('data-be'), sv = $b.attr('data-sv'), act = $b.attr('data-hap');
				FS.api.post('/packages/haproxy/servers/' + encodeURIComponent(be) + '/' + encodeURIComponent(sv) + '/' + act, {}).then(function () {
					FS.toast(T(act === 'enable' ? '%s enabled' : '%s disabled', be + '/' + sv), 'success');
					w.refresh();
				}, function (e) {
					FS.toast(e.message, 'danger');
					$b.prop('disabled', false).removeClass('is-busy');
				});
			});
		},
		load: function (w) {
			return FS.api.get('/packages/haproxy/status').then(function (r) {
				var d = r.data, $b = w.$body.find('.fs-hap').empty();
				if (!d.frontends.length && !d.backends.length) {
					$b.append(D.empty('fa-scale-balanced', T('HAProxy has no frontends or backends.')));
					return;
				}
				if (w.settings.frontends && d.frontends.length) {
					$b.append(el('h3', 'fs-nicd-section', T('Frontends')));
					var $f = el('ul', 'fs-wlist');
					d.frontends.forEach(function (f) {
						$f.append(el('li', 'fs-svc').append(D.dot(st(f.status), f.status), el('strong', '', f.name), el('span', 'fs-mono small', f.sessions + ' / ' + f.limit)));
					});
					$b.append($f);
				}
				$b.append(el('h3', 'fs-nicd-section', T('Backends')));
				var $l = el('ul', 'fs-wlist');
				d.backends.forEach(function (be) {
					$l.append(el('li', 'fs-svc').append(D.dot(st(be.status), be.status), el('strong', '', be.name), el('span', 'fs-mono small', be.sessions + ' / ' + be.limit)));
					be.servers.forEach(function (sv) {
						var maint = String(sv.status).toUpperCase() === 'MAINT', act = maint ? 'enable' : 'disable';
						$l.append(el('li', 'fs-svc ps-4').append(D.dot(st(sv.status), sv.status),
							el('div', '').append(el('span', '', sv.name), el('small', '', sv.status)),
							el('div', 'd-flex align-items-center gap-2').append(el('span', 'fs-mono small', sv.sessions + ' / ' + sv.limit),
								el('button', 'fs-icon-btn' + (maint ? ' fs-icon-btn--go' : '')).attr({ type: 'button', 'data-hap': act, 'data-be': be.name, 'data-sv': sv.name,
									title: T(maint ? 'Enable %s' : 'Disable %s', sv.name), 'aria-label': T(maint ? 'Enable %s' : 'Disable %s', be.name + '/' + sv.name) })
									.append($('<i class="fa-solid" aria-hidden="true"></i>').addClass(maint ? 'fa-play' : 'fa-pause')))));
					});
				});
				$b.append($l);
			});
		}
	});
})(jQuery, window.FS, window.FSDashboard);
