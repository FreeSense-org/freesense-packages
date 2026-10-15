/*
 * FreeSense Fleet dashboard: draws the fleet wall and keeps it current.
 * Polls fleet_data.php with an ETag: every 10 s while the tab is visible
 * (every 2 s while an action runs on a firewall), every 60 s while hidden.
 * A refresh never animates (docs/webui/01-tokens.md).
 * The "..." menus (page and tiles) are built here too; quick actions post
 * to fleet_action.php and show their progress on the tile.
 */
(function () {
	'use strict';

	var root = document.getElementById('fs-fleet');
	if (!root) {
		return;
	}
	var T = JSON.parse(root.getAttribute('data-strings'));
	var wall = root.querySelector('[data-fleet="wall"]');
	var headline = root.querySelector('[data-fleet="headline"]');
	var checked = root.querySelector('[data-fleet="checked"]');
	var filterEmpty = root.querySelector('[data-fleet="filter-empty"]');
	var buttons = Array.prototype.slice.call(root.querySelectorAll('[data-filter]'));
	var data = JSON.parse(document.getElementById('fs-fleet-initial').textContent);
	var filter = 'all';
	var groupSelect = root.querySelector('[data-fleet="group"]');
	var group = '';
	var etag = null;
	var stale = false;
	/* May this user act on firewalls (the full Fleet privilege)? */
	var canManage = root.getAttribute('data-manage') === '1';
	/* The tile asking "Reboot ...?" and the tile whose menu is open; a refresh keeps both. */
	var confirming = null;
	var menuOpen = null;
	var deferred = false;
	/* A message for one tile after its action was refused: id => text. */
	var notes = {};
	var activityEl = root.querySelector('[data-fleet="activity"]');
	/* Server clock minus browser clock, so "ago" is right when the two disagree. */
	var skew = data.now * 1000 - Date.now();

	var BADGE = {
		online: ['pass', 'fa-circle-check'], degraded: ['warn', 'fa-triangle-exclamation'],
		offline: ['block', 'fa-circle-xmark'], 'new': ['neutral', 'fa-hourglass-half'],
		warn: ['warn', 'fa-triangle-exclamation'], info: ['info', 'fa-circle-info']
	};

	function el(tag, cls, text) {
		var e = document.createElement(tag);
		if (cls) {
			e.className = cls;
		}
		if (text !== undefined && text !== null) {
			e.textContent = text;
		}
		return e;
	}

	/* The same markup as fs_badge() in fs_ui.inc. */
	function badge(kind, label, title) {
		var b = BADGE[kind] || BADGE['new'];
		var s = el('span', 'fs-badge fs-badge--' + b[0]);
		var i = el('i', 'fa-solid ' + b[1]);
		i.setAttribute('aria-hidden', 'true');
		s.appendChild(i);
		s.appendChild(document.createTextNode(label));
		if (title) {
			s.title = title;
		}
		return s;
	}

	function ago(ts) {
		if (!ts) {
			return T.never;
		}
		var d = Math.max(0, Math.round((Date.now() + skew) / 1000 - ts));
		if (d < 90) {
			return T.ago_s.replace('%d', d);
		}
		if (d < 5400) {
			return T.ago_m.replace('%d', Math.round(d / 60));
		}
		if (d < 172800) {
			return T.ago_h.replace('%d', Math.round(d / 3600));
		}
		return T.ago_d.replace('%d', Math.round(d / 86400));
	}

	function fact(dl, term, value, mono) {
		dl.appendChild(el('dt', null, term));
		var dd = el('dd', mono ? 'fs-mono' : null, value);
		dl.appendChild(dd);
		return dd;
	}

	function tile(b) {
		var li = el('li', 'fs-fleet-box');
		li.setAttribute('data-state', b.state);
		li.setAttribute('aria-label', b.label + ': ' + T[b.state]);

		var top = el('div', 'fs-fleet-box-top');
		var names = el('div', 'fs-fleet-box-names');
		var h = el('h3', 'fs-fleet-box-name');
		var a = el('a', null, b.label);
		a.href = '/fleet/fleet_box.php?id=' + encodeURIComponent(b.id);
		h.appendChild(a);
		names.appendChild(h);
		if (b.host && b.host !== b.label) {
			names.appendChild(el('div', 'fs-fleet-box-host', b.host));
		}
		top.appendChild(names);
		var side = el('div', 'fs-fleet-box-side');
		if (b.state === 'online') {
			side.appendChild(el('span', 'fs-fleet-ok', T.online));
		} else {
			side.appendChild(badge(b.state, T[b.state]));
		}
		side.appendChild(tileMenu(b));
		top.appendChild(side);
		li.appendChild(top);

		var running = isBusy(b);
		if (running) {
			li.setAttribute('data-busy', 'true');
		}
		if (b.op) {
			li.appendChild(opLine(b.op));
		}
		if (notes[b.id]) {
			li.appendChild(el('p', 'fs-fleet-problem', notes[b.id]));
		}
		/* A failed action usually says the same as the problem; say it once. */
		if (b.problem && !running && !(b.op && b.op.text.indexOf(b.problem) !== -1)) {
			li.appendChild(el('p', 'fs-fleet-problem', b.problem));
		}
		if (confirming === b.id) {
			li.appendChild(confirmStrip(b));
		}

		var dl = el('dl', 'fs-fleet-facts');
		fact(dl, T.version, b.version || '-');
		fact(dl, T.role, b.role === 'managed' ? T.managed : T.monitor);
		fact(dl, T.tunnel, b.overlay, true);
		var seen = fact(dl, T.seen, ago(b.seen));
		seen.setAttribute('data-seen', b.seen || 0);
		var backup = fact(dl, T.backup, ago(b.backup));
		backup.setAttribute('data-seen', b.backup || 0);
		li.appendChild(dl);

		var foot = el('div', 'fs-fleet-box-foot');
		(b.groups || []).forEach(function (g) {
			var chip = el('span', 'fs-fleet-group', g.name);
			chip.style.setProperty('--fs-fleet-group', 'var(--fs-series-' + g.color + ')');
			foot.appendChild(chip);
		});
		if (b.rollback === false) {
			foot.appendChild(badge('warn', T.rollback, T.rollback_hint));
		}
		if (b.carp && b.carp !== 'none' && b.carp !== 'ok') {
			foot.appendChild(badge('degraded', T.carp + ': ' + b.carp));
		}
		if (b.breakglass) {
			foot.appendChild(badge('warn', T.breakglass));
		}
		li.appendChild(foot);
		return li;
	}

	/* "Restarting (1 min 5 s)" with a spinner while it runs; the result for a moment after. */
	function opLine(op) {
		var p = el('p', 'fs-fleet-op');
		p.setAttribute('data-op', op.state);
		p.setAttribute('role', 'status');
		var icon = { running: 'fa-spinner', queued: 'fa-clock', done: 'fa-circle-check', failed: 'fa-circle-xmark', skipped: 'fa-forward' }[op.state] || 'fa-circle-info';
		var i = el('i', 'fa-solid ' + icon);
		i.setAttribute('aria-hidden', 'true');
		p.appendChild(i);
		var text = el('span', null, op.text);
		p.appendChild(text);
		if (op.state === 'running') {
			var t = el('span', 'fs-fleet-op-time');
			t.setAttribute('data-since', op.started);
			p.appendChild(t);
		}
		return p;
	}

	function elapsed(ts) {
		var d = Math.max(0, Math.round((Date.now() + skew) / 1000 - ts));
		return d < 60 ? T.secs.replace('%d', d) : T.mins.replace('%d', Math.floor(d / 60)).replace('%s', d % 60);
	}

	function confirmStrip(b) {
		var box = el('div', 'fs-fleet-confirm');
		box.setAttribute('role', 'group');
		box.setAttribute('aria-label', T.reboot_q.replace('%s', b.label));
		box.appendChild(el('p', 'fs-fleet-confirm-q', T.reboot_q.replace('%s', b.label)));
		box.appendChild(el('p', 'fs-fleet-confirm-hint', T.reboot_hint));
		var row = el('div', 'fs-fleet-confirm-actions');
		var go = el('button', 'btn btn-sm btn-primary');
		go.type = 'button';
		var gi = el('i', 'fa-solid fa-power-off icon-embed-btn');
		gi.setAttribute('aria-hidden', 'true');
		go.appendChild(gi);
		go.appendChild(document.createTextNode(T.reboot_now));
		go.addEventListener('click', function () {
			confirming = null;
			act(b, 'reboot', T.rebooting);
		});
		var no = el('button', 'btn btn-sm btn-outline-secondary', T.cancel);
		no.type = 'button';
		no.addEventListener('click', function () {
			confirming = null;
			render();
		});
		row.appendChild(go);
		row.appendChild(no);
		box.appendChild(row);
		/* Focus the question once, when it opens. */
		setTimeout(function () { if (document.activeElement === document.body || !wall.contains(document.activeElement)) { go.focus({ preventScroll: true }); } }, 0);
		return box;
	}

	/* ---- the "..." menus ---- */

	function menuItem(menu, label, icon, handler, disabled) {
		var li = el('li');
		li.setAttribute('role', 'none');
		var a = el(typeof handler === 'string' ? 'a' : 'button', 'fs-fleet-menu-item');
		a.setAttribute('role', 'menuitem');
		a.tabIndex = -1;
		var i = el('i', 'fa-solid ' + icon);
		i.setAttribute('aria-hidden', 'true');
		a.appendChild(i);
		a.appendChild(document.createTextNode(label));
		if (typeof handler === 'string') {
			a.href = handler;
		} else {
			a.type = 'button';
			a.disabled = !!disabled;
			if (disabled) {
				a.setAttribute('aria-disabled', 'true');
			}
			a.addEventListener('click', function () {
				closeMenus();
				handler();
			});
		}
		li.appendChild(a);
		menu.appendChild(li);
	}

	function menuSeparator(menu) {
		var li = el('li', 'fs-fleet-menu-sep');
		li.setAttribute('role', 'separator');
		menu.appendChild(li);
	}

	function tileMenu(b) {
		var wrap = el('div', 'fs-fleet-menu');
		var btn = el('button', 'fs-fleet-menu-btn');
		btn.type = 'button';
		btn.setAttribute('aria-haspopup', 'menu');
		btn.setAttribute('aria-label', T.actions_for.replace('%s', b.label));
		btn.title = T.actions;
		var bi = el('i', 'fa-solid fa-ellipsis');
		bi.setAttribute('aria-hidden', 'true');
		btn.appendChild(bi);
		var menu = el('ul', 'fs-fleet-menu-list');
		menu.setAttribute('role', 'menu');
		var page = '/fleet/fleet_box.php?id=' + encodeURIComponent(b.id);
		var busy = isBusy(b);
		var down = b.state === 'offline' || b.state === 'new';
		menuItem(menu, T.open, 'fa-arrow-right', page);
		menuItem(menu, T.webui, 'fa-up-right-from-square', page + '&view=overview#webui');
		menuItem(menu, T.events, 'fa-list', page + '&view=events');
		if (canManage) {
			menuSeparator(menu);
			menuItem(menu, T.backup_now, 'fa-floppy-disk', function () { act(b, 'backup', T.backing_up); }, busy || down);
			if (b.managed) {
				menuItem(menu, T.services, 'fa-gears', page + '&view=manage');
				menuItem(menu, T.reboot, 'fa-power-off', function () {
					confirming = b.id;
					render();
				}, busy || down);
			}
		}
		wireMenu(wrap, btn, menu, b.id);
		wrap.appendChild(btn);
		wrap.appendChild(menu);
		return wrap;
	}

	function closeMenus() {
		Array.prototype.forEach.call(document.querySelectorAll('.fs-fleet-menu[data-open]'), function (m) {
			m.removeAttribute('data-open');
			m.querySelector('.fs-fleet-menu-btn').setAttribute('aria-expanded', 'false');
		});
		menuOpen = null;
		if (deferred) {
			deferred = false;
			render();
		}
	}

	/* Opens on click, Enter or arrow down; arrows move, Escape closes and returns focus. */
	function wireMenu(wrap, btn, menu, key) {
		btn.setAttribute('aria-expanded', 'false');
		function items() {
			return Array.prototype.filter.call(menu.querySelectorAll('[role="menuitem"]'), function (i) { return !i.disabled; });
		}
		function open(focusFirst) {
			closeMenus();
			wrap.setAttribute('data-open', '');
			btn.setAttribute('aria-expanded', 'true');
			menuOpen = key;
			if (focusFirst && items()[0]) {
				items()[0].focus();
			}
		}
		btn.addEventListener('click', function (e) {
			e.stopPropagation();
			if (wrap.hasAttribute('data-open')) {
				closeMenus();
			} else {
				open(e.detail === 0);
			}
		});
		btn.addEventListener('keydown', function (e) {
			if (e.key === 'ArrowDown') {
				e.preventDefault();
				open(true);
			}
		});
		menu.addEventListener('keydown', function (e) {
			var list = items();
			var at = list.indexOf(document.activeElement);
			if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
				e.preventDefault();
				var next = (at + (e.key === 'ArrowDown' ? 1 : -1) + list.length) % list.length;
				list[next].focus();
			} else if (e.key === 'Escape') {
				e.preventDefault();
				closeMenus();
				btn.focus();
			} else if (e.key === 'Tab') {
				closeMenus();
			}
		});
		menu.addEventListener('click', function (e) {
			e.stopPropagation();
		});
	}
	document.addEventListener('click', function () {
		if (menuOpen !== null) {
			closeMenus();
		}
	});
	/* The page's own menu (server-rendered). */
	Array.prototype.forEach.call(document.querySelectorAll('[data-fleet-menu]'), function (wrap) {
		wireMenu(wrap, wrap.querySelector('.fs-fleet-menu-btn'), wrap.querySelector('.fs-fleet-menu-list'), 'page');
		Array.prototype.forEach.call(wrap.querySelectorAll('[data-submit]'), function (b) {
			b.addEventListener('click', function () {
				var form = document.getElementById(b.getAttribute('data-submit'));
				if (form.elements.group) {
					form.elements.group.value = group;
				}
				form.submit();
			});
		});
	});

	/* ---- quick actions ---- */

	function act(b, action, text) {
		delete notes[b.id];
		/* Show it at once; the next refresh brings the controller's own record. */
		b.op = { state: 'running', text: text, started: Math.round((Date.now() + skew) / 1000) };
		render();
		var body = new URLSearchParams();
		body.set('id', b.id);
		body.set('action', action);
		if (typeof csrfMagicToken !== 'undefined') {
			body.set('__csrf_magic', csrfMagicToken);
		}
		fetch('/fleet/fleet_action.php', { method: 'POST', body: body, credentials: 'same-origin', headers: { 'Accept': 'application/json' } })
			.then(function (r) {
				return r.json().catch(function () { return { ok: false, message: 'HTTP ' + r.status }; });
			})
			.then(function (res) {
				if (!res.ok) {
					b.op = null;
					notes[b.id] = res.message;
				}
			})
			.catch(function () {
				b.op = null;
				notes[b.id] = T.action_failed;
			})
			.then(function () {
				etag = null;
				poll();
			});
	}

	function isBusy(b) {
		return !!b.op && (b.op.state === 'running' || b.op.state === 'queued');
	}

	/* A strip per running group operation: "Back up Denmark  5 of 8 done" with a bar. */
	function renderActivity() {
		if (!activityEl) {
			return;
		}
		var frag = document.createDocumentFragment();
		(data.activity || []).forEach(function (op) {
			var row = el('a', 'fs-fleet-activity');
			row.href = '/fleet/fleet_activity.php?op=' + op.id;
			var i = el('i', 'fa-solid fa-spinner');
			i.setAttribute('aria-hidden', 'true');
			row.appendChild(i);
			row.appendChild(el('strong', null, op.title));
			row.appendChild(el('span', 'fs-fleet-activity-text', op.text));
			var bar = el('span', 'fs-fleet-bar');
			bar.setAttribute('role', 'progressbar');
			bar.setAttribute('aria-valuenow', op.percent);
			bar.setAttribute('aria-valuemin', '0');
			bar.setAttribute('aria-valuemax', '100');
			bar.setAttribute('aria-label', op.title);
			var fill = el('span', 'fs-fleet-bar-fill');
			fill.style.width = op.percent + '%';
			bar.appendChild(fill);
			row.appendChild(bar);
			row.appendChild(el('span', 'fs-fleet-activity-link', T.details));
			frag.appendChild(row);
		});
		activityEl.replaceChildren(frag);
		activityEl.hidden = !(data.activity || []).length;
	}

	function inGroup(b) {
		return (group === '') || (b.groups || []).some(function (g) { return String(g.id) === group; });
	}

	function visible(b) {
		if (!inGroup(b)) {
			return false;
		}
		if (filter === 'all') {
			return true;
		}
		if (filter === 'unprotected') {
			return b.rollback === false;
		}
		return b.state === filter;
	}

	function render() {
		/* Never rebuild the wall under an open menu: it would close in the user's hand. */
		if (menuOpen !== null || (confirming !== null && wall.querySelector('.fs-fleet-confirm'))) {
			deferred = true;
			return;
		}
		deferred = false;
		headline.textContent = data.headline;
		renderActivity();
		/* The tiles count the firewalls in the chosen group. */
		var counts = { all: 0, online: 0, degraded: 0, offline: 0, 'new': 0, unprotected: 0 };
		data.boxes.forEach(function (b) {
			if (inGroup(b)) {
				counts.all++;
				counts[b.state]++;
				if (b.rollback === false) {
					counts.unprotected++;
				}
			}
		});
		buttons.forEach(function (btn) {
			var key = btn.getAttribute('data-filter');
			var n = counts[key];
			btn.querySelector('[data-count]').textContent = n;
			btn.setAttribute('aria-pressed', key === filter ? 'true' : 'false');
		});
		var frag = document.createDocumentFragment();
		var shown = 0;
		data.boxes.forEach(function (b) {
			if (visible(b)) {
				frag.appendChild(tile(b));
				shown++;
			}
		});
		wall.replaceChildren(frag);
		wall.hidden = data.total === 0;
		if (shown === 0 && data.total > 0) {
			var label = root.querySelector('[data-filter="' + filter + '"] .fs-tile-label').textContent.toLowerCase();
			filterEmpty.textContent = ((filter === 'all') ? T.none_in_group : T.none_match.replace('%s', label)) + ' ';
			var all = el('button', 'btn btn-link p-0 align-baseline', T.show_all);
			all.type = 'button';
			all.addEventListener('click', function () {
				if (groupSelect) {
					groupSelect.value = '';
				}
				group = '';
				setFilter('all');
			});
			filterEmpty.appendChild(all);
			filterEmpty.hidden = false;
		} else {
			filterEmpty.hidden = true;
		}
		tick();
	}

	/* Only the relative times move between refreshes. */
	function tick() {
		var text = data.checked ? T.checked.replace('%s', ago(data.checked)) : T.not_checked;
		checked.textContent = stale ? text + '. ' + T.stale : text;
		Array.prototype.forEach.call(wall.querySelectorAll('[data-seen]'), function (dd) {
			dd.textContent = ago(parseInt(dd.getAttribute('data-seen'), 10));
		});
		Array.prototype.forEach.call(wall.querySelectorAll('[data-since]'), function (s) {
			s.textContent = elapsed(parseInt(s.getAttribute('data-since'), 10));
		});
	}

	function setFilter(key) {
		filter = (filter === key && key !== 'all') ? 'all' : key;
		render();
	}

	buttons.forEach(function (btn) {
		btn.addEventListener('click', function () { setFilter(btn.getAttribute('data-filter')); });
	});
	if (groupSelect) {
		/* fleet_dashboard.php?group=<id> opens the dashboard on that group (the Groups page links here). */
		var wanted = new URLSearchParams(window.location.search).get('group') || '';
		if (wanted !== '' && groupSelect.querySelector('option[value="' + wanted.replace(/[^0-9]/g, '') + '"]')) {
			groupSelect.value = wanted;
			group = wanted;
		}
		var allLabel = root.querySelector('[data-fleet="backup-all-label"]');
		var labelGroup = function () {
			if (allLabel) {
				allLabel.textContent = group === '' ? T.backup_all : T.backup_group.replace('%s', groupSelect.options[groupSelect.selectedIndex].text.replace(/ \(\d+\)$/, ''));
			}
		};
		groupSelect.addEventListener('change', function () {
			group = groupSelect.value;
			labelGroup();
			render();
		});
		labelGroup();
	}

	function poll() {
		var headers = { 'Accept': 'application/json' };
		if (etag) {
			headers['If-None-Match'] = etag;
		}
		fetch(root.getAttribute('data-src'), { headers: headers, credentials: 'same-origin', cache: 'no-store' })
			.then(function (r) {
				if (r.status === 304) {
					return null;
				}
				if (!r.ok || (r.headers.get('Content-Type') || '').indexOf('application/json') !== 0) {
					throw new Error('HTTP ' + r.status);
				}
				etag = r.headers.get('ETag');
				return r.json();
			})
			.then(function (next) {
				stale = false;
				if (next) {
					skew = next.now * 1000 - Date.now();
					data = next;
					render();
				} else {
					tick();
				}
			})
			.catch(function () {
				stale = true;
				tick();
			})
			.then(schedule);
	}

	var timer = null;
	function schedule() {
		clearTimeout(timer);
		var busy = data.boxes.some(isBusy) || (data.activity || []).length > 0;
		timer = setTimeout(poll, document.hidden ? 60000 : (busy ? 2000 : 10000));
	}
	/* The running time on a busy tile counts every second. */
	setInterval(function () {
		if (!document.hidden && wall.querySelector('[data-since]')) {
			tick();
		}
	}, 1000);
	document.addEventListener('visibilitychange', function () {
		if (!document.hidden) {
			poll();
		} else {
			schedule();
		}
	});

	render();
	schedule();
}());
