/*
 * FreeSense Fleet dashboard: draws the fleet wall and keeps it current.
 * Polls fleet_data.php with an ETag: every 10 s while the tab is visible,
 * every 60 s while hidden. A refresh never animates (docs/webui/01-tokens.md).
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
	var etag = null;
	var stale = false;
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
		if (b.state === 'online') {
			top.appendChild(el('span', 'fs-fleet-ok', T.online));
		} else {
			top.appendChild(badge(b.state, T[b.state]));
		}
		li.appendChild(top);

		if (b.problem) {
			li.appendChild(el('p', 'fs-fleet-problem', b.problem));
		}

		var dl = el('dl', 'fs-fleet-facts');
		fact(dl, T.version, b.version || '-');
		fact(dl, T.role, b.role === 'managed' ? T.managed : T.monitor);
		fact(dl, T.tunnel, b.overlay, true);
		var seen = fact(dl, T.seen, ago(b.seen));
		seen.setAttribute('data-seen', b.seen || 0);
		li.appendChild(dl);

		var foot = el('div', 'fs-fleet-box-foot');
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

	function visible(b) {
		if (filter === 'all') {
			return true;
		}
		if (filter === 'unprotected') {
			return b.rollback === false;
		}
		return b.state === filter;
	}

	function render() {
		headline.textContent = data.headline;
		buttons.forEach(function (btn) {
			var key = btn.getAttribute('data-filter');
			var n = key === 'all' ? data.total : data.counts[key];
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
			filterEmpty.textContent = T.none_match.replace('%s', label) + ' ';
			var all = el('button', 'btn btn-link p-0 align-baseline', T.show_all);
			all.type = 'button';
			all.addEventListener('click', function () { setFilter('all'); });
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
	}

	function setFilter(key) {
		filter = (filter === key && key !== 'all') ? 'all' : key;
		render();
	}

	buttons.forEach(function (btn) {
		btn.addEventListener('click', function () { setFilter(btn.getAttribute('data-filter')); });
	});

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
		timer = setTimeout(poll, document.hidden ? 60000 : 10000);
	}
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
