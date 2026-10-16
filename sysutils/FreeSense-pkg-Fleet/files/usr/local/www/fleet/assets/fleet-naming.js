/*
 * FreeSense Fleet naming: a live example of a group's hostname pattern in
 * the group modal, and the name an invitation will get. The server checks
 * and takes the real name (its counters are never reused).
 */
(function () {
	'use strict';

	function slug(s) {
		return String(s || '').toLowerCase().replace(/[^a-z0-9-]+/g, '-').replace(/-+/g, '-').replace(/^-|-$/g, '');
	}

	function render(pattern, vars) {
		return pattern.replace(/\{([a-z]+)\}/g, function (all, t) {
			if (t === 'nn') {
				return '01';
			}
			if (t === 'nnn') {
				return '001';
			}
			return slug(vars[t]) || t;
		});
	}

	var box = document.querySelector('[data-fleet-naming]');
	if (box) {
		var pat = box.querySelector('[data-naming-pattern]');
		var dom = box.querySelector('[data-naming-domain]');
		var out = box.querySelector('[data-naming-preview]');
		var groupName = document.getElementById('group_name');
		var show = function () {
			var p = pat.value.trim().toLowerCase();
			var d = dom.value.trim().toLowerCase();
			if (p === '' && d === '') {
				out.textContent = '';
				return;
			}
			out.textContent = 'Example: ' + (p ? render(p, {site: 'cph', role: 'edge', group: groupName ? groupName.value : ''}) : '<hostname>') + (d ? '.' + d : '');
		};
		[pat, dom, groupName].forEach(function (el) {
			if (el) {
				el.addEventListener('input', show);
			}
		});
		/* The modal fills the fields after it opens. */
		document.addEventListener('shown.bs.modal', show);
		box.closest('.modal') && box.closest('.modal').addEventListener('transitionend', show);
		show();
	}

	var sel = document.getElementById('naming_group');
	var site = document.getElementById('site');
	var host = document.getElementById('hostname');
	if (sel && host) {
		var hint = function () {
			var o = sel.options[sel.selectedIndex];
			var p = o.getAttribute('data-pattern') || '';
			var d = o.getAttribute('data-domain') || '';
			host.placeholder = p ? render(p, {site: site ? site.value : '', group: o.textContent}).replace(/01$|001$/, '##') + (d ? '.' + d : '') : (d ? '<hostname>.' + d : 'From the group');
		};
		sel.addEventListener('change', hint);
		if (site) {
			site.addEventListener('input', hint);
		}
		hint();
	}
}());
