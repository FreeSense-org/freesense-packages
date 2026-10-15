/*
 * FreeSense Fleet policy editor: search and filter the rule cards, show a
 * rule's settings only while it is on, and keep the counts current. The
 * form works without this script (every rule and setting is posted).
 */
(function () {
	'use strict';

	var root = document.querySelector('[data-fleet-picker]');
	if (!root) {
		return;
	}
	var cards = Array.prototype.slice.call(root.querySelectorAll('[data-rule]'));
	var search = root.querySelector('[data-picker="search"]');
	var segs = Array.prototype.slice.call(root.querySelectorAll('[data-show]'));
	var empty = root.querySelector('[data-picker="empty"]');
	var show = 'all';

	function counts() {
		var on = 0;
		var lock = 0;
		cards.forEach(function (c) {
			var isOn = c.querySelector('[data-rule-toggle]').checked;
			var m = c.querySelector('[data-rule-mode]:checked');
			on += isOn ? 1 : 0;
			lock += (isOn && m && m.value === 'lock') ? 1 : 0;
		});
		root.querySelector('[data-picker="on"]').textContent = on;
		root.querySelector('[data-picker="lock"]').textContent = lock;
		Array.prototype.forEach.call(root.querySelectorAll('[data-area]'), function (sec) {
			var all = sec.querySelectorAll('[data-rule]');
			var n = sec.querySelectorAll('[data-rule].is-on').length;
			var link = root.querySelector('[data-area-link="' + sec.getAttribute('data-area') + '"] [data-area-count]');
			link.textContent = n + '/' + all.length;
		});
	}

	function apply() {
		var q = search.value.trim().toLowerCase();
		var any = false;
		cards.forEach(function (c) {
			var on = c.classList.contains('is-on');
			var ok = (q === '' || c.getAttribute('data-text').indexOf(q) !== -1) &&
			    (show === 'all' || (show === 'on' && on) || (show === 'off' && !on) || (show === 'lockable' && c.getAttribute('data-lockable') === '1'));
			c.hidden = !ok;
			any = any || ok;
		});
		Array.prototype.forEach.call(root.querySelectorAll('[data-area]'), function (sec) {
			var visible = sec.querySelectorAll('[data-rule]:not([hidden])').length > 0;
			sec.hidden = !visible;
			var link = root.querySelector('[data-area-link="' + sec.getAttribute('data-area') + '"]');
			link.classList.toggle('is-empty', !visible);
		});
		empty.hidden = any;
	}

	cards.forEach(function (c) {
		var t = c.querySelector('[data-rule-toggle]');
		var st = c.querySelector('[data-rule-settings]');
		t.addEventListener('change', function () {
			c.classList.toggle('is-on', t.checked);
			if (st) {
				st.hidden = !t.checked;
			}
			counts();
		});
		Array.prototype.forEach.call(c.querySelectorAll('[data-rule-mode]'), function (r) {
			r.addEventListener('change', counts);
		});
	});
	search.addEventListener('input', apply);
	segs.forEach(function (b) {
		b.addEventListener('click', function () {
			show = b.getAttribute('data-show');
			segs.forEach(function (o) {
				o.classList.toggle('is-active', o === b);
				o.setAttribute('aria-pressed', o === b ? 'true' : 'false');
			});
			apply();
		});
	});
	root.querySelector('[data-picker="clear"]').addEventListener('click', function () {
		search.value = '';
		segs[0].click();
	});
	/* Enter in the search box filters; it must not save the policy. */
	search.addEventListener('keydown', function (e) {
		if (e.key === 'Enter') {
			e.preventDefault();
		}
	});
	counts();
}());
