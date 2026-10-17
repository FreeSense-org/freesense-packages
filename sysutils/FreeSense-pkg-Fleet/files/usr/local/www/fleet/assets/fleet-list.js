/*
 * FreeSense Fleet lists: a filter bar applies a choice at once (and a
 * search after a short pause), and while an operation runs the results
 * block is fetched again every 3 s (15 s in a hidden tab) and swapped, so
 * progress moves without a reload. The filter bar is outside that block
 * and keeps what is being typed.
 */
(function () {
	'use strict';

	/* A page may load this twice (its own tag and the filter bar's): run once. */
	if (window.fsFleetList) {
		return;
	}
	window.fsFleetList = true;

	Array.prototype.forEach.call(document.querySelectorAll('[data-fleet-filters]'), function (form) {
		form.classList.add('is-live');
		/* Leave empty choices out of the address (?group=1, not ?q=&state=&group=1). */
		function go() {
			Array.prototype.forEach.call(form.elements, function (el) {
				if (el.name && (el.value === '')) {
					el.disabled = true;
				}
			});
			form.submit();
		}
		/* Back to this page from the browser's cache: the fields left out above must work again. */
		window.addEventListener('pageshow', function () {
			Array.prototype.forEach.call(form.elements, function (el) { el.disabled = false; });
		});
		Array.prototype.forEach.call(form.querySelectorAll('select'), function (s) {
			s.addEventListener('change', go);
		});
		var q = form.querySelector('input[name="q"]');
		var timer = null;
		if (q) {
			q.addEventListener('input', function () {
				clearTimeout(timer);
				timer = setTimeout(go, 600);
			});
			/* Back at the end of what was typed after the page reloads. */
			if (q.value !== '' && new URLSearchParams(window.location.search).has('q')) {
				q.focus();
				q.setSelectionRange(q.value.length, q.value.length);
			}
		}
	});

	function refresh() {
		var block = document.getElementById('fs-fleet-activity');
		if (!block || block.getAttribute('data-running') !== '1') {
			return;
		}
		setTimeout(function () {
			fetch(window.location.href, { credentials: 'same-origin', cache: 'no-store' })
				.then(function (r) { return r.ok ? r.text() : null; })
				.then(function (html) {
					var next = html && new DOMParser().parseFromString(html, 'text/html').getElementById('fs-fleet-activity');
					if (next) {
						block.replaceWith(next);
					}
				})
				.catch(function () {})
				.then(refresh);
		}, document.hidden ? 15000 : 3000);
	}
	refresh();
}());
