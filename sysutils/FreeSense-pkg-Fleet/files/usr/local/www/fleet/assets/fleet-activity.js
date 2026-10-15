/*
 * FreeSense Fleet activity: while an operation runs, fetch the page again
 * every 3 s (every 15 s in a hidden tab) and swap the activity block, so
 * progress moves without a reload. Stops by itself when nothing runs.
 */
(function () {
	'use strict';

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
