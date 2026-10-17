/*
 * FreeSense Fleet: sections of one form shown one at a time. The switch
 * (fs_view_switch with key "section") changes the section in place, so
 * nothing typed is lost, and keeps it in the address. Every section stays
 * in the form, so saving still sends all fields. A field the browser
 * refuses in a hidden section opens that section.
 *
 * Panel order lists ([data-fleet-order]): up/down buttons and drag and
 * drop; each row's hidden order[] value is renumbered after a move.
 */
(function () {
	'use strict';

	var root = document.querySelector('[data-fleet-tabs]');
	if (root) {
		var panels = Array.prototype.slice.call(root.querySelectorAll('[data-tab-panel]'));
		var links = Array.prototype.slice.call(document.querySelectorAll('[data-fleet-tabs-switch] a')).filter(function (a) {
			return new URL(a.href, window.location.href).searchParams.has('section');
		});
		var show = function (name) {
			panels.forEach(function (p) {
				p.hidden = p.getAttribute('data-tab-panel') !== name;
			});
			links.forEach(function (a) {
				if (new URL(a.href, window.location.href).searchParams.get('section') === name) {
					a.setAttribute('aria-current', 'page');
				} else {
					a.removeAttribute('aria-current');
				}
			});
			var url = new URL(window.location.href);
			url.searchParams.set('section', name);
			window.history.replaceState(null, '', url);
			/* After saving, the page comes back on this section. */
			if (root.hasAttribute('action')) {
				var act = new URL(root.getAttribute('action'), window.location.href);
				act.searchParams.set('section', name);
				root.setAttribute('action', act.pathname + act.search);
			}
		};
		links.forEach(function (a) {
			a.addEventListener('click', function (e) {
				e.preventDefault();
				show(new URL(a.href, window.location.href).searchParams.get('section'));
			});
		});
		root.addEventListener('invalid', function (e) {
			var p = e.target.closest('[data-tab-panel]');
			if (p && p.hidden) {
				show(p.getAttribute('data-tab-panel'));
			}
		}, true);
	}

	Array.prototype.forEach.call(document.querySelectorAll('[data-fleet-order]'), function (list) {
		var live = list.parentNode.querySelector('[data-fleet-order-live]');
		var renumber = function () {
			Array.prototype.forEach.call(list.children, function (li, i) {
				li.querySelector('input[name^="order["]').value = i + 1;
				li.querySelector('[data-move="-1"]').disabled = (i === 0);
				li.querySelector('[data-move="1"]').disabled = (i === list.children.length - 1);
			});
		};
		list.addEventListener('click', function (e) {
			var b = e.target.closest('[data-move]');
			if (!b) {
				return;
			}
			var li = b.closest('li');
			if (b.getAttribute('data-move') === '-1' && li.previousElementSibling) {
				list.insertBefore(li, li.previousElementSibling);
			} else if (b.getAttribute('data-move') === '1' && li.nextElementSibling) {
				list.insertBefore(li.nextElementSibling, li);
			}
			renumber();
			(b.disabled ? li.querySelector('[data-move]:not([disabled])') : b).focus();
			if (live) {
				live.textContent = li.getAttribute('data-name') + ': ' + (Array.prototype.indexOf.call(list.children, li) + 1);
			}
		});
		var dragged = null;
		list.addEventListener('dragstart', function (e) {
			dragged = e.target.closest('li');
			e.dataTransfer.effectAllowed = 'move';
			dragged.classList.add('is-dragging');
		});
		list.addEventListener('dragover', function (e) {
			var over = e.target.closest('li');
			if (!dragged || !over || over === dragged) {
				return;
			}
			e.preventDefault();
			var r = over.getBoundingClientRect();
			list.insertBefore(dragged, (e.clientY - r.top) > r.height / 2 ? over.nextSibling : over);
		});
		list.addEventListener('dragend', function () {
			if (dragged) {
				dragged.classList.remove('is-dragging');
			}
			dragged = null;
			renumber();
		});
		renumber();
	});
}());
