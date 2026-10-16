/*
 * FreeSense Fleet template editor: add and remove alias cards, and keep
 * each card's icon and entry count current. Without the script the form
 * still posts the cards it was given.
 */
(function () {
	'use strict';

	var list = document.querySelector('[data-tpl-list]');
	if (!list) {
		return;
	}
	var blank = document.querySelector('[data-tpl-blank]');
	var icons = {host: 'fa-server', network: 'fa-network-wired', port: 'fa-plug'};
	var next = parseInt(list.getAttribute('data-next'), 10) || 0;

	function count(card) {
		var text = card.querySelector('[data-tpl-entries]').value;
		var n = text.split(/\r?\n/).filter(function (l) { return l.split('#')[0].trim() !== ''; }).length;
		card.querySelector('[data-tpl-count]').textContent = n === 1 ? '1 entry' : n + ' entries';
	}

	function wire(card) {
		var type = card.querySelector('[data-tpl-type]');
		var icon = card.querySelector('[data-tpl-icon]');
		type.addEventListener('change', function () {
			icon.className = 'fa-solid ' + (icons[type.value] || 'fa-server');
		});
		card.querySelector('[data-tpl-entries]').addEventListener('input', function () {
			count(card);
		});
		card.querySelector('[data-tpl-remove]').addEventListener('click', function () {
			if (list.querySelectorAll('[data-tpl-card]').length > 1) {
				card.remove();
			} else {
				Array.prototype.forEach.call(card.querySelectorAll('input, textarea'), function (f) { f.value = ''; });
				count(card);
			}
		});
		count(card);
	}

	Array.prototype.forEach.call(list.querySelectorAll('[data-tpl-card]'), wire);
	document.querySelector('[data-tpl-add]').addEventListener('click', function () {
		var html = blank.innerHTML.replace(/999999/g, String(next++));
		var holder = document.createElement('div');
		holder.innerHTML = html.trim();
		var card = holder.firstElementChild;
		list.appendChild(card);
		wire(card);
		card.querySelector('input').focus();
	});
}());
