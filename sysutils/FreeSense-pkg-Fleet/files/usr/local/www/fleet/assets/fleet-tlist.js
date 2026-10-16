/*
 * FreeSense Fleet rule and port forward template editor: add and remove
 * rows. Without the script the form still posts the rows it was given.
 */
(function () {
	'use strict';

	var list = document.querySelector('[data-tl-list]');
	if (!list) {
		return;
	}
	var blank = document.querySelector('[data-tl-blank]');
	var next = parseInt(list.getAttribute('data-next'), 10) || 0;

	function wire(row) {
		row.querySelector('[data-tl-remove]').addEventListener('click', function () {
			if (list.querySelectorAll('[data-tl-row]').length > 1) {
				row.remove();
			} else {
				Array.prototype.forEach.call(row.querySelectorAll('input:not([type=checkbox])'), function (f) { f.value = ''; });
			}
		});
	}

	Array.prototype.forEach.call(list.querySelectorAll('[data-tl-row]'), wire);
	document.querySelector('[data-tl-add]').addEventListener('click', function () {
		var holder = document.createElement('tbody');
		holder.innerHTML = blank.innerHTML.replace(/999999/g, String(next++)).trim();
		var row = holder.firstElementChild;
		list.appendChild(row);
		wire(row);
		row.querySelector('input').focus();
	});
}());
