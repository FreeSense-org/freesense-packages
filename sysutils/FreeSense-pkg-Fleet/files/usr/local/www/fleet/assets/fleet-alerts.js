/* Show the fields of the chosen channel type only; a stored channel's secrets may be left empty. */
(function () {
	var modal = document.getElementById('chan-modal');
	if (!modal) { return; }
	var sel = modal.querySelector('[data-fleet-chan-type]');
	function sync() {
		var editing = modal.querySelector('input[name=id]').value !== '';
		sel.disabled = false;
		modal.querySelectorAll('[data-fleet-chan-fields]').forEach(function (box) {
			var on = box.getAttribute('data-fleet-chan-fields') === sel.value;
			box.hidden = !on;
			box.querySelectorAll('input').forEach(function (i) {
				i.disabled = !on;
				var optional = (sel.value === 'ntfy' && i.name === 'cfg_ntfy_token') || i.getAttribute('data-fleet-optional') === '1' ||
				    (editing && i.getAttribute('data-fleet-secret-hint') === '1');
				i.required = on && !optional;
			});
		});
		modal.querySelector('.fs-fleet-keep-hint').hidden = !editing || sel.value === 'email';
		if (editing) {
			sel.setAttribute('aria-readonly', 'true');
			sel.style.pointerEvents = 'none';
		} else {
			sel.removeAttribute('aria-readonly');
			sel.style.pointerEvents = '';
		}
	}
	sel.addEventListener('change', sync);
	modal.addEventListener('shown.bs.modal', sync);
	modal.addEventListener('show.bs.modal', function () { setTimeout(sync, 0); });
	sync();
})();
