/*
 * FreeSense Fleet confirmations: a button (or link) with data-fleet-confirm
 * asks first. The attribute is made by fleet_confirm() in fleet_list.inc:
 * {title, text, action, tone: danger|warning|info, icon, cancel, type?,
 * typeLabel?, items?}. Cancel is focused and comes first, the action last,
 * in one row. Without JavaScript the button simply does what it says, so
 * the server still checks everything; the dialog only gives a moment to
 * think. With "type" the action stays off until that text is typed.
 */
(function () {
	'use strict';

	var modalEl = null;
	var dlg = null;

	function el(tag, cls, text) {
		var n = document.createElement(tag);
		if (cls) {
			n.className = cls;
		}
		if (text !== undefined) {
			n.textContent = text;
		}
		return n;
	}

	function build() {
		modalEl = el('div', 'modal fade fs-modal-form fleet-confirm');
		modalEl.setAttribute('tabindex', '-1');
		modalEl.setAttribute('aria-labelledby', 'fleet-confirm-title');
		modalEl.setAttribute('aria-describedby', 'fleet-confirm-text');
		modalEl.setAttribute('aria-hidden', 'true');
		modalEl.setAttribute('role', 'alertdialog');
		var dialog = el('div', 'modal-dialog modal-dialog-centered');
		var content = el('div', 'modal-content');
		var head = el('div', 'modal-header fleet-confirm-head');
		var icon = el('span', 'fleet-confirm-icon');
		icon.setAttribute('aria-hidden', 'true');
		var iconGlyph = el('i');
		icon.appendChild(iconGlyph);
		var title = el('h2', 'modal-title');
		title.id = 'fleet-confirm-title';
		var close = el('button', 'btn-close');
		close.type = 'button';
		close.setAttribute('data-bs-dismiss', 'modal');
		close.setAttribute('aria-label', 'Close');
		head.appendChild(icon);
		head.appendChild(title);
		head.appendChild(close);
		var body = el('div', 'modal-body');
		var text = el('p', 'fleet-confirm-text');
		text.id = 'fleet-confirm-text';
		var items = el('ul', 'fleet-confirm-items');
		var typeBox = el('div', 'fleet-confirm-type');
		var typeLabel = el('label', 'form-label');
		typeLabel.setAttribute('for', 'fleet-confirm-typed');
		var typed = el('input', 'form-control fs-mono');
		typed.id = 'fleet-confirm-typed';
		typed.type = 'text';
		typed.setAttribute('autocomplete', 'off');
		typed.setAttribute('spellcheck', 'false');
		typeBox.appendChild(typeLabel);
		typeBox.appendChild(typed);
		body.appendChild(text);
		body.appendChild(items);
		body.appendChild(typeBox);
		var foot = el('div', 'modal-footer');
		var cancel = el('button', 'btn btn-outline-secondary');
		cancel.type = 'button';
		cancel.setAttribute('data-bs-dismiss', 'modal');
		var go = el('button', 'btn');
		go.type = 'button';
		var goIcon = el('i', 'icon-embed-btn');
		goIcon.setAttribute('aria-hidden', 'true');
		var goText = el('span');
		go.appendChild(goIcon);
		go.appendChild(goText);
		foot.appendChild(cancel);
		foot.appendChild(go);
		content.appendChild(head);
		content.appendChild(body);
		content.appendChild(foot);
		dialog.appendChild(content);
		modalEl.appendChild(dialog);
		document.body.appendChild(modalEl);
		dlg = {title: title, iconGlyph: iconGlyph, text: text, items: items, typeBox: typeBox, typeLabel: typeLabel, typed: typed,
		    cancel: cancel, go: go, goIcon: goIcon, goText: goText, close: close, run: null};

		go.addEventListener('click', function () {
			if (go.disabled || !dlg.run) {
				return;
			}
			var run = dlg.run;
			dlg.run = null;
			window.bootstrap.Modal.getOrCreateInstance(modalEl).hide();
			run();
		});
		typed.addEventListener('input', function () {
			go.disabled = (typed.value.trim() !== dlg.expect);
		});
		typed.addEventListener('keydown', function (e) {
			if ((e.key === 'Enter') && !go.disabled) {
				e.preventDefault();
				go.click();
			}
		});
		/* Cancel takes the focus, so Enter never confirms a delete by accident. */
		modalEl.addEventListener('shown.bs.modal', function () {
			(dlg.typeBox.hidden ? dlg.cancel : dlg.typed).focus();
		});
		modalEl.addEventListener('hidden.bs.modal', function () {
			dlg.run = null;
		});
	}

	function ask(cfg, run) {
		if (!window.bootstrap || !window.bootstrap.Modal) {
			if (window.confirm(String(cfg.title || '') + '\n\n' + String(cfg.text || ''))) {
				run();
			}
			return;
		}
		if (!modalEl) {
			build();
		}
		var tone = (['danger', 'warning', 'info'].indexOf(cfg.tone) >= 0) ? cfg.tone : 'danger';
		modalEl.setAttribute('data-tone', tone);
		dlg.title.textContent = cfg.title || '';
		dlg.iconGlyph.className = 'fa-solid fa-' + (cfg.icon || (tone === 'danger' ? 'trash' : 'triangle-exclamation'));
		dlg.text.textContent = cfg.text || '';
		dlg.text.hidden = !cfg.text;
		dlg.items.textContent = '';
		(cfg.items || []).forEach(function (t) {
			dlg.items.appendChild(el('li', '', t));
		});
		dlg.items.hidden = !(cfg.items && cfg.items.length);
		dlg.cancel.textContent = cfg.cancel || 'Cancel';
		dlg.close.setAttribute('aria-label', cfg.cancel || 'Cancel');
		dlg.go.className = 'btn ' + (tone === 'danger' ? 'btn-danger' : (tone === 'warning' ? 'btn-warning' : 'btn-primary'));
		dlg.goIcon.className = 'fa-solid fa-' + (cfg.icon || (tone === 'danger' ? 'trash' : 'check')) + ' icon-embed-btn';
		dlg.goText.textContent = cfg.action || 'OK';
		dlg.expect = cfg.type ? String(cfg.type) : '';
		dlg.typeBox.hidden = (dlg.expect === '');
		dlg.typed.value = '';
		dlg.typeLabel.textContent = cfg.typeLabel || '';
		dlg.go.disabled = (dlg.expect !== '');
		dlg.run = run;
		window.bootstrap.Modal.getOrCreateInstance(modalEl).show();
	}

	document.addEventListener('click', function (e) {
		var btn = e.target.closest ? e.target.closest('[data-fleet-confirm]') : null;
		if (!btn || btn.disabled) {
			return;
		}
		/* The click made after the admin agreed goes through. */
		if (btn.fleetConfirmed) {
			btn.fleetConfirmed = false;
			return;
		}
		var cfg;
		try {
			cfg = JSON.parse(btn.getAttribute('data-fleet-confirm'));
		} catch (err) {
			return;
		}
		e.preventDefault();
		e.stopPropagation();
		ask(cfg, function () {
			btn.fleetConfirmed = true;
			btn.click();
		});
	}, true);
}());
