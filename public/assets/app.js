// SPDX-License-Identifier: GPL-3.0-or-later
// Linux Mail Dashboard – bez inline skriptů (CSP script-src 'self').
'use strict';

document.addEventListener('DOMContentLoaded', () => {
  // QR kód pro nastavení MFA
  document.querySelectorAll('[data-qr]').forEach((el) => {
    if (typeof window.qrcode !== 'function') return;
    const qr = window.qrcode(0, 'M');
    qr.addData(el.dataset.qr);
    qr.make();
    el.innerHTML = qr.createSvgTag({ cellSize: 5, margin: 4, scalable: true });
  });

  // potvrzení akcí
  document.querySelectorAll('form[data-confirm]').forEach((form) => {
    form.addEventListener('submit', (ev) => {
      if (!window.confirm(form.dataset.confirm)) ev.preventDefault();
    });
  });

  // kód MFA: jen číslice
  document.querySelectorAll('input.code').forEach((input) => {
    input.addEventListener('input', () => { input.value = input.value.replace(/[^0-9 ]/g, ''); });
  });
});
