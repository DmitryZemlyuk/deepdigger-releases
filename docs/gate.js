// Login gate: the game code is encrypted; the login and password are the key. A correct login is remembered on this device.
"use strict";
(function () {
  const KEY = 'deepdigger:gate';
  const form = document.getElementById('gate');
  const err = document.getElementById('gate-err');
  let blob = null;
  const data = fetch('game.bin?v=' + document.documentElement.dataset.v).then(r => r.arrayBuffer()).then(b => (blob = new Uint8Array(b)));

  async function decrypt(key) {
    await data;
    const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: blob.subarray(16, 28) }, key, blob.subarray(28));
    return new TextDecoder().decode(plain);
  }
  async function derive(login, pass) {
    await data;
    const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(login.trim().toLowerCase() + '\n' + pass), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey({ name: 'PBKDF2', salt: blob.subarray(0, 16), iterations: 250000, hash: 'SHA-256' }, base, { name: 'AES-GCM', length: 256 }, true, ['decrypt']);
  }
  function start(code) {
    form.remove();
    document.getElementById('loading').hidden = false;
    const s = document.createElement('script');
    s.src = URL.createObjectURL(new Blob([code], { type: 'text/javascript' }));
    document.body.appendChild(s);
  }
  async function tryStored() {
    let saved = null;
    try { saved = JSON.parse(localStorage.getItem(KEY) || 'null'); } catch (e) { /* ignore */ }
    if (saved) {
      try {
        const key = await crypto.subtle.importKey('jwk', saved, { name: 'AES-GCM' }, false, ['decrypt']);
        start(await decrypt(key));
        return;
      } catch (e) { /* credentials changed: ask again */ }
    }
    form.hidden = false;
    form.login.focus();
  }
  async function login(l, p) {
    try {
      const key = await derive(l, p);
      const code = await decrypt(key);
      try { localStorage.setItem(KEY, JSON.stringify(await crypto.subtle.exportKey('jwk', key))); } catch (e) { /* private mode */ }
      start(code);
    } catch (e) {
      err.textContent = 'Неверный логин или пароль';
      form.classList.remove('shake'); void form.offsetWidth; form.classList.add('shake');
    }
  }
  form.addEventListener('submit', e => {
    e.preventDefault();
    err.textContent = '';
    const b = form.querySelector('button');
    b.disabled = true;
    login(form.login.value, form.password.value).finally(() => { b.disabled = false; });
  });
  if (!window.crypto || !crypto.subtle) { form.hidden = false; err.textContent = 'Нужен HTTPS и современный браузер'; return; }
  tryStored();
})();
