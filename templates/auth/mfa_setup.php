<?php /** @var \MailPanel\Web\View $view */ $title = 'Nastavení dvoufázového ověření'; ?>
<section class="card narrow">
  <h1>Nastavení dvoufázového ověření</h1>
  <p>Přístup do panelu vyžaduje druhý faktor. Naskenujte kód v ověřovací aplikaci
     (Microsoft Authenticator, Google Authenticator, FreeOTP, Aegis…) a opište vygenerovaný kód.</p>
  <?php if ($error): ?><div class="alert alert-error" role="alert"><?= $view->e($error) ?></div><?php endif; ?>
  <div class="qr" data-qr="<?= $view->e($uri) ?>" aria-label="QR kód pro ověřovací aplikaci"></div>
  <p class="small muted">Nelze naskenovat? Zadejte klíč ručně:</p>
  <p><code class="secret"><?= $view->e($secret) ?></code></p>
  <form method="post" action="<?= $view->e($view->url('/login/mfa-setup')) ?>" class="stack">
    <?= $view->csrf() ?>
    <label>Kód z aplikace
      <input name="code" inputmode="numeric" pattern="[0-9 ]{6,7}" maxlength="7" autocomplete="one-time-code" required class="code">
    </label>
    <button class="primary">Potvrdit a přihlásit</button>
  </form>
</section>
<script src="<?= $view->e($view->asset('vendor/qrcode-1.4.4.js')) ?>" defer></script>
