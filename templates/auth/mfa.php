<?php /** @var \MailPanel\Web\View $view */ $title = 'Ověřovací kód'; ?>
<section class="card narrow">
  <h1>Ověřovací kód</h1>
  <p class="muted">Zadejte 6místný kód z ověřovací aplikace v telefonu.</p>
  <?php if ($error): ?><div class="alert alert-error" role="alert"><?= $view->e($error) ?></div><?php endif; ?>
  <form method="post" action="<?= $view->e($view->url('/login/mfa')) ?>" class="stack">
    <?= $view->csrf() ?>
    <label>Kód
      <input name="code" inputmode="numeric" pattern="[0-9 ]{6,7}" maxlength="7" autocomplete="one-time-code" required autofocus class="code">
    </label>
    <button class="primary">Přihlásit</button>
  </form>
  <p class="small"><a href="<?= $view->e($view->url('/login')) ?>">Zpět</a> · Ztracený telefon? Požádejte správce o reset MFA.</p>
</section>
