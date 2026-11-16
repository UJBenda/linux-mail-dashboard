<?php /** @var \MailPanel\Web\View $view */ $title = 'Přihlášení'; ?>
<section class="card narrow">
  <h1><?= $view->e($appName) ?></h1>
  <p class="muted">Přihlaste se účtem Active Directory.</p>
  <?php if ($expired): ?><div class="alert alert-info">Přihlášení vypršelo, přihlaste se znovu.</div><?php endif; ?>
  <?php if ($error): ?><div class="alert alert-error" role="alert"><?= $view->e($error) ?></div><?php endif; ?>
  <form method="post" action="<?= $view->e($view->url('/login')) ?>" class="stack">
    <?= $view->csrf() ?>
    <label>Uživatelské jméno
      <input name="username" value="<?= $view->e($username) ?>" autocomplete="username" autocapitalize="none" spellcheck="false" required autofocus>
    </label>
    <label>Heslo
      <input name="password" type="password" autocomplete="current-password" required>
    </label>
    <button class="primary">Pokračovat</button>
  </form>
  <p class="muted small">Přístup je auditován. Neoprávněný přístup je zakázán.</p>
</section>
