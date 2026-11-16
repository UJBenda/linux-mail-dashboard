<?php
/** @var \MailPanel\Web\View $view */
use MailPanel\Auth\Roles;
$title = 'Přehled';
?>
<h1>Přehled</h1>

<div class="grid">
  <section class="card">
    <h2>Mail server</h2>
    <p class="muted">Provoz, fronta, spam, stav služeb a grafy přibudou v dalších krocích
       (sběr logů → dashboard → fronta a karanténa).</p>
  </section>

  <section class="card">
    <h2>Stav panelu</h2>
    <dl class="kv">
      <dt>Databáze</dt><dd><span class="badge ok">připojeno</span></dd>
      <dt>Migrace</dt>
      <dd><?php if ($status['pending'] === []): ?><span class="badge ok">aktuální</span>
          <?php else: ?><span class="badge warn">čeká: <?= $view->e(implode(', ', $status['pending'])) ?></span><?php endif; ?></dd>
      <?php if ($status['audit'] !== null): ?>
      <dt>Integrita auditu</dt>
      <dd><?php if ($status['audit']['ok']): ?><span class="badge ok">v pořádku</span> <span class="muted small"><?= $view->e($status['audit']['count']) ?> záznamů</span>
          <?php else: ?><span class="badge bad">PORUŠENA u záznamu <?= $view->e($status['audit']['seq']) ?></span><?php endif; ?></dd>
      <?php endif; ?>
    </dl>
  </section>

  <section class="card">
    <h2>Můj účet</h2>
    <dl class="kv">
      <dt>Uživatel</dt><dd><?= $view->e($user['username']) ?> <span class="muted">(<?= $user['source'] === 'ad' ? 'AD' : 'nouzový účet' ?>)</span></dd>
      <dt>Role</dt><dd><?php foreach ($roles as $r): ?><span class="badge" title="<?= $view->e(Roles::DESCRIPTIONS[$r]) ?>"><?= $view->e(Roles::LABELS[$r]) ?></span> <?php endforeach; ?></dd>
    </dl>
    <h3>Poslední přihlášení</h3>
    <table class="compact">
      <?php foreach ($recent as $r): ?>
      <tr class="<?= $r['result'] === 'ok' ? '' : 'row-bad' ?>">
        <td><?= $view->e($view->dt($r['created_at'])) ?></td><td><?= $view->e($r['ip']) ?></td>
        <td><?= $view->e($r['action']) ?></td><td><?= $view->e($r['result']) ?></td>
      </tr>
      <?php endforeach; ?>
    </table>
  </section>
</div>
