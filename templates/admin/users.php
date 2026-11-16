<?php /** @var \MailPanel\Web\View $view */ use MailPanel\Auth\Roles; $title = 'Uživatelé panelu'; ?>
<h1>Uživatelé panelu</h1>
<p class="muted">Účty AD vznikají při prvním přihlášení; role se při každém přihlášení přebírají ze skupin AD.
   Nouzový lokální účet se zakládá jen z příkazové řádky (<code>bin/mailpanel user:local</code>).</p>
<div class="table-wrap">
<table>
  <thead><tr><th>Uživatel</th><th>Zdroj</th><th>Role</th><th>MFA</th><th>Poslední přihlášení</th><th>Stav</th><th></th></tr></thead>
  <tbody>
  <?php foreach ($users as $u): ?>
    <tr class="<?= $u['is_active'] ? '' : 'row-muted' ?>">
      <td><strong><?= $view->e($u['username']) ?></strong><br><span class="muted small"><?= $view->e($u['display_name']) ?></span></td>
      <td><?= $u['source'] === 'ad' ? 'AD' : 'lokální' ?></td>
      <td><?php foreach (Roles::parse((string) $u['roles']) as $r): ?><span class="badge"><?= $view->e(Roles::LABELS[$r]) ?></span> <?php endforeach; ?>
          <?php if ($u['roles'] === ''): ?><span class="muted">žádná</span><?php endif; ?></td>
      <td><?= $u['mfa_enrolled_at'] ? '<span class="badge ok">ano</span>' : '<span class="badge warn">ne</span>' ?></td>
      <td class="nowrap"><?= $view->e($view->dt($u['last_login_at'])) ?><br><span class="muted small"><?= $view->e($u['last_login_ip']) ?></span></td>
      <td><?= $u['is_active'] ? 'povolen' : 'zakázán' ?></td>
      <td class="actions">
        <?php if ($u['mfa_enrolled_at']): ?>
        <form method="post" action="<?= $view->e($view->url('/admin/users/' . $u['id'] . '/mfa-reset')) ?>" data-confirm="Zrušit MFA uživatele <?= $view->e($u['username']) ?>? Při příštím přihlášení si ho nastaví znovu.">
          <?= $view->csrf() ?><button class="small">Reset MFA</button>
        </form>
        <?php endif; ?>
        <?php if ((int) $u['id'] !== (int) $user['id']): ?>
        <form method="post" action="<?= $view->e($view->url('/admin/users/' . $u['id'] . '/active')) ?>">
          <?= $view->csrf() ?><input type="hidden" name="active" value="<?= $u['is_active'] ? '0' : '1' ?>">
          <button class="small"><?= $u['is_active'] ? 'Zakázat' : 'Povolit' ?></button>
        </form>
        <?php endif; ?>
      </td>
    </tr>
  <?php endforeach; ?>
  </tbody>
</table>
</div>
