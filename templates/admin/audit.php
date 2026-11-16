<?php /** @var \MailPanel\Web\View $view */ $title = 'Auditní záznam'; ?>
<h1>Auditní záznam</h1>

<?php if ($verify !== null): ?>
  <?php if ($verify['ok']): ?>
    <div class="alert alert-success">Řetěz integrity je v pořádku (<?= $view->e($verify['count']) ?> záznamů).
      Hlava: <code><?= $view->e($verify['head']) ?></code></div>
  <?php else: ?>
    <div class="alert alert-error">Integrita PORUŠENA u záznamu <?= $view->e($verify['seq']) ?>: <?= $view->e($verify['problem']) ?>.
      Jde o bezpečnostní událost – postupujte podle plánu řešení incidentů.</div>
  <?php endif; ?>
<?php endif; ?>

<form method="get" class="filters">
  <input name="user" placeholder="uživatel" value="<?= $view->e($filter['user']) ?>">
  <select name="action">
    <option value="">všechny akce</option>
    <?php foreach ($actions as $a): ?><option<?= $a === $filter['action'] ? ' selected' : '' ?>><?= $view->e($a) ?></option><?php endforeach; ?>
  </select>
  <select name="result">
    <option value="">výsledek</option>
    <?php foreach (['ok', 'fail', 'denied'] as $r): ?><option<?= $r === $filter['result'] ? ' selected' : '' ?>><?= $r ?></option><?php endforeach; ?>
  </select>
  <input name="ip" placeholder="IP nebo rozsah CIDR" value="<?= $view->e($filter['ip']) ?>">
  <input name="from" type="date" value="<?= $view->e($filter['from']) ?>" title="od">
  <input name="to" type="date" value="<?= $view->e($filter['to']) ?>" title="do">
  <button>Filtrovat</button>
  <a class="button" href="<?= $view->e($view->url('/admin/audit', array_filter($filter) + ['format' => 'csv'])) ?>">Export CSV</a>
  <a class="button" href="<?= $view->e($view->url('/admin/audit', ['verify' => 1])) ?>">Ověřit integritu</a>
</form>

<p class="muted small"><?= $view->e($total) ?> záznamů</p>
<div class="table-wrap">
<table>
  <thead><tr><th>#</th><th>Čas</th><th>Uživatel</th><th>IP</th><th>Akce</th><th>Výsledek</th><th>Podrobnosti</th></tr></thead>
  <tbody>
  <?php foreach ($rows as $r): ?>
    <tr class="<?= $r['result'] === 'ok' ? '' : 'row-bad' ?>">
      <td class="num"><?= $view->e($r['seq']) ?></td>
      <td class="nowrap"><?= $view->e($view->dt($r['created_at'])) ?></td>
      <td><?= $view->e($r['username']) ?></td>
      <td class="nowrap"><?= $view->e($r['ip']) ?></td>
      <td><?= $view->e($r['action']) ?></td>
      <td><?= $view->e($r['result']) ?></td>
      <td><code class="small"><?= $view->e($r['details'] === '{}' ? '' : $r['details']) ?></code></td>
    </tr>
  <?php endforeach; ?>
  </tbody>
</table>
</div>
<?php if ($pages > 1): ?>
<nav class="pager">
  <?php if ($page > 1): ?><a href="<?= $view->e($view->url('/admin/audit', array_filter($filter) + ['page' => $page - 1])) ?>">‹ novější</a><?php endif; ?>
  <span>strana <?= $view->e($page) ?> / <?= $view->e($pages) ?></span>
  <?php if ($page < $pages): ?><a href="<?= $view->e($view->url('/admin/audit', array_filter($filter) + ['page' => $page + 1])) ?>">starší ›</a><?php endif; ?>
</nav>
<?php endif; ?>
