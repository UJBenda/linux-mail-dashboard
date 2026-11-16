<?php
/** @var \MailPanel\Web\View $view */
/** @var array<string,mixed>|null $user */
$nav = [
    ['/', 'Přehled', 'dashboard.view'],
    ['/admin/audit', 'Audit', 'audit.view'],
    ['/admin/users', 'Uživatelé', 'users.manage'],
];
?><!doctype html>
<html lang="cs">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title><?= $view->e(($title ?? '') !== '' ? $title . ' – ' . $appName : $appName) ?></title>
<link rel="stylesheet" href="<?= $view->e($view->asset('app.css')) ?>">
<script src="<?= $view->e($view->asset('app.js')) ?>" defer></script>
</head>
<body>
<?php if ($user): ?>
<header class="topbar">
  <a class="brand" href="<?= $view->e($view->url('/')) ?>"><?= $view->e($appName) ?></a>
  <nav>
    <?php foreach ($nav as [$href, $label, $perm]): if (!$view->can($perm)) continue; ?>
      <a href="<?= $view->e($view->url($href)) ?>"<?= $path === $href ? ' aria-current="page"' : '' ?>><?= $view->e($label) ?></a>
    <?php endforeach; ?>
  </nav>
  <div class="who">
    <span title="<?= $view->e($user['roles']) ?>"><?= $view->e($user['display_name'] ?: $user['username']) ?></span>
    <form method="post" action="<?= $view->e($view->url('/logout')) ?>"><?= $view->csrf() ?><button class="link">Odhlásit</button></form>
  </div>
</header>
<?php endif; ?>
<main class="<?= $user ? 'page' : 'center' ?>">
<?php if (!empty($flash)): ?>
  <div class="alert alert-<?= $view->e($flash['type']) ?>"><?= $view->e($flash['message']) ?></div>
<?php endif; ?>
<?= $content ?>
</main>
</body>
</html>
