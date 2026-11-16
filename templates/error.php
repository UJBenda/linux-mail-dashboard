<?php /** @var \MailPanel\Web\View $view */ ?>
<section class="card narrow">
  <h1><?= $view->e($status) ?> – <?= $view->e($title) ?></h1>
  <?php if ($message !== ''): ?><p><?= $view->e($message) ?></p><?php endif; ?>
  <p><a href="<?= $view->e($view->url('/')) ?>">Zpět na přehled</a></p>
</section>
