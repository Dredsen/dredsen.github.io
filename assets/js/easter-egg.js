(function () {
  const trigger = document.getElementById('easter-egg');
  const modal = document.getElementById('egg-modal');
  const video = document.getElementById('egg-video');
  if (!trigger || !modal || !video) return;

  function open() {
    modal.hidden = false;
    document.body.style.overflow = 'hidden';
    video.currentTime = 0;
    video.play().catch(() => {});
  }

  function close() {
    modal.hidden = true;
    document.body.style.overflow = '';
    video.pause();
  }

  trigger.addEventListener('click', open);

  video.addEventListener('ended', close);

  modal.addEventListener('click', (e) => {
    if (e.target instanceof Element && e.target.hasAttribute('data-egg-close')) close();
  });

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && !modal.hidden) close();
  });
})();
