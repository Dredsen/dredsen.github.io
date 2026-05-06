(async function () {
  const list = document.getElementById('post-list');

  try {
    const res = await fetch('posts/index.json', { cache: 'no-cache' });
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const posts = await res.json();

    if (!Array.isArray(posts) || posts.length === 0) {
      list.innerHTML = '<li class="empty">No posts yet.</li>';
      return;
    }

    posts.sort((a, b) => (b.date || '').localeCompare(a.date || ''));

    list.innerHTML = '';
    for (const p of posts) {
      const li = document.createElement('li');
      li.className = 'post-card';

      const h2 = document.createElement('h2');
      const a = document.createElement('a');
      a.href = 'post.html?p=' + encodeURIComponent(p.slug);
      a.textContent = p.title || p.slug;
      h2.appendChild(a);

      const meta = document.createElement('p');
      meta.className = 'post-meta';
      meta.textContent = p.date || '';

      const summary = document.createElement('p');
      summary.className = 'post-summary';
      summary.textContent = p.summary || '';

      li.appendChild(h2);
      li.appendChild(meta);
      if (p.summary) li.appendChild(summary);
      list.appendChild(li);
    }
  } catch (err) {
    list.innerHTML = '<li class="error">Failed to load posts: ' + err.message + '</li>';
  }
})();
