(async function () {
  const article = document.getElementById('post');

  const params = new URLSearchParams(window.location.search);
  const slug = params.get('p');

  if (!slug || !/^[a-z0-9][a-z0-9\-_]*$/i.test(slug)) {
    article.innerHTML = '<p class="error">Invalid or missing post slug.</p>';
    return;
  }

  try {
    const [mdRes, idxRes] = await Promise.all([
      fetch('posts/' + slug + '.md', { cache: 'no-cache' }),
      fetch('posts/index.json', { cache: 'no-cache' })
    ]);

    if (!mdRes.ok) throw new Error('Post not found.');
    const md = await mdRes.text();

    let meta = { title: slug, date: '' };
    if (idxRes.ok) {
      const posts = await idxRes.json();
      const found = posts.find(p => p.slug === slug);
      if (found) meta = { ...meta, ...found };
    }

    const rawHtml = window.marked.parse(md);
    const cleanHtml = window.DOMPurify.sanitize(rawHtml);

    article.innerHTML = '';

    const header = document.createElement('header');
    const h1 = document.createElement('h1');
    h1.textContent = meta.title;
    header.appendChild(h1);
    if (meta.date) {
      const date = document.createElement('p');
      date.className = 'post-meta';
      date.innerHTML = '<span class="date-chip">' + meta.date + '</span>';
      header.appendChild(date);
    }
    article.appendChild(header);

    const body = document.createElement('div');
    body.innerHTML = cleanHtml;
    article.appendChild(body);

    document.title = meta.title + ' — // 0xDEADBEEF';
  } catch (err) {
    article.innerHTML = '<p class="error">Failed to load post: ' + err.message + '</p>';
  }
})();
