*Author: [Dredsen](https://dredsen.github.io/)*

---

[Wetty](https://github.com/butlerx/wetty) is a web-based terminal that lets you access an SSH session through the browser. It is the kind of project where a client-side bug can get serious quickly, because the browser page is directly connected to a live shell.

I reported a DOM XSS in Wetty's file-download handling that was published as [CVE-2026-49864](https://github.com/butlerx/wetty/security/advisories/GHSA-p26j-h7wj-r568). It affects versions before `3.0.4` and was fixed in `3.0.4`.

The short version: Wetty supported a terminal escape sequence that lets terminal output trigger a file download. The filename from that sequence was decoded from base64, inserted into a Toastify notification as raw HTML, and rendered with escaping disabled.

That meant output shown inside the terminal could become JavaScript running in the Wetty page.

---

## What happened

Every byte from the SSH session gets passed through the Wetty client. The file-download feature watches that output for special markers:

```ts
const fileDownloader = new FileDownloader();

socket.on('data', (data: string) => {
  const remainingData = fileDownloader.buffer(data);
});
```

When a complete file-download sequence is found, Wetty decodes the filename and creates a toast:

```ts
if (fileNameBase64 !== undefined) {
  fileName = window.atob(fileNameBase64);
}

Toastify({
  text: `Download ready: <a href="${blobUrl}" target="_blank" download="${fileName}">${fileName}</a>`,
  duration: 10000,
  escapeMarkup: false,
}).showToast();
```

The dangerous part is the combination of:

- attacker-controlled filename
- direct interpolation into an HTML string
- `escapeMarkup: false`

No HTML escaping happened between `atob()` and the toast markup.

## Why it mattered

Normally, terminal output should be terminal output. It should not be able to run JavaScript in the browser.

In this case, if an attacker could get a victim to render the file-download escape sequence inside Wetty, the filename could break out of the toast HTML and inject script. That script ran in the Wetty origin.

That mattered because Wetty exposed the live terminal object on the page. Script running in the page could type into the victim's SSH session:

```text
terminal output contained a crafted file-download sequence
Wetty decoded the filename
Toastify rendered the filename as raw HTML
injected JavaScript ran in the Wetty page
JavaScript typed commands into the active SSH session
```

The advisory demonstrated this by writing a command into the shell and confirming the command ran as the connected SSH user.

The scarier version is a shared host. A lower-privileged user could plant the sequence in a file or log. If a higher-privileged user opened that content through Wetty, the browser-side XSS could type commands into the higher-privileged user's terminal.

## Impact

The published advisory rated this as High severity with CVSS `8.6`.

The impact was not just "show an alert box." Because the vulnerable page is a live web terminal, JavaScript in that origin could:

- read rendered terminal contents
- type attacker-chosen input into the SSH session
- turn content the victim viewed into commands run as that victim's shell user

That is the part that made this interesting to me. The XSS sink was a toast notification, but the real target was the terminal behind it.

## Fix

The direct fix was to HTML-escape the decoded filename before putting it into the Toastify string:

```ts
const safeName = fileName.replace(/[&<>"']/g, (c) =>
  ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c] ?? c,
);

Toastify({
  text: `Download ready: <a href="${blobUrl}" target="_blank" download="${safeName}">${safeName}</a>`,
  duration: 10000,
  escapeMarkup: false,
}).showToast();
```

An even cleaner pattern would be building the notification with DOM APIs instead of string HTML, but escaping the filename removes the injection point.

## Final notes

This was published as [GHSA-p26j-h7wj-r568](https://github.com/butlerx/wetty/security/advisories/GHSA-p26j-h7wj-r568) / [CVE-2026-49864](https://github.com/advisories/GHSA-p26j-h7wj-r568). Users should update Wetty to `3.0.4` or later.
