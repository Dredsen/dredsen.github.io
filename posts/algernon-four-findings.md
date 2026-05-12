*Author: [Dredsen](https://dredsen.github.io/)*

---

Algernon is a small, self-contained web server written in Go. You point it at a directory and it serves whatever's there: Markdown, Lua, templates, static files, the lot. The pitch is "drop a single binary in a folder and you've got a working site." It's the kind of tool people reach for when they want zero-setup file serving without standing up nginx or a framework and just want something thats simple and works out of the box.

I decided to test out using AI Fuzzing with Qwen 3.6 35B with a custom harness on the main branch of Algernon 1.17.6 and ended up with four advisories. None of them require authentication, all of them work on a default install with no flags, and three of them are reachable just by running the documented quickstart inside a project folder.

---

## What I found

### 1. `handler.lua` discovery walks above the server root

When Algernon serves a directory, it looks for a `handler.lua` script to use as the request handler. If the current directory doesn't have one, the search walks **upward** through parent directories, past the configured server root, all the way toward the filesystem root.

The first `handler.lua` it finds gets loaded into the Lua interpreter with the full Algernon API exposed - file system, shell, HTTP client, database drivers. Anyone who can write a file at any ancestor path on disk gets pre-authenticated code execution on the next request.

Plant a `handler.lua` one directory above the served root and any unauthenticated request triggers it:

```
$ ./algernon site/
$ curl http://127.0.0.1:8080/
=== PWNED via parent handler.lua ===
Hostname: DESKTOP-4RLE5YR
```

The handler that lives one directory **above** `site/` (and was never part of the served tree) executed inside the Algernon process and its output became the HTTP 200 response body.

### 2. Auto-refresh SSE listener leaks edits across the network

The `-a` / `--autorefresh` flag spins up a second HTTP listener that streams a Server-Sent-Events feed of every filename the developer is editing. That listener:

- binds to all interfaces by default on Linux and macOS,
- sets `Access-Control-Allow-Origin: *` on every response,
- has no authentication and is not gated by the main permission system.

Anything on the same network can subscribe to a live transcript of your editor activity. Any web page you open in a browser can subscribe cross-origin. The leak is filenames and timing, not file contents, but it's still a real-time map of your project layout to anyone who asks.

```
$ curl -H "Origin: http://evil.example" http://127.0.0.1:5553/sse
HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
Content-Type: text/event-stream

id: 0
data: C:\Users\xbox\...\site\.env.local
```

The stream emits **absolute paths**, so it also leaks the developer's username, drive letter, and directory layout. No `Authorization`, no cookie, no token, and the `Origin: http://evil.example` header was happily reflected as a wildcard.

### 3. Default install serves dotfiles, including `.git` and `.env`

The documented quickstart is `algernon .` - point it at the current directory. If that directory is a git repository, the server happily serves `.git/config`, `.git/HEAD`, pack files, anything else under `.git/`. Same for `.env`, `.ssh`, `.htpasswd`, anything starting with a dot.

There's an opt-in `ignore.txt` mechanism, but it only hides files from the directory listing - the file handler itself still serves them when the URL is requested directly. So patterns in `ignore.txt` cover one half of the exposure and leave the other half wide open.

```
$ curl http://127.0.0.1:8080/.env
DATABASE_URL=postgres://app:hunter2@db.internal:5432/prod
SECRET_KEY_BASE=fake-jwt-signing-secret-for-poc-only

$ curl http://127.0.0.1:8080/.git/config
[core]
        repositoryformatversion = 0
[remote "origin"]
        url = git@github.com:internal/private-repo.git
```

Both came back unauthenticated. The `.env` was on the `ignore.txt` block-list and still served - the listing hid it, the file handler didn't care.

### 4. Single-file mode forces debug mode

Algernon has a "single file" shortcut: `algernon foo.po2` or `algernon page.html` to demo one file without setting up a directory. This mode unconditionally sets `debugMode = true`, no opt-out.

`debugMode` turns on the pretty error page, which on any script or template error dumps the full server-side source of the file being rendered, line-by-line, with the absolute filesystem path. If the served file contains secrets (API keys hardcoded into a Lua script, database credentials in a template), a single malformed request that triggers an error is enough to leak them.

```
$ ./algernon page.po2     # page.po2 references data.lua, which has a parse error
$ curl http://127.0.0.1:8080/
<title>Lua Error</title>
...
Contents of data.lua:
local SECRET = "sk-LEAKCANARY-DATALUA-PRIVATE"
this is intentionally bad lua
```

The `SECRET` from `data.lua` ended up in the HTML response of an unauthenticated `GET /`. No debug flag was passed - single-file mode turned it on by itself.

---
## Disclosure

All four were reported privately to the maintainer and patched within 24 hours. Thanks to [xyproto](https://github.com/xyproto) for the quick turnaround, [Here are the in-depth reports for CVE/GHSA](https://github.com/xyproto/algernon/security).
