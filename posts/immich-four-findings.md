*Author: [Dredsen](https://dredsen.github.io/)*

---

[Immich](https://github.com/immich-app/immich) is a self-hosted photo and video backup app. Think Google Photos, but running on your own server.

That makes it a pretty interesting target to review. It handles login, OAuth, shared albums, download links, email templates, profile pictures, and a lot of personal data. Photos are not just random files. They are usually some of the most private things people store.

I spent some time looking through Immich `v2.7.5` and ended up reporting four issues privately. This post is the short version of what I found.

I am keeping this simple on purpose. The private reports had the deeper technical details, and I do not think every blog post needs to be a wall of code. I did include a little bit of code and test output here though, because it makes the bugs easier to understand.

---

## What I reported

The four reports were:

- Shared-link auth bypass
- OAuth account takeover
- Plaintext shared-link passwords
- OAuth profile-picture SSRF

## 1. Shared-link auth bypass

Immich has a shared-link feature that lets you share photos or albums with someone else. You can also put a password on the share, which should mean that only people with the link and the password can view or download the content.

The issue was that the password check only happened on the login-style shared-link endpoints. The actual content routes still trusted the share key in the URL. So if someone had the share URL, they could reach the photos behind a password-protected share without supplying the password.

The rough shape of the vulnerable path was:

```ts
const sharedLink = await this.sharedLinkRepository.getByKey(bytes);

if (!this.isValidSharedLink(sharedLink)) {
  throw new UnauthorizedException('Invalid share key');
}

return { user: sharedLink.user, sharedLink };
```

That checks whether the share key exists and is valid, but it does not check whether the share has a password or whether the requester has passed that password check.

The result looked like this:

```text
POST /api/shared-links/login?key=... with the wrong password -> 401
GET  /api/assets/.../original?key=... with no password        -> 200
```

This is the one I considered the biggest problem. Shared links leak in boring ways all the time: browser history, screenshots, link previews, referer logs, chat apps, and other places people do not normally think about. If the password is not enforced on the content routes, the password protection mostly becomes a UI promise rather than real access control.

## 2. OAuth account takeover

This one depended on how the Immich instance was configured.

When a user signed in with OAuth for the first time, Immich could link that OAuth identity to an existing local account if the email address matched. The missing piece was checking whether the OAuth provider had actually verified that email address.

The code path was basically:

```ts
let user = await this.userRepository.getByOAuthId(profile.sub);

if (!user && normalizedEmail) {
  const emailUser = await this.userRepository.getByEmail(normalizedEmail);

  if (emailUser && !emailUser.oauthId) {
    user = await this.userRepository.update(emailUser.id, {
      oauthId: profile.sub,
    });
  }
}
```

The missing check was the boring but important one:

```ts
profile.email_verified === true
```

If an identity provider allowed users to register with unverified email addresses, an attacker could register at the provider using someone else's email and then sign in to Immich. Immich would see the email match, link the OAuth identity, and issue a session for the existing account.

The test result was the important part:

```text
OIDC profile email matched an existing local account
email_verified was false or not enforced
Immich linked the OAuth identity anyway
```

That turns into account takeover on instances where the identity provider allows unverified-email signup. It is conditional, but when the conditions line up, the impact is pretty obvious.

## 3. Plaintext shared-link passwords

While looking at the shared-link code, I also noticed that shared-link passwords were stored differently from normal user passwords.

User passwords were hashed properly. Shared-link passwords were stored as plaintext, compared as plaintext, and returned by the API as a string. The response schema made it look like the field was meant to be a boolean for "has password", but the implementation exposed the actual password value.

The comparison was the first clue:

```ts
if (password !== dto.password) {
  throw new UnauthorizedException('Invalid password');
}
```

The bigger issue was that the password could come back in API responses as the actual string:

```json
{
  "id": "shared-link-id",
  "password": "example-share-password"
}
```

This did not give an attacker access by itself, but it made every read primitive worse. A database backup, a compromised API key with shared-link read access, or a future bug that exposed shared-link rows could leak the passwords directly.

Passwords should not come back out of the API like that. Even temporary sharing passwords deserve the same basic treatment: hash them, compare them safely, and only expose whether a password exists.

## 4. OAuth profile-picture SSRF

On first OAuth login, Immich downloaded the user's profile picture from the URL supplied by the OAuth provider.

The issue was that the URL was fetched without enough validation. There was no meaningful restriction around private IP ranges, local network addresses, protocol handling, response size, or content type before the server made the request.

The flow was roughly:

```ts
if (!user.profileImagePath && profile.picture) {
  await this.syncProfilePicture(user, profile.picture);
}
```

Then the repository fetched the URL directly:

```ts
async getProfilePicture(url: string) {
  const response = await fetch(url);

  return {
    data: await response.arrayBuffer(),
    contentType: response.headers.get('content-type'),
  };
}
```

That makes it a blind SSRF in most cases. The attacker usually cannot read the response body because Immich expects the result to be an image, but the server-side request still happens from the Immich host's network. That can be enough to probe internal services or hit endpoints that should not be reachable from the outside.

The test result was simple:

```text
profile.picture = internal URL
OAuth login happened
Immich attempted to fetch that URL from the server side
image decode failed later, but the request had already fired
```

The usual fix here is the standard SSRF checklist: restrict protocols, resolve and block private IP ranges, limit redirects, cap response size, require image content types, and treat identity-provider profile fields as untrusted input.

## Final notes

Thanks to the Immich team for handling the reports.
