*Author: [Dredsen](https://dredsen.github.io/)*

---

[Umami](https://github.com/umami-software/umami) is a self-hosted web analytics platform. It is the kind of tool people run when they want something lighter and more privacy-friendly than Google Analytics.

I looked at Umami `3.1.0` and reported two issues privately. Both were in places where the code looked normal at first glance, but the security property depended on a small detail being correct.

The first issue was session logout not actually revoking Redis-backed sessions. The second was predictable random values being used for team access codes and public share slugs.

Both were accepted by the maintainer and fixed in `v3.2`.

---

## What I reported

The two reports were:

- Logout does not revoke Redis-backed sessions
- Predictable PRNG for team access codes and share slugs

## 1. Logout did not revoke Redis-backed sessions

Umami can use Redis as a server-side session store. In that setup, logging out should delete the server-side session entry so the token stops working immediately.

The issue was a key mismatch.

When the session was created, Umami stored it under a Redis key like `auth:<random>`. The token given to the browser was an encrypted JWT that contained that `authKey`.

The logout route did not decrypt the token to recover the Redis key. It deleted the token string itself:

```ts
if (redis.enabled) {
  const token = request.headers.get('authorization')?.split(' ')?.[1];

  await redis.client.del(token);
}
```

But the actual session was stored like this:

```ts
const authKey = `auth:${createAuthKey()}`;

await redis.client.set(authKey, data);

return createSecureToken({ authKey }, secret());
```

So logout was deleting a Redis key named after the encrypted JWT, but that key never existed. The real `auth:<random>` key stayed in Redis until the normal TTL expired.

The result was pretty direct:

```text
login returned a token
POST /api/auth/logout returned 200
the same token still authenticated after logout
the auth:* Redis key was still present
```

This mattered most when a token was copied or leaked before logout. A user could press logout on a shared machine or after noticing something suspicious, but anyone holding the token could still use it for up to the Redis session TTL. In the tested version, that window was one hour.

The fix was to decrypt the token, pull out the `authKey`, and delete that key instead of deleting the opaque JWT string.

## 2. Predictable team access codes and share slugs

The second issue was in random value generation.

Umami used `pure-rand` and seeded one shared `xoroshiro128plus` generator when the module loaded:

```ts
const seed = Date.now() ^ (Math.random() * 0x100000000);
const rng = prand.xoroshiro128plus(seed);

export function random(min: number, max: number) {
  return prand.unsafeUniformIntDistribution(min, max, rng);
}

export function getRandomChars(n: number, chars = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ') {
  const arr = chars.split('');
  let s = '';

  for (let i = 0; i < n; i++) {
    s += arr[random(0, arr.length - 1)];
  }

  return s;
}
```

That function was used for values that needed to be secret, including team access codes:

```ts
accessCode: `team_${getRandomChars(16)}`
```

The problem is that `xoroshiro128plus` is not a cryptographic random generator, and the seed effectively collapsed down to a 32-bit value because of JavaScript's bitwise behavior. Once an attacker could observe one generated access code, they could recover or brute-force the generator state and predict later values from the same process.

For a normal user, the path was:

```text
create a team
observe your own team access code
recover the generator state from that code
predict a future team access code
join that team with POST /api/teams/join
```

In the report, the predicted code matched the next generated team code exactly. That meant a regular user could join a team they were never invited to if they predicted the access code.

Team membership mattered because a `teamMember` could access and mutate websites owned by that team. So this was not just guessing a vanity invite code. It crossed a tenant boundary inside the app.

The safer fix was to use Node's `crypto` APIs for anything security-sensitive:

```ts
import crypto from 'node:crypto';

export function random(min: number, max: number) {
  return crypto.randomInt(min, max + 1);
}
```

Random-looking is not the same thing as secret. If a value controls access, it needs cryptographic randomness.

## Final notes

Thanks to the Umami maintainer for accepting the reports and fixing them quickly.
