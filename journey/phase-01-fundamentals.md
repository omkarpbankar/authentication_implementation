# Phase 1: Identity Fundamentals

**Goal:** Understand how login works before using any big tools.
**Time:** About 6 hours. Take it one section at a time.
**Code:** [apps/phase1_fundamentals/](../apps/phase1_fundamentals/)

---

## 1. Who are you, and what may you do?

Imagine checking in to a hotel.

- At the front desk, you show your ID. That is **authentication**: proving who you are.
- Your key card opens your room but not other rooms. That is **authorization**: what you are allowed to do.

The hotel analogy stops there, but the separation is the most important idea in this course. A person can be fully authenticated and still not be allowed to do something.

| Status code | Meaning | Hotel version |
|---|---|---|
| **401** | We do not know who you are | No key card |
| **403** | We know who you are, and you may not do this | Your card, wrong room |

**Ways to prove identity** come in three types:

- Something you **know**, like a password.
- Something you **have**, like your phone.
- Something you **are**, like a fingerprint.

Using two different types is multi-factor authentication. Two passwords would still be only one type.

---

## 2. The web forgets you instantly

Web traffic uses HTTP, and HTTP is **stateless**: every request stands alone, and the server remembers nothing from the last one.

Imagine a shop assistant who forgets you each time you blink. You would need to prove who you are on every single request. Sending a password with every click would be slow and risky, so the web uses a trick.

**The cookie.** After you log in, the server gives your browser a small value. The browser sends it back on every later request, like showing a wristband at an event.

**The session.** The cookie holds a long random ID. The server keeps the real record:

```
Browser cookie:   session_id = kX9f2...   (means nothing by itself)
Redis:            session:kX9f2... -> {"username": "asha"}
```

This is like a coat check ticket. The ticket is worthless without the record behind the counter, and the counter can cancel it at any moment.

---

## 3. Four ideas people mix up

| Idea | What it does | Reversible? | Needs a key? | Example |
|---|---|---|---|---|
| **Encoding** | Changes format | Yes, by anyone | No | Base64 |
| **Encryption** | Hides data | Yes, with the key | Yes | HTTPS |
| **Hashing** | Makes a one-way fingerprint | No | No | Password storage |
| **Signing** | Proves who made it and that it is unchanged | Not about hiding | Yes | JWT signature |

**Why are passwords hashed, not encrypted?** Encryption can be reversed, so a stolen key would reveal every password. A hash cannot be reversed. At login, the server hashes what you typed and compares fingerprints.

**Why use a slow hash?** Attackers who steal a database guess passwords by hashing billions of candidates. SHA-256 is built to be fast, which helps them. Argon2id is built to be slow and to use a lot of memory, so your login takes a fraction of a second, while billions of guesses become hugely expensive.

**What is a salt?** A random value added to each password before hashing, so two people with the same password get different hashes. Argon2id handles this for you.

---

## 4. Hands-on: Exercise 1, HTTP Basic

HTTP Basic is the simplest login there is: the browser sends a username and password on every request.

Open [exercise1_basic_auth.py](../apps/phase1_fundamentals/exercise1_basic_auth.py) and read the comments. Then start it:

```powershell
uv run uvicorn apps.phase1_fundamentals.exercise1_basic_auth:app --port 8101
```

In a second terminal, try these:

```powershell
curl.exe -i http://localhost:8101/public
curl.exe -i http://localhost:8101/secret
curl.exe -i -u asha:wrong http://localhost:8101/secret
curl.exe -i -u asha:correct-horse-battery http://localhost:8101/secret
```

Now see what actually travels over the network:

```powershell
curl.exe -v -u asha:correct-horse-battery http://localhost:8101/secret
```

Find the `Authorization: Basic ...` line, copy the value after `Basic`, and decode it:

```powershell
uv run python -c "import base64; print(base64.b64decode('PASTE_VALUE_HERE').decode())"
```

Your password appears. Base64 is not protection, so Basic is only safe over HTTPS, and even then the password is sent on every request.

Press `Ctrl+C` in the first terminal when you are finished.

---

## 5. Cookie safety settings

| Setting | What it does | Protects against |
|---|---|---|
| `HttpOnly` | JavaScript cannot read the cookie | Scripts stealing it through XSS |
| `Secure` | Sent only over HTTPS | Network eavesdropping |
| `SameSite` | Limits sending on requests started by other sites | Much of CSRF |
| `Max-Age` | Sets when it expires | Forgotten long-lived logins |

`HttpOnly` stops a script from *reading* the cookie. It does not stop a script already running on the page from *using* the site as you, because the browser still attaches the cookie. So it reduces the damage from XSS, but it does not remove it.

---

## 6. Hands-on: Exercise 2, sessions in Redis

Open [exercise2_sessions.py](../apps/phase1_fundamentals/exercise2_sessions.py), then start it:

```powershell
docker compose up -d --wait
uv run uvicorn apps.phase1_fundamentals.exercise2_sessions:app --port 8102
```

In a second terminal, sign in and save the cookie to a file:

```powershell
curl.exe -i -c cookies.txt -d "username=asha&password=correct-horse-battery" http://localhost:8102/login
curl.exe -b cookies.txt http://localhost:8102/me
```

See the session stored on the server:

```powershell
docker compose exec redis redis-cli --scan --pattern "session:*"
```

**Try stealing your own session.** Copy the cookie file, log out with the original, and try the copy:

```powershell
Copy-Item cookies.txt stolen.txt
curl.exe -X POST -b cookies.txt http://localhost:8102/logout
curl.exe -i -b stolen.txt http://localhost:8102/me
```

You get `401`, even though `stolen.txt` still holds the same cookie, because the server's record is gone.

Delete both files when you finish: `Remove-Item cookies.txt, stolen.txt`

---

## 7. Sessions vs tokens

You will build tokens in Phase 2, but keep this in mind now.

| | Server-side session | JWT |
|---|---|---|
| Where is the data? | On the server | Inside the token |
| Check on each request | Look it up | Verify the signature |
| Can it be cancelled at once? | Yes, delete the record | Not by default |
| A stolen one works until | It is deleted or expires | It expires |

Neither is always better. Sessions are easy to cancel. Tokens let other services check them without a shared database.

---

## 8. Attacks to know

| Attack | In plain words | Main defense |
|---|---|---|
| **Credential stuffing** | Reusing leaked passwords on other sites | MFA, breached-password checks, rate limits |
| **Phishing** | A fake login page | Passkeys, MFA |
| **XSS** | Attacker's script runs on your site | Escape output, Content Security Policy |
| **CSRF** | Another site triggers your browser | CSRF tokens, `SameSite` |
| **Session fixation** | Attacker plants a known session ID | New session ID at login |
| **User enumeration** | Error messages reveal who has an account | Identical responses |
| **Replay** | Reusing a captured message | Expiry, single-use values |
| **Token theft** | Copying a credential | Short lifetimes, safe storage |

Our code already defends against some of these. Look for the comments about identical errors and creating a new session ID at login.

---

## 9. Hands-on: Exercise 3, the CSRF lab

**The idea.** Your browser attaches cookies automatically. If you are signed in to your bank and visit a malicious page, that page can make your browser send a request to the bank, and the cookie may go along for the ride. The attacker cannot see the cookie. They do not need to.

**What counts as "the same site"?** `SameSite` compares the domain and ignores ports. So `localhost:8103` and `localhost:8104` count as the same site, and this lab uses `127.0.0.1` for the attacker, which counts as a different site.

Start the bank and the attacker page in two terminals:

```powershell
uv run uvicorn apps.phase1_fundamentals.csrf_lab.bank:app --host localhost --port 8103
```

```powershell
uv run python -m http.server 8104 --bind 127.0.0.1 --directory apps/phase1_fundamentals/csrf_lab/evil_site
```

Now run the attacks in your browser:

1. Open http://localhost:8103 (use `localhost`), click **Sign in**, and note the balance of 1000.
2. Open http://127.0.0.1:8104 in a new tab.
3. Click **Claim prize A**. You see "Not signed in".
4. Go back to the attacker page and click **Claim prize B**. You see "Sent 100 to attacker".
5. Refresh the bank tab. The balance is now 900, and you clicked only a link.
6. Go back and click **Claim prize C**. It is blocked as well.

**What happened?** The cookie uses `SameSite=Lax`:

| Attack | Request | Cookie sent? | Result |
|---|---|---|---|
| A | POST from another site | No | Blocked |
| B | GET from clicking a link | **Yes** | **Money moved** |
| C | POST from another site | No | Blocked |

`Lax` still sends cookies on top-level GET navigations, because otherwise following a link to a site would show you as signed out. That is why the real bug in Attack B is using a **GET request to change data**. GET should only read.

**The fix has two parts.** See `safe_transfer` in [bank.py](../apps/phase1_fundamentals/csrf_lab/bank.py).

1. Use POST for anything that changes data.
2. Require a CSRF token: a random value the bank puts in its own form. The attacker's page cannot read the bank's page, because browsers block that, so it cannot include the right value.

Attack C was stopped by `SameSite` first, so the token did not get tested in the browser. The tests in [test_csrf_lab.py](../tests/phase1/test_csrf_lab.py) send the cookie directly, and show the token blocks the request even if a cookie arrives. Run them with:

```powershell
uv run pytest tests/phase1 -v
```

This lab is for your own machine. Using these techniques on systems you do not own is illegal.

---

## 10. Write it in your own words

Fill in [docs/01-fundamentals.md](../docs/01-fundamentals.md). Keep it short, and write as if explaining to a friend.

---

## Small test

Pass mark: 6 of 8. Answer each one before opening its answer. Rough wording is fine if the idea is right.

**1. A signed-in user tries to open an admin page and is refused. Is that a 401 or a 403, and why?**

<details><summary>Answer</summary>

403. The server knows who they are, so authentication succeeded. They lack permission, which is an authorization failure.

</details>

**2. Decode this Basic value in your head or with Python: `YXNoYTpzZWNyZXQ=`. What does the result prove about Base64?**

<details><summary>Answer</summary>

It decodes to `asha:secret`. Base64 is encoding, not encryption. Anyone can reverse it with no key.

</details>

**3. Why are passwords hashed rather than encrypted?**

<details><summary>Answer</summary>

Encryption is reversible, so anyone with the key could recover every password. Hashing is one-way. The server only needs to compare fingerprints.

</details>

**4. Why is a slow hash like Argon2id better than a fast one like SHA-256 for passwords?**

<details><summary>Answer</summary>

Attackers guess by hashing huge numbers of candidates. A slow, memory-hungry hash barely affects one real login but makes billions of guesses very expensive.

</details>

**5. What does `HttpOnly` protect against, and what does it not stop?**

<details><summary>Answer</summary>

It stops JavaScript from reading the cookie, so XSS cannot copy it directly. It does not stop an XSS script from sending requests as the user, because the browser still attaches the cookie.

</details>

**6. A session ID and a JWT are both stolen. Which one can the server cancel straight away, and why?**

<details><summary>Answer</summary>

The session ID, because the server can delete its record. A JWT is checked by its signature alone, so it keeps working until it expires, unless you add extra revocation work.

</details>

**7. Why did Attack A fail and Attack B succeed, even though both used `SameSite=Lax`?**

<details><summary>Answer</summary>

Lax blocks the cookie on cross-site POST requests, but still sends it on top-level GET navigations, such as clicking a link. Attack B also relied on a bug: a GET route that changed data.

</details>

**8. Why can't the attacker's page simply include the correct CSRF token?**

<details><summary>Answer</summary>

The token is random and unique to the session, and it sits in the bank's own page. Browsers stop one site from reading another site's pages, so the attacker cannot get it.

</details>
