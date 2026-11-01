# Glossary

Plain-English definitions, in alphabetical order.

| Term | Meaning |
|---|---|
| **Access token** | A short-lived credential an app sends to prove it may call an API. |
| **API** | A way for programs to talk to each other over the network. |
| **Argon2id** | A password hashing method designed to be slow and memory-hungry, which makes guessing expensive. |
| **Authentication (AuthN)** | Proving who you are. |
| **Authorization (AuthZ)** | Deciding what you are allowed to do. |
| **Base64** | A way to write data as plain text. It is reversible by anyone and hides nothing. |
| **Claim** | One piece of information inside a token, such as a user ID or expiry time. |
| **Client** | The app asking for access on someone's behalf. |
| **Cookie** | A small value a website asks your browser to store and send back on later requests. |
| **Credential** | Something used to prove identity, such as a password or token. |
| **Credential stuffing** | Trying usernames and passwords leaked from one site on other sites. |
| **CSRF** | Cross-Site Request Forgery. A malicious site makes your browser send an unwanted request to a site where you are signed in. |
| **Docker container** | A small isolated environment that runs one service, such as a database. |
| **Encoding** | Changing data's format. No key, and no secrecy. |
| **Encryption** | Scrambling data so only someone with the key can read it. It is reversible with the key. |
| **Entitlement** | What a user's access includes, such as PDF export on a Premium plan. |
| **Hash** | A one-way fingerprint of data. You cannot turn it back into the original. |
| **HTTP** | The language browsers and servers use to talk. |
| **HTTPS** | HTTP with encryption, so others on the network cannot read or change the traffic. |
| **HttpOnly** | A cookie setting that stops JavaScript from reading the cookie. |
| **IDOR / BOLA** | A bug where changing an ID in a request reveals someone else's data. |
| **Identity Provider (IdP)** | A service that handles login and vouches for who someone is, such as Google or Entra ID. |
| **JWT** | JSON Web Token. A signed token that carries claims. |
| **MFA** | Multi-Factor Authentication. Login using two or more types of proof. |
| **OAuth 2** | A standard that lets an app get limited access on your behalf without your password. |
| **OIDC** | OpenID Connect. A layer on OAuth 2 that tells an app who signed in. |
| **Passkey** | A phishing-resistant login based on a key stored on your device. |
| **Phishing** | Tricking someone into giving their credentials to a fake site. |
| **PKCE** | A one-time secret that protects the OAuth login flow from stolen codes. |
| **RBAC** | Role-Based Access Control. Permissions are grouped into roles, and users receive roles. |
| **Redis** | A very fast in-memory data store. We use it for sessions. |
| **Refresh token** | A longer-lived token used to get new access tokens without logging in again. |
| **Replay attack** | Reusing a valid message or token that was captured earlier. |
| **Row-Level Security (RLS)** | A database rule that limits which rows a session can see or change. |
| **Salt** | A random value added before hashing, so identical passwords get different hashes. |
| **SameSite** | A cookie setting that controls whether the cookie is sent on requests started by other sites. |
| **SAML** | An older XML-based standard for enterprise single sign-on. |
| **Scope** | A named permission an app requests, such as read access to a calendar. |
| **Secure** | A cookie setting that limits the cookie to encrypted connections. |
| **Session** | The server's record that a particular browser has signed in. |
| **Session fixation** | Tricking a victim into signing in with a session ID the attacker already knows. |
| **Signature** | Proof that data came from a key holder and was not changed. |
| **SSO** | Single Sign-On. One login opens many apps. |
| **Stateless** | The server keeps no memory between requests. |
| **Tenant** | One customer or organization using a shared application. |
| **TOTP** | The six-digit codes from an authenticator app. |
| **Token** | A string that proves something, usually that you are signed in. |
| **User enumeration** | Using an app's responses to discover which accounts exist. |
| **XSS** | Cross-Site Scripting. Attacker-controlled JavaScript runs on a trusted site. |
