# Phase 5: AWS Cognito

**Goal:** Add customer sign-up and login on AWS.
**You will build:** App 4, with sign-up, login, groups, and machine-to-machine access.

## The big idea

Cognito is a ready-made login service for your customers, run by AWS. You rent the membership desk instead of building your own. The concepts from Phase 3 still apply, so most of the learning here is about Cognito's differences.

| Cognito part | Job |
|---|---|
| **User pool** | Stores users and handles login |
| **Identity pool** | Swaps a login for temporary AWS credentials |
| **App client** | Your app's registration |
| **Lambda triggers** | Your own code that runs during login steps |

## Learn in this order

1. **User pool vs identity pool.** One proves who you are, and the other gives access to AWS services.
2. **Feature plans.** Lite, Essentials, and Plus. We stay on Essentials.
3. **Managed login vs custom UI.** Use Cognito's pages, or build your own and call its API.
4. **Token differences.** Access tokens have `client_id` rather than `aud`, and `token_use` says which type a token is.
5. **Groups and custom scopes.** Roles for users and permissions for machines.
6. **Lambda triggers.** Add a custom claim during token creation.

## What you will build

Deploy a user pool from a template, sign users in with managed login, build a custom sign-up form, enforce groups, add a custom claim, and set up machine-to-machine access. Then delete everything.

## Cost safety

Set a billing alert before you start, avoid SMS, stay off the Plus plan, and always finish with the teardown step.

## Run it

The code is in [apps/app4_cognito/](../apps/app4_cognito/), and the AWS template is [infra/cognito.yaml](../infra/cognito.yaml). It was tested against a simulated provider, and `cfn-lint` checked the template.

```powershell
uv run pytest tests/app4_cognito -v
uv run cfn-lint infra/cognito.yaml
```

**Your step:** The AWS credentials on this machine are invalid. Fix them, then follow [the setup guide](../apps/app4_cognito/SETUP.md). Nothing has been deployed to AWS, so no cost has been incurred.

## Small test

Pass mark: 4 of 5.

**1. What is the difference between a user pool and an identity pool?**

<details><summary>Answer</summary>

A user pool handles authentication. An identity pool exchanges that proof for temporary AWS credentials.

</details>

**2. Why might a generic token validator fail on a Cognito access token?**

<details><summary>Answer</summary>

Cognito access tokens use `client_id` instead of the usual `aud` claim.

</details>

**3. Why check the `token_use` claim?**

<details><summary>Answer</summary>

So an ID token cannot be used where an access token is required.

</details>

**4. What are Lambda triggers for?**

<details><summary>Answer</summary>

Running your own code during Cognito's steps, such as adding a custom claim when tokens are created.

</details>

**5. Name two things that protect you from surprise AWS costs in this phase.**

<details><summary>Answer</summary>

Any two of: a billing alert, avoiding SMS, staying on Essentials rather than Plus, and tearing down resources afterward.

</details>
