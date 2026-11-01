# Phase 0: Workspace Setup

**Goal:** Understand the tools running on your machine.
**Time:** About 1 hour, since setup is already done for you.
**Status:** Built and running, apart from the two small steps below.

## What was set up

| Tool | What it does for you |
|---|---|
| `uv` and `.venv` | Installs Python packages into this project only |
| `pyproject.toml` | Lists the packages this project needs |
| Docker | Runs services in small isolated containers |
| Postgres | A database, used from Phase 8 |
| Redis | A fast data store, used for sessions in Phase 1 |
| Keycloak | A free login server you run yourself, used from Phase 3 |
| Mailpit | Catches test emails locally, used in Phase 10 |
| Git | Tracks changes to your code |
| `.env` | Holds local passwords, and is never committed |

## Understanding the setup

**Think of Docker as a row of small rented offices.** Each service has its own office, and they do not disturb your computer's main setup. You can start or stop one without affecting the others.

**Ports are like door numbers.** Your computer has one address, and each service answers at a different door. `127.0.0.1` means "this computer only", so nobody else on your network can reach these services.

| Service | Address | Note |
|---|---|---|
| Keycloak | http://localhost:8080 | The admin site |
| Postgres | `127.0.0.1:5433` | Moved from the usual 5432 to avoid clashes |
| Redis | `127.0.0.1:6380` | Moved because 6379 is used by something in your WSL environment |

**`.env` holds secrets.** Secrets must stay out of Git, because Git keeps history, and a committed password stays in that history even if you delete it later. `.gitignore` is what keeps `.env` out. The `.env.example` file is safe to share because it has only placeholders.

## Your two steps

### Step 1: Fix one line in `.env`

Claude Code is blocked from reading `.env` to protect your secrets, so this edit is yours.

Open `.env` and change the Redis line to:

```
REDIS_URL=redis://127.0.0.1:6380/0
```

Phase 1 works without this change, but later phases will need it.

### Step 2: Sign in to Keycloak

1. Run `docker compose up -d --wait` in the project folder.
2. Open http://localhost:8080.
3. Sign in with `KEYCLOAK_ADMIN_USER` and `KEYCLOAK_ADMIN_PASSWORD` from `.env`.
4. Look around, then come back. You will not need to change anything yet.

## Daily commands

| Task | Command |
|---|---|
| Start services | `docker compose up -d --wait` |
| Check services | `docker compose ps` |
| Stop services | `docker compose stop` |
| Run tests | `uv run pytest` |
| Check code style | `uv run ruff check .` |

`docker compose down -v` deletes the stored data, so avoid it unless you want a fresh start.

## Small test

Pass mark: 4 of 5. Answer each one before opening its answer.

**1. Why does `.env` stay out of Git?**

<details><summary>Answer</summary>

It contains secrets, and Git keeps a permanent history. A committed secret stays in that history even after you delete the file.

</details>

**2. What does `127.0.0.1` mean, and why do our services use it?**

<details><summary>Answer</summary>

It means "this computer". Binding services to it keeps them unreachable from other devices on your network.

</details>

**3. What problem does Docker solve here?**

<details><summary>Answer</summary>

It runs Postgres, Redis, and Keycloak in isolated containers, so you avoid installing each one on Windows, and you can start and stop them easily.

</details>

**4. Why does Redis use port 6380 instead of its usual 6379?**

<details><summary>Answer</summary>

Something else on your machine, in WSL, already uses 6379, and only one service can listen on a port at a time.

</details>

**5. What is the difference between `.env` and `.env.example`?**

<details><summary>Answer</summary>

`.env` holds your real local secrets and is ignored by Git. `.env.example` lists the setting names with placeholders, and is safe to commit.

</details>
