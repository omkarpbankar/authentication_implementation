"""Magic links and password reset. Both email a secret, so both follow the same rules.

The token is random, short-lived, single-use, and stored only as a hash.
"""

import asyncio
import secrets
import smtplib
from email.message import EmailMessage
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from apps.app1_jwt.deps import KeyRingDep, StoreDep, TokenPair, issue_pair, password_hash
from apps.app1_jwt.settings import settings
from apps.shared.rate_limit import RateLimiter

router = APIRouter(tags=["Email links"])
MAGIC_TTL_SECONDS = 900
RESET_TTL_SECONDS = 900
GENERIC_REPLY = {"message": "If that account exists, we have sent an email."}


class EmailRequest(BaseModel):
    email: str


class TokenRequest(BaseModel):
    token: str


class ResetRequest(BaseModel):
    token: str
    new_password: str = Field(min_length=12, max_length=128)


class Mailer:
    def send(self, to: str, subject: str, body: str) -> None:
        message = EmailMessage()
        message["From"] = settings.mail_from
        message["To"] = to
        message["Subject"] = subject
        message.set_content(body)
        with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=5) as smtp:
            smtp.send_message(message)


def get_mailer() -> Mailer:
    return Mailer()


MailerDep = Annotated[Mailer, Depends(get_mailer)]


async def send_link(
    store,
    mailer: Mailer,
    email: str,
    kind: str,
    ttl: int,
    subject: str,
    path: str,
) -> None:
    user = await store.get_user_by_email(email.lower())
    # The reply is the same either way, so this cannot reveal who has an account.
    if user is None:
        return
    # Stops anyone from flooding a person's inbox.
    if not await RateLimiter(store.redis).allow(f"email:{user['id']}", 5, 3600):
        return
    token = secrets.token_urlsafe(32)
    await store.save_single_use(kind, token, user["id"], ttl)
    # The link opens a page, which then POSTs the token. A GET that signs someone in could be
    # triggered by an email security scanner opening the link.
    body = f"{settings.origin}{path}?token={token}\n\nThis link expires in 15 minutes."
    await asyncio.to_thread(mailer.send, user["email"], subject, body)


@router.post("/auth/magic/request", status_code=status.HTTP_202_ACCEPTED)
async def request_magic_link(
    body: EmailRequest, store: StoreDep, mailer: MailerDep
) -> dict[str, str]:
    await send_link(
        store, mailer, body.email, "magic", MAGIC_TTL_SECONDS, "Your sign-in link", "/magic"
    )
    return GENERIC_REPLY


@router.post("/auth/magic/verify")
async def use_magic_link(body: TokenRequest, store: StoreDep, ring: KeyRingDep) -> TokenPair:
    user_id = await store.take_single_use("magic", body.token)
    if user_id is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "This link is invalid or has expired")
    return await issue_pair(store, ring, user_id)


@router.post("/auth/reset/request", status_code=status.HTTP_202_ACCEPTED)
async def request_reset(body: EmailRequest, store: StoreDep, mailer: MailerDep) -> dict[str, str]:
    await send_link(
        store, mailer, body.email, "reset", RESET_TTL_SECONDS, "Reset your password", "/reset"
    )
    return GENERIC_REPLY


@router.post("/auth/reset/confirm")
async def confirm_reset(body: ResetRequest, store: StoreDep) -> dict[str, str]:
    user_id = await store.take_single_use("reset", body.token)
    user = await store.get_user_by_id(user_id) if user_id else None
    if user is None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "This link is invalid or has expired")
    user["password_hash"] = password_hash.hash(body.new_password)
    await store.save_user(user)
    # The reset may be happening because someone else got in, so end every session.
    await store.revoke_everything(user_id)
    return {"message": "Password changed. Please sign in."}
