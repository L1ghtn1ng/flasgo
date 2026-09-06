from __future__ import annotations

import json
import re
import secrets

from .contracts import project_response
from .exceptions import HTTPException
from .session import Session
from .stores import SessionStore, StoreUnavailable
from .validation import ValidationBudget

_SESSION_ID = re.compile(r"[A-Za-z0-9_-]{43}")


class ServerSideSessions:
    """Opaque session IDs with atomic updates, rotation, revocation, and expiry."""

    def __init__(self, store: SessionStore, *, max_bytes: int = 65_536) -> None:
        """
        Initialize server-side session storage with a maximum serialized session size.
        
        Parameters:
        	store (SessionStore): Backend used to store session records.
        	max_bytes (int): Maximum allowed size of serialized session data in bytes.
        
        Raises:
        	ValueError: If max_bytes is not a positive integer.
        """
        if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes <= 0:
            raise ValueError("Session max_bytes must be a positive integer.")
        self.store = store
        self.max_bytes = max_bytes

    async def load(self, token: str | None) -> Session:
        """
        Load a server-side session by its opaque session identifier.
        
        Parameters:
        	token (str | None): The session identifier to retrieve.
        
        Returns:
        	Session: The stored session, or an empty session when the identifier is missing, malformed, or unknown.
        
        Raises:
        	StoreUnavailable: If the stored session data is invalid or exceeds the configured size limit.
        """
        if token is None or not _SESSION_ID.fullmatch(token):
            return Session({})
        raw = await self.store.get("session:" + token)
        if raw is None:
            return Session({})
        try:
            if len(raw) > self.max_bytes:
                raise ValueError("Session too large.")
            envelope = json.loads(raw)
            data = project_response(dict, envelope["data"], ValidationBudget())
            if not isinstance(envelope["version"], str):
                raise ValueError("Invalid session version.")
        except Exception as exc:
            raise StoreUnavailable("Stored session data is invalid.") from exc
        return Session(data, _session_id=token, _stored=raw)

    async def save(self, session: Session, *, max_age: int) -> str | None:
        """
        Persist changes to a server-side session.
        
        Parameters:
        	session (Session): The session to create, update, rotate, or revoke.
        	max_age (int): The session lifetime in seconds; must be positive.
        
        Returns:
        	str | None: The session identifier, or an empty string when the session data is cleared.
        
        Raises:
        	ValueError: If `max_age` is not positive or the serialized session exceeds `max_bytes`.
        	HTTPException: With status 409 if the stored session changed or expired before saving.
        """
        if max_age <= 0:
            raise ValueError("Server-side session lifetime must be positive.")
        if not session.modified:
            return session.session_id
        old_id = session.session_id
        if not session.data:
            if old_id is not None:
                await self.revoke(old_id)
            session._session_id = None
            session._stored = None
            session.modified = False
            return ""
        data = project_response(dict, session.data, ValidationBudget())
        raw = json.dumps(
            {"version": secrets.token_urlsafe(16), "data": data}, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")
        if len(raw) > self.max_bytes:
            raise ValueError("Session exceeds max_bytes.")
        if old_id is None:
            token = secrets.token_urlsafe(32)
            saved = await self.store.create("session:" + token, raw, max_age)
        elif session._rotate:
            token = secrets.token_urlsafe(32)
            saved = await self.store.rotate(
                "session:" + old_id, session._stored or b"", "session:" + token, raw, max_age
            )
        else:
            token = old_id
            saved = await self.store.replace("session:" + old_id, session._stored or b"", raw, max_age)
        if not saved:
            raise HTTPException(409, "Session changed or expired. Reload before retrying the operation.")
        session._session_id = token
        session._stored = raw
        session._rotate = False
        session.modified = False
        return token

    async def revoke(self, session_id: str) -> None:
        """Revoke a stored session by its session ID.
        
        Parameters:
        	session_id (str): The session ID to revoke.
        """
        if not _SESSION_ID.fullmatch(session_id):
            raise ValueError("Invalid session ID.")
        await self.store.delete("session:" + session_id)
