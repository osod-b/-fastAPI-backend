import jwt
from core.config import setting
from datetime import timedelta, timezone, datetime
from typing import TypedDict, Optional
from fastapi import HTTPException
from uuid import UUID

class JWTParams(TypedDict, total=False):
    sub: str
    name: str
    iat: str
    role: str
    root: bool

#Maybe for both cases provide deletion of those cookie values
def jwt_threat() -> None:
    raise HTTPException(status_code=401, detail="JWT Exposure threat. Recommendation to delete it.")

def token_expiration() -> None:
    raise HTTPException(status_code=401, detail="Refresh JWT isn't valid. Provide your credentials again")

def _create_jwt_payload(refresh=False, **kwargs: JWTParams) -> dict:
    payload = {}

    if refresh:
        payload.update({'type':'refresh_token'})
    else:
        payload.update({'type':'access_token'})

    payload.update({k: v for k, v in kwargs.items()})

    return payload

def __time_sign_payload(payload: set, expires_delta: timedelta | None) -> dict:
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=30)

    payload.update({'exp':expire})
    payload.update({'iat':datetime.now(timezone.utc)})

    return payload

def _create_jwt(payload: dict, expires_delta: timedelta | None = None) -> str:
    complete_payload = __time_sign_payload(payload, expires_delta)

    try:
        jwt_token = jwt.encode(complete_payload, key=setting.JWT_SECRET_KEY, algorithm=setting.HASHING_ALGORITHM)
    except Exception as e:
        raise ValueError(f'{e}')

    return jwt_token

def _create_refresh_jwt(payload: dict, expires_delta: timedelta | None) -> str:
    complete_payload = __time_sign_payload(payload, expires_delta)

    try:
        refresh_jwt = jwt.encode(complete_payload, setting.JWT_SECRET_KEY, algorithm=setting.HASHING_ALGORITHM)
    except Exception as e:
        raise ValueError(f'{e}')
    
    return refresh_jwt

def _decode_jwt(token: str) -> Optional[dict]:
    try:
        decoded_payload = jwt.decode(token, setting.JWT_SECRET_KEY, algorithms=[setting.HASHING_ALGORITHM])
    except Exception:
        return None
    return decoded_payload

def _check_token_expirity(token: str) -> bool:
    actual_datetime = int(datetime.now(timezone.utc).timestamp())
    decoded_payload = _decode_jwt(token)

    if not decoded_payload['exp'] or not decoded_payload:
        return False
    if decoded_payload['exp'] < actual_datetime:
        return False
    
    return True

def _refresh_access_token(a_token: str, r_token: str) -> str:
    if not _check_token_expirity(r_token):
        token_expiration() 
    if _check_token_expirity(a_token):
        jwt_threat()
    
    decoded_payload = _decode_jwt(a_token)
    refreshed_access_token = _create_jwt(payload=decoded_payload)

    return refreshed_access_token

def _tokens_validity(a_token: Optional[str], r_token: Optional[str]) -> bool:
    if a_token and r_token:
        return _decode_jwt(a_token) and _decode_jwt(r_token)
    else:
        return False