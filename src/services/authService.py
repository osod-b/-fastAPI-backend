from services.jwtService import _create_jwt, _create_refresh_jwt, _create_jwt_payload, _refresh_access_token, _tokens_validity
from fastapi import HTTPException, status, Request
from sqlalchemy.exc import IntegrityError, OperationalError
from fastapi.responses import JSONResponse
from schemas.user import UserLogin, UserRegistration
from datetime import timezone, timedelta, datetime
from typing import Optional
from passlib.context import CryptContext
from sqlalchemy.orm import Session
from models.user import UserModel
from sqlalchemy import or_
import mailtrap as mt
import secrets
from uuid import UUID, uuid4
import json

from app.redis import redis_session

pwd_context = CryptContext(schemes=['bcrypt'], deprecated='auto')

class UserLoginService:

    def login(self, post: UserLogin, uip: str, db: Session) -> dict | tuple:
        creds = _normz(post.identifier.value)[0]             
        model = _get_user_by_context(creds, creds, db)    # think how to split username from email

        act_stt = model.active
        role = model.role
        root = model.root
        uuid = model.id

        p_pwd = post.password.value
        h_pwd = model.password

        if not _vrf_pwd(p_pwd, h_pwd):
            raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Password Doesn't Match")

        if not _mail_actv(act_stt):
            a_code = _gen_access_code()
            d_model = json.dumps(model.as_dict())

            redis_session.hset_exp('user', uip, 'login',
                                   mapping = {
                                            'access_code': a_code,
                                            'progress_key': 1,
                                            'model': d_model },
                                   time=60*15)
            
            return {"message": "Flow was started. Keep onto the next step"}
        else:
            a_payload = _create_jwt_payload(**{'sub': uuid, 'name': creds,
                                           'role': role, 'root': root})
            
            r_payload = _create_jwt_payload(**{'sub': uuid, 'name': creds},
                                           refresh=True)

            a_token = _create_jwt(payload=a_payload)
            r_token = _create_refresh_jwt(payload=r_payload, 
                                          expires_delta=timedelta(hours=12))   #create jwt and create refresh jwt ????

            return (a_token, r_token)
    
    def mfa(self, post, uip: str, db: Session) -> dict:
        code = post.value

        if not _verify_redis_key(uip, 'login'):
            raise HTTPException(
                        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                        detail='1')
    
        if not _verify_progress_key(uip, 'login', 1):
            raise HTTPException(
                        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                        detail='2')                                               #why isn't here alleged key

        if not _verify_access_code(uip, code, 'login'):
            raise HTTPException(
                        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                        detail='3')

        model_d = redis_session.hget('user', uip, 'login', 'user_object')
        model_d = json.loads(model)
        uname = model_d['username']

        model = _get_user_by_context(uname, db)

        creds = model.username
        uuid = model.id
        role = model.role
        root = model.root

        _make_user_changes_to_db(model, db, active=True)

        a_payload = _create_jwt_payload(**{'sub': uuid, 'name': creds,
                                           'role': role, 'root': root})
        
        r_payload = _create_jwt_payload(**{'sub': uuid, 'name': creds},
                                           refresh=True)

        a_token = _create_jwt(a_payload)
        r_token = _create_refresh_jwt(r_payload, timedelta(hours=12)) 

        redis_session.hdel('user', uip, 'login')

        return (a_token, r_token)

    def refresh(a_token: Optional[str], r_token: Optional[str]) -> str:
        result = _refresh_access_token(a_token, r_token)

        return result



class UserRegiserService:
    def __init__(self):
        ...

    def register(post: UserRegistration, uip: str, db: Session) -> dict:
        
        uname = post.username.value
        email = post.email.value

        uname, email = _normz(uname, email)

        if _get_user_by_context(uname, db):
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Username already taken")
    
        if _get_user_by_context(email, db):
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already taken") 

        vcode = _gen_access_code()

        redis_session.hset_exp(name='user', ip=uip, operation='register',
                              time=60*15, mapping={'access_code':f'{vcode}', 'user_object':post_arg.model_dump_json(), 
                                                                                                          'progress_key': 1})

        return { "issued": datetime.now(timezone.utc).isoformat() }


# def register(post_arg: UserRegistration, req: Request, db_arg: Session) -> set:

#     user, email = _normz(post_arg.username.value, post_arg.email.value)
#     _user_presence(username=user, email=email, db=db_arg)

    
#     generated_code = _gen_access_code()

#     redis_session.set_hash_with_time_expirity(name='user', ip=user_ip, operation='register', time=60*15, mapping={'access_code':f'{generated_code}', 'user_object':post_arg.model_dump_json(), 
#                                                                                                           'progress_key': 1})
#     return {"issued": datetime.now(timezone.utc).isoformat()}

def reg_mfa(code_arg: str, request_arg: Request, db_arg: Session):
    user_ip = _get_ip_address(request_arg)

    if not _verify_redis_key(ip=user_ip, operation='register'):
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail='r_key')
    
    if not _verify_progress_key(alleged_key=1, ip=user_ip, operation='register'):
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail='p_key')
    
    if not _verify_access_code(code=code_arg.value, ip=user_ip, operation='register'):
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail='a_c')
    
    user = UserRegistration.model_validate_json(redis_session.get_single_value(name='user', ip=user_ip, operation='register', inner_key='user_object'))

    username, email, set_role = _normz(user.username.value, user.email.value, 'user')

    password_hash = _hash_password_context(user.password.value)
    generated_uuid = _generate_uuid4()

    transformed = _compound_user_model(username=username, email=email, role=set_role, password_hash=password_hash, uuid=generated_uuid)
    _upload_user_to_db(target=transformed, db=db_arg)

    redis_session.clean_hash_by_key(name='user', ip=user_ip, operation='register')

    return {"issued": datetime.now(timezone.utc).isoformat()}
    
def forgot_pwd(email_arg: str, db_arg: Session, request_arg: Request) -> dict:

    if _tokens_validity(request_arg.cookies.get('access_token'), request_arg.cookies.get('refresh_token')):
        raise HTTPException(status_code=status.HTTP_405_METHOD_NOT_ALLOWED, detail='Method not allowed, user is logged in')

    user_ip = _get_ip_address(request_arg)
    db_user = _get_user_by_context(db=db_arg, email=email_arg.value)

    generated_code = _gen_access_code()

    redis_session.set_hash_with_time_expirity(name='user', ip=user_ip, operation='forgot_pwd', time = 60*15, mapping={'access_code': generated_code,'email': email_arg.value,'progress_key': 1})

    return {'issued': datetime.now(timezone.utc).isoformat()}

def vrf_code(code_arg: str, request_arg: Request) -> set:
    user_ip = _get_ip_address(request_arg)

    if not _verify_redis_key(ip=user_ip, operation='forgot_pwd'):
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail='r_key')
    
    if not _verify_progress_key(alleged_key=1, ip=user_ip, operation='forgot_pwd'):
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail='p_key')
    
    if not _verify_access_code(code=code_arg.value, ip=user_ip, operation='forgot_pwd'):
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail='a_c')
    
    redis_session.set_single_hash_value(name='user', ip=user_ip, operation='forgot_pwd', inner_key='progress_key', value= 2)

    return {'issued': datetime.now(timezone.utc).isoformat()}

def reset_pwd(password_arg: str, request_arg: Request , db_arg: Session) -> set:
    user_ip = _get_ip_address(request_arg) 

    if not _verify_redis_key(ip=user_ip, operation='forgot_pwd'):
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail='r_key')
    
    if not _verify_progress_key(alleged_key=2, ip=user_ip, operation='forgot_pwd'):
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail='p_key')
    
    client_email = redis_session.get_single_value(name='user', ip=user_ip, operation='forgot_pwd', inner_key='email')

    db_user = _get_user_by_context(db=db_arg, email=client_email)
    hashed_password = _hash_password_context(password_arg.value)
    _make_user_changes_to_db(target=db_user, db=db_arg, password=hashed_password)

    if not db_user.active:
        _make_user_changes_to_db(target=db_user, db=db_arg, active=True)
    
    redis_session.clean_hash_by_key(name='user', ip=user_ip, operation='forgot_pwd')
    
    return {'Completed': datetime.now(timezone.utc).isoformat()}



def _verify_redis_key(ip: str, operation: str) -> bool:
    return bool(redis_session.get_whole_hash(name='user', ip=ip, operation=operation))

def _verify_progress_key(ip: str, operation: str, alleged_key: int) -> bool:
    return int(redis_session.get_single_value(name='user', ip=ip, operation=operation, inner_key='progress_key')) == alleged_key

def _verify_access_code(ip: str, operation: str, code: str) -> bool:
    return redis_session.get_single_value(name='user', ip=ip, operation=operation, inner_key='access_code') == code

def _vrf_pwd(plain_pwd: str, hashed_pwd: str) -> bool:
    return pwd_context.verify(plain_pwd, hashed_pwd)

def _mail_actv(state: bool) -> bool:
    return state

def _hash_password_context(password: str) -> str:
    return pwd_context.hash(password)

def _get_ip_address(request: Request) -> str:
    return request.headers['x-user-ip']

def _normz(*credentials) -> tuple:
    return tuple(map(str.casefold, credentials))

def _gen_access_code() -> str:
    return secrets.token_urlsafe(4)

def _generate_uuid4() -> UUID:
    return uuid4()

def _generate_email(sub: str, message: str, cat: str, sender: str = "hello@demomailtrap.co", reciever: str = "ripplehkg@gmail.com"):
    mail = mt.Mail(sender=mt.Address(email=sender, name="Tax Service"), to=[mt.Address(email=reciever)], subject=sub, text=message, category=cat)
    client = mt.MailtrapClient(token="a8d01dcb0d3951256ae216dda3d4f096").send(mail)
    return

def _prolong_token(arg):
    ...

def _upload_user_to_db(target: UserModel, db: Session) -> None:
    try:
        db.add(target)
    except IntegrityError as E:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"Something went wrong (Integrity) {E}")
    
    db.commit()
    db.refresh(target)

    return

def _make_user_changes_to_db(target: UserModel, db: Session, **kwargs) -> None:
    try:
        for key, value in kwargs.items():
            setattr(target, key, value) 
    except IntegrityError:
        db.rollback()
        raise HTTPException()
    
    db.commit()
    db.refresh(target)

    return

def _compound_user_model(uuid: UUID, username: str, email: str, role: str, password_hash: str) -> UserModel:
    user_model = UserModel(id = uuid, username = username, email = email, password = password_hash, role = role, root = False, active = True)
    
    return user_model

def _get_user_by_context(username: str | None = None, db: Session = None, email: str | None = None, ignore=True, ) -> Optional[UserModel]:
    if not ignore:
        try:
            instance = db.query(UserModel).filter(or_(UserModel.username == username, UserModel.email == email)).first()
        except OperationalError:
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Coldn't find user by provided data")
        if not instance:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Couldn't find user")
        
        return instance
    else:
        instance = db.query(UserModel).filter(or_(UserModel.username == username, UserModel.email == email)).first()
        return instance

def _user_presence(username: str, email: str, db: Session) -> UserModel:

    if _get_user_by_context(username, db):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Username already taken")
    
    if _get_user_by_context(email, db):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already taken") 
    
    
#CLEANER CODE
#style helpers in the same consistent way