from services.authService import login, register, logout, forgot_pwd, vrf_code, reset_pwd, reg_mfa, refresh, login_mfa, _get_ip_address
from services.jwtService import _tokens_validity
from fastapi import APIRouter, Depends, Cookie, Request, status, HTTPException
from validators.users import VerificationalCode, EmailValidator, PasswordValidator
from schemas.user import UserLogin, UserRegistration
from datetime import datetime, timezone
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from db.schema import SessionLocal


from services.authService import UserLoginService

auth = APIRouter()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

#generate uuid in db model

#separate layers, build basic structure for endpoints, completly analyze and finish auth endpoints. Re read all and create understanding of system.

#TODO_: 
#account lock up after 3 bad attempts but lock out after page refresh
#after some certain verification's as log in autofill fields - remember me property (if remember me - create longer session or longer jwt expirity??)
#abstract email validation before registration
#account deactivation after 15 days logged out

#Bearer token, some issues with BucketRateLimiter, also analyze it.

#alternative concepts - maybe with async
#save somewhat like key in this relation, next step will be verifier endpoint where user will send his code
#this second endpoint takes this code insterted and then varifies it with the code in endpoint


#emails out, token out
#exclude .env + cahces

@auth.post('/auth/login', status_code=status.HTTP_200_OK)
def login_user(
        post: UserLogin, req: Request, db: Session = Depends(get_db), 
        service: UserLoginService = Depends()):
    
    a_token = req.cookies.get('access_token')
    r_token = req.cookies.get('refresh_token')

    if _tokens_validity(a_token, r_token):
        raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, 
                    detail='Already Logged In')
    
    uip = _get_ip_address(req)
    
    result = service.login(post, uip, db)

    if isinstance(result, dict):
        response = JSONResponse(content=result)
    elif isinstance(result, tuple):
        a_token, r_token = result

        response = JSONResponse(
                    content = {"message": "Successful Log In. JWT Saved"})
        
        response.set_cookie(key="access_token", value=a_token, httponly=True,
                            secure=True, samesite="strict", max_age=30*60)
        
        response.set_cookie(key="refresh_token", value = r_token, httponly=True,
                            secure=True, samesite="strict", max_age=7*24*60*60)

    return response


@auth.post('/auth/login/activate_email', status_code=status.HTTP_200_OK)
def mfa_user(
        post: VerificationalCode, req: Request, db: Session = Depends(get_db),
        service: UserLoginService = Depends()):
    
    uip = _get_ip_address(req)

    result = service.mfa(post, uip, db)
    a_token, r_token = result

    response = JSONResponse(
                content = { "message": "Successful Log In. JWT Saved" })
    
    response.set_cookie(key="access_token", value=a_token, httponly=True,
                        secure=True, samesite="strict", max_age=30*60)
    
    response.set_cookie(key="refresh_token", value=r_token, httponly=True,
                        secure=True, samesite="strict", max_age=7*24*60*60)
    
    return response


@auth.post('/auth/logout', status_code=status.HTTP_200_OK)
def logout_user(a_token=Cookie(alias='access_token', default=None),
                r_token=Cookie(alias='refresh_token', default=None)):
    
    if not _tokens_validity(a_token, r_token):
            raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Isn't Logged In")

    response = JSONResponse(content = { "message": "Log Out." })

    response.delete_cookie("access_token")
    response.delete_cookie("refresh_token")

    return response                                                             #deleted jwt cookies isn't providing complete log out


@auth.post('/auth/refresh', status_code=status.HTTP_200_OK)                     #when is this function forced
def refresh_session(a_token = Cookie(alias="access_token", default=None),
                   r_token = Cookie(alias="refresh_token", default=None),
                   service: UserLoginService = Depends()):
    
    if not _tokens_validity(a_token, r_token):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="JWT Doesn't Exist")
    
    token = service.refresh(a_token, r_token)
    result = { "message": "Successfull JWT Refresh." }

    response = JSONResponse(content=result)
    response.set_cookie(key='access_token', value=token, httponly=True,
                        secure=True, samesite="strict", max_age=30*60)

    return response


@auth.post('/auth/register', status_code=status.HTTP_202_ACCEPTED)
def register_user(post: UserRegistration, req: Request,
                 db: Session = Depends(get_db),
                 service: UserLoginService = Depends()):
    
    a_token = req.cookies.get('access_token')
    r_token = req.cookies.get('refresh_token')
    
    if _tokens_validity(a_token, r_token):
        raise HTTPException(status_code=status.HTTP_405_METHOD_NOT_ALLOWED, detail='Log out first')             # weird check are you sure it would work?

    uip = _get_ip_address(req)

    result = service.register(post, uip, db)

    # response = JSONResponse(content=data)

    return response
    
@auth.patch('/auth/register/verification', status_code=status.HTTP_200_OK)
def register_mfa(code: VerificationalCode, request:Request, database: Session = Depends(get_db)):
    data = reg_mfa(code_arg=code, request_arg=request, db_arg=database)
    data.update({"message": "Completed"})
    
    return JSONResponse(content=data)

@auth.post('/auth/forgot_password', status_code=status.HTTP_202_ACCEPTED)
def forgot_password(email: EmailValidator, request: Request, database: Session = Depends(get_db)):
    data = forgot_pwd(email_arg=email, request_arg=request, db_arg=database)
    data.update({'message': 'Completed'})

    return JSONResponse(content=data)

@auth.post('/auth/verify_code', status_code=status.HTTP_202_ACCEPTED)
def verify_code(code: VerificationalCode, request: Request):
    data = vrf_code(code_arg=code, request_arg=request)
    data.update({'message': 'Completed'}) 

    return JSONResponse(content=data)

@auth.post('/auth/reset_password', status_code=status.HTTP_200_OK)
def reset_password_user(password: PasswordValidator, request: Request, database: Session = Depends(get_db)):
    data = reset_pwd(password_arg=password, request_arg=request, db_arg=database)
    data.update({'message':'Completed'})

    return JSONResponse(content=data)