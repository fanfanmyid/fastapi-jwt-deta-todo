from datetime import datetime, timedelta
from tabnanny import check
from typing import Union

from fastapi import Depends, FastAPI, HTTPException, status,Form
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
import json

from deta import Deta  # Import Deta
deta = Deta("c0p1a406_AXVnCDjdozsWrTF8Pw8xdstHgUTm2AV5")
# to get a string like this run:
# openssl rand -hex 32
SECRET_KEY = "Ffff166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: Union[str, None] = None


class User(BaseModel):
    username: str
    email: Union[str, None] = None
    full_name: Union[str, None] = None
    disabled: Union[bool, None] = None


class UserInDB(User):
    hashed_password: str


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

deta = Deta("c0p1a406_AXVnCDjdozsWrTF8Pw8xdstHgUTm2AV5")
db = deta.Base("user_db")
db_todo = deta.Base("todo_db")

app = FastAPI()


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def get_user_db(username:str):
    catch = db.fetch(query=[{"id":username}])
    jsonData = json.dumps(catch.__dict__)
    jsonDataLoad = json.loads(jsonData)
    checker = bool(jsonDataLoad['_items'])
    if checker:
        jsonDataLoadContent = jsonDataLoad['_items'][0]['detail']
        UserInDB(**jsonDataLoadContent)
        return UserInDB(**jsonDataLoadContent)
    else:
        return False

def authenticate_user_db(username: str, password: str):
    user = get_user_db(username)
    if(user == False):
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user


def create_access_token(data: dict, expires_delta: Union[timedelta, None] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = get_user_db(username=token_data.username)
    if user is None:
        raise credentials_exception
    return user


async def get_current_active_user(current_user: User = Depends(get_current_user)):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user_db(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/users/me/", response_model=User)
async def read_users_me(current_user: User = Depends(get_current_active_user)):
    return current_user


@app.get("/")
async def root():
    return {"Test": "OK"}

@app.post("/register")
async def register_user(username: str = Form(),password:str = Form(), email:str = Form(),fullname:str= Form()):
    hashed_password = get_password_hash(password)
    db.insert({
    "id" : username,
    "detail": {
        "username": username,
        "full_name": fullname,
        "email": email,
        "hashed_password": hashed_password,
        "disabled": False,
    }
    })
    return {"username": username,
            "email" : email,
            "fullname" : fullname,
            }
    
@app.get("/users/me/items")
async def read_own_items(current_user: User = Depends(get_current_active_user)):
    catch = db_todo.fetch(query=[{"owner":current_user.username}])
    jsonData = json.dumps(catch.__dict__)
    jsonDataLoad = json.loads(jsonData)
    checker = bool(jsonDataLoad['_items'])
    if checker:
        jsonDataLoadContent = jsonDataLoad['_items']
        return {"data": jsonDataLoadContent}
    else:
        return False
    
@app.post("/users/me/items")
async def write_own_items(current_user: User = Depends(get_current_active_user), todo:str = Form()):
    dt_now = datetime.now()
    dt_string = dt_now.strftime("%d/%m/%Y %H:%M:%S")
    db_todo.insert({
        "owner" : current_user.username,
        "todo" : todo,
        "timestamp" : dt_string
    })
    
    return {"owner" : current_user.username,
            "todo" : todo,
            "timestamp" : dt_string
            }
