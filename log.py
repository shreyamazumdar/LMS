from datetime import datetime, timedelta
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel

# to get a string like this run:
# openssl rand -hex 32
SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


fake_users_db = {
    "johndoe": {
        "username": "johndoe",
        "full_name": "John Doe",
        "email": "johndoe@example.com",
        "hashed_password": "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",
        "disabled": False,
    }
}


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: str | None = None


class User(BaseModel):
    username: str
    email: str | None = None
    full_name: str | None = None
    disabled: bool | None = None


class UserInDB(User):
    hashed_password: str


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI()


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def get_user(db, username: str):
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)


def authenticate_user(fake_db, username: str, password: str):
    user = get_user(fake_db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
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
    user = get_user(fake_users_db, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user


async def get_current_active_user(
    current_user: Annotated[User, Depends(get_current_user)]
):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


@app.post("/token", response_model=Token)
async def login_for_access_token(
    form_data: OAuth2PasswordRequestForm= Depends()#Annotated[OAuth2PasswordRequestForm, Depends()]
):
    user = authenticate_user(fake_users_db, form_data.username, form_data.password)
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
async def read_users_me(
    current_user: Annotated[User, Depends(get_current_active_user)]
):
    return current_user


@app.get("/users/me/items/")
async def read_own_items(
    current_user: Annotated[User, Depends(get_current_active_user)]
):
    return [{"item_id": "Foo", "owner": current_user.username}]






















































































# # import psycopg2
# # from fastapi import FastAPI
# # from pydantic import BaseModel

# # app = FastAPI()

# # class UserRegistration(BaseModel):
# #     username: str
# #     password: str
# #     email: str
# #     userid: int
# #     role: str

# # # Function to save user data to the database
# # def save_user_to_database(user: UserRegistration):
# #     conn = psycopg2.connect(
# #         dbname="your_database_name",
# #         user="your_username",
# #         password="your_password",
# #         host="your_host",
# #         port="your_port"
# #     )
# #     cursor = conn.cursor()
# #     query = """
# #     INSERT INTO users (username, password, email, userid, role)
# #     VALUES (%s, %s, %s, %s, %s)
# #     """
# #     values = (user.username, user.password, user.email, user.userid, user.role)
# #     cursor.execute(query, values)
# #     conn.commit()
# #     cursor.close()
# #     conn.close()

# # @app.post("/register")
# # def register_user(username: str, password: str, email: str, userid: int, role: str):
# #     user = UserRegistration(
# #         username=username,
# #         password=password,
# #         email=email,
# #         userid=userid,
# #         role=role
# #     )
# #     save_user_to_database(user)
# #     return {"message": "User registered successfully"}

# # # You can run the FastAPI application with uvicorn
# # # For example: uvicorn main:app --reload
# # import psycopg2
# # from fastapi import FastAPI
# # from pydantic import BaseModel

# # app = FastAPI()

# # class UserRegistration(BaseModel):
# #     username: str
# #     password: str
# #     email: str
# #     userid: int
# #     role: str

# # # Function to save user data to the database
# # def save_user_to_database(user: UserRegistration):
# #     conn = psycopg2.connect(
# #         dbname="postgres",
# #         user="shreya",
# #         password="12062023",
# #         host="127.0.0.1",
# #         port="5432"
# #     )
# #     cursor = conn.cursor()
# #     query = """
# #     INSERT INTO users (username, password, email, userid, role)
# #     VALUES (%s, %s, %s, %s, %s)
# #     """
# #     values = (user.username, user.password, user.email, user.userid, user.role)
# #     cursor.execute(query, values)
# #     conn.commit()
# #     cursor.close()
# #     conn.close()

# # @app.post("/register")
# # def register_user(username: str, password: str, email: str, userid: int, role: str):
# #     user = UserRegistration(
# #         username=username,
# #         password=password,
# #         email=email,
# #         userid=userid,
# #         role=role
# #     )
# #     save_user_to_database(user)
# #     return {"message": "User registered successfully"}

# # # You can run the FastAPI application with uvicorn
# # # For example: uvicorn main:app --reload


# import psycopg2
# import jwt
# from fastapi import FastAPI
# from pydantic import BaseModel

# app = FastAPI()

# class UserRegistration(BaseModel):
#     username: str
#     password: str
#     email: str
#     userid: int
#     role: str

# # Function to save user data to the database
# def save_user_to_database(user: UserRegistration, token: str):
#     conn = psycopg2.connect(
#         dbname="postgres",
#         user="shreya",
#         password="12062023",
#         host="127.0.0.1",
#         port="5432"
#     )
#     cursor = conn.cursor()
#     query = """
#     INSERT INTO users (username, password, email, userid, role, token)
#     VALUES (%s, %s, %s, %s, %s, %s)
#     """
#     values = (user.username, user.password, user.email, str(user.userid), user.role, token)
#     cursor.execute(query, values)
#     conn.commit()
#     cursor.close()
#     conn.close()

# # JWT configuration
# SECRET_KEY = "your-secret-key"
# ALGORITHM = "HS256"

# # Function to generate JWT token
# def generate_jwt_token(user_id: int, username: str, role: str) -> str:
#     payload = {
#         "user_id": user_id,
#         "username": username,
#         "role": role
#     }
#     token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
#     return token

# @app.post("/register")
# def register_user(
#     username: str,
#     password: str,
#     email: str,
#     userid: int,
#     role: str
# ):
#     user = UserRegistration(
#         username=username,
#         password=password,
#         email=email,
#         userid=userid,
#         role=role
#     )
#     token = generate_jwt_token(user.userid, user.username, user.role)
#     save_user_to_database(user, token)
#     return {"message": "User registered successfully", "token": token}


# # You can run the FastAPI application with uvicorn
# # For example: uvicorn main:app --reload
