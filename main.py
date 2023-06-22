from fastapi import FastAPI,responses,Depends, HTTPException, status, Request
from asyncpg import create_pool
from typing import List, Annotated
from pydantic import BaseModel
import psycopg2
from jose import JWTError, jwt
import bcrypt
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from typing import Optional
from datetime import datetime, timedelta,date
from psycopg2 import sql

app = FastAPI()

database_url = "postgresql://shreya:12062023@localhost/postgres"
pool=None
async def get_pool():
    global pool
    if pool is None:
        pool = await create_pool(database_url)
    return pool

conn = psycopg2.connect(
    dbname="postgres",
    user="shreya",
    password="12062023",
    host="127.0.0.1",
    port="5432"
)

SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Book model
class Book(BaseModel):
    book_id: int
    title: str
    author: str
    publication_date: int

# Issue model
class Issue(BaseModel):
    issue_id: int
    user_id: int
    book_id: int
    issue_date: str
    return_date: str = None

class User(BaseModel):
    user_id: int    
    username: str
    password: str
    email: str  
    role: str 
    disabled: bool | None = None

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: str | None = None

class UserInDB(User):
    hashed_password: str
    user_id: Optional[int]=None
    password: Optional[str]=None
    role: Optional[str]=None


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

async def close_pool():
    if pool is not None:
        await pool.close()
@app.on_event("startup")
async def startup_event():
    await get_pool()
@app.on_event("shutdown")
async def shutdown_event():
    await close_pool()

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def get_user_from_db(username: str):
    with conn.cursor() as cur:
        query = sql.SQL("SELECT * FROM users WHERE username = %s;")
        cur.execute(query, (username,))
        user_data = cur.fetchone()

    if user_data:
        user_id, username, password, email, role = user_data
        return UserInDB(
            username=username,
            hashed_password=password,
            email=email,
            role=role,
        )
    return None

def authenticate_user(username: str, password: str):
    user = get_user_from_db(username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user

def authenticate_user(username: str, password: str):
    user = get_user_from_db(username)
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


async def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        user = get_user_from_db(username)
        if user is None:
            raise HTTPException(status_code=401, detail="Invalid user")
        return user
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    
async def get_current_active_user(current_user: Annotated[User, Depends(get_current_user)]):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

@app.get("/users/me/", response_model=User)
async def read_users_me(current_user: Annotated[User, Depends(get_current_active_user)]):
    return current_user


@app.get("/")
async def index():
    return {"message": "Welocome to the Library Management System!"}

@app.post("/register")
async def register(request: Request, username: str, password: str, email: str, role: str):
    connection = await (await get_pool()).acquire()
    try:
        async with connection.transaction():
            hashed_password = get_password_hash(password)  # Hash the password
            await connection.execute(
                "INSERT INTO users (username, password, email, role) VALUES ($1, $2, $3, $4)",
                username, hashed_password, email, role
            )
        return {"message": "User registered successfully"}
    finally:
        await (await get_pool()).release(connection)


@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
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



@app.get("/books", response_model=List[Book])
async def list_books():
    cursor = conn.cursor()
    cursor.execute("SELECT book_id, title, author, publication_date FROM books")
    results = cursor.fetchall()
    cursor.close()
    books = []
    for result in results:
        book_id, title, author, publication_date = result
        books.append(Book(book_id=book_id, title=title, author=author, publication_date=publication_date))
    return books


@app.post("/books")
async def create_book(request: Request,
    book_id:int, title:str, author:str, publication_date:int,
    current_user: User = Depends(get_current_user)
):
    if current_user.username != "admin":
        raise HTTPException(status_code=403, detail="User not authorized")
    query = "INSERT INTO books (book_id, title, author, publication_date) VALUES (%s ,%s, %s, %s) RETURNING book_id;"
    with conn.cursor() as cursor:
        cursor.execute(query, (book_id,title, author, publication_date))
        book_id = cursor.fetchone()[0]
        conn.commit()
    # conn.close()
    return {"book_id": book_id, "message": "Book created successfully"}

async def add_issue_to_db(book_id:int, user_id:int):
    # Your database connection logic here
    issue_date=date.today()
    return_date=None
    query = """
        INSERT INTO issue ( user_id, book_id, issue_date, return_date)
        VALUES (%s, %s, %s, %s)
    """
    values = (user_id, book_id, issue_date,return_date)

    # Execute the query and handle any exceptions
    try:
        with conn.cursor() as cur:
            cur.execute(query, values)
            conn.commit()
    except Exception as e:
        # Handle the exception according to your application's error handling logic
        print(f"An error occurred while adding the issue to the database: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to add issue")

    return {"message": "Book issued successfully"}

@app.post("/issue-book")
async def issue_book(book_id:int, user_id:int, current_user: User = Depends(get_current_user)):
    if current_user.username == "admin":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Admins cannot issue books")
    
    # Perform the necessary operations to update the "issue" table with the provided issue details
    try:
        await add_issue_to_db(book_id, user_id)
    except:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to add issue")

    return {"message": "Book issued successfully"}

@app.post("/return-book/{issue_id}")
async def return_book(issue_id: int, user_id: int, current_user: User = Depends(get_current_user)):
    if current_user.username == "admin":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Admins cannot return books")

    # Check if the issue exists and belongs to the current user
    query = "SELECT * FROM issue WHERE issue_id = $1 AND user_id = $2"
    values = (issue_id, user_id)

    try:
        connection = await (await get_pool()).acquire()
        async with connection.transaction():
            issue_data = await connection.fetchrow(query, *values)

        if issue_data is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Issue not found or does not belong to the user")
    except Exception as e:
        error_detail = f"An error occurred while checking the issue: {str(e)}"
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=error_detail)
    finally:
        await (await get_pool()).release(connection)

    # Perform the necessary operations to update the "issue" table and mark the book as returned
    query = "UPDATE issue SET return_date = $1 WHERE issue_id = $2 AND user_id = $3"
    return_date = date.today()
    values = (return_date, issue_id, user_id)

    try:
        connection = await (await get_pool()).acquire()
        async with connection.transaction():
            await connection.execute(query, *values)
    except Exception as e:
        error_detail = f"An error occurred while updating the issue: {str(e)}"
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=error_detail)
    finally:
        await (await get_pool()).release(connection)

    return {"message": "Book returned successfully"}

