 
from pydantic import BaseModel, EmailStr

class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class RegisterResponse(BaseModel):
    message: str
    user_id: int
    username: str

class Token(BaseModel):
    access_token: str
    refresh_token: str
    #token_type: str  
    user_id: int