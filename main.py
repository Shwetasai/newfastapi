from fastapi import FastAPI, HTTPException, Depends
from sqlalchemy.orm import Session
from . import models, schemas, database, utils, auth
from fastapi.middleware.cors import CORSMiddleware
from jose import jwt, JWTError
from .config import settings
from .utils import send_verification_email

models.Base.metadata.create_all(bind=database.engine)

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

def get_db():
    db = database.SessionLocal()
    try:
        yield db
    finally:
        db.close()

@app.post("/register")
def register(user: schemas.UserCreate, db: Session = Depends(get_db)):
    existing_user = db.query(models.User).filter(models.User.email == user.email).first()

    if existing_user:
        if not existing_user.is_verified:
            token = auth.create_verification_token(data={"sub": user.email})
            utils.send_verification_email(user.email, token)
            raise HTTPException(
                status_code=400, 
                detail="Email already registered but not verified. A new verification link has been sent."
            )
        raise HTTPException(status_code=400, detail="Email already registered")


    hashed_pw = utils.hash_password(user.password)
    new_user = models.User(username=user.username, email=user.email, password=hashed_pw)

    try:
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail="Something went wrong. Check logs.")

    token = auth.create_verification_token(data={"sub": user.email})

    send_verification_email(user.email, token)

    return {
        "message": "Registration successful,verification link has been send .",
        "user_id": new_user.id,
        "username": new_user.username
    }

@app.get("/verify")
def verify_email(token: str, db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        email = payload.get("sub")
        user = db.query(models.User).filter(models.User.email == email).first()

        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        user.is_verified = True
        db.commit()
        return {"message": "Email verified successfully. You can now login."}

    except JWTError:
        raise HTTPException(status_code=400, detail="Invalid or expired token")


@app.post("/login", response_model=schemas.Token)
def login(user: schemas.UserLogin, db: Session = Depends(get_db)):
    db_user = db.query(models.User).filter(models.User.email == user.email).first()
    if not db_user or not utils.verify_password(user.password, db_user.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not db_user.is_verified:
        raise HTTPException(status_code=403, detail="Email not verified")

    access_token = auth.create_access_token(data={"sub": db_user.email})
    refresh_token = auth.create_refresh_token(data={"sub": db_user.email})
    
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "user_id": db_user.id
    }

@app.post("/reset-password-request")
def reset_password_request(data: schemas.EmailRequest, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.email == data.email).first()
    if not user:
        raise HTTPException(status_code=404, detail="Email not found")

    token = auth.create_password_reset_token({"sub": user.email})
    utils.send_reset_email(user.email, token)
    return {"message": "Password reset link sent to your email"}

@app.post("/reset-password")
def reset_password(data: schemas.ResetPassword, db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(data.token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        email = payload.get("sub")
        user = db.query(models.User).filter(models.User.email == email).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        user.password = utils.hash_password(data.new_password)
        db.commit()
        return {"message": "Password reset successful"}
    except JWTError:
        raise HTTPException(status_code=400, detail="Invalid or expired token")

@app.post("/update-password")
def update_password(data: schemas.UpdatePassword, db: Session = Depends(get_db)):
    try:
        user = db.query(models.User).filter(models.User.email == data.email).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
            
        if not utils.verify_password(data.old_password, user.password):
            raise HTTPException(status_code=401, detail="Invalid current password")

        user.password = utils.hash_password(data.new_password)
        db.commit()
        return {"message": "Password updated successfully"}
    except Exception as e:
        print(f"Error updating password: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")
