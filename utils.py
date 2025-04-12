from passlib.context import CryptContext
import smtplib
from email.message import EmailMessage
from .config import settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str):
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str):
    return pwd_context.verify(plain_password, hashed_password)

def send_verification_email(email: str, token: str):
    msg = EmailMessage()
    msg['Subject'] = 'Verify Your Email'
    msg['From'] = settings.FROM_EMAIL
    msg['To'] = email
    msg.set_content(f"Click the link to verify your account: http://localhost:8000/verify?token={token}")

    try:
        with smtplib.SMTP(settings.EMAIL_HOST, settings.EMAIL_PORT) as server:
            server.starttls()
            server.login(settings.EMAIL_USERNAME, settings.EMAIL_PASSWORD)
            server.send_message(msg)
            print("Verification email sent successfully!")
    except Exception as e:
        print("Failed to send email:", e)

def send_reset_email(email: str, token: str):
    msg = EmailMessage()
    msg['Subject'] = 'Reset Your Password'
    msg['From'] = settings.FROM_EMAIL
    msg['To'] = email
    msg.set_content(f"Click the link to reset your password: http://localhost:8000/reset-password?token={token}")

    try:
        with smtplib.SMTP(settings.EMAIL_HOST, settings.EMAIL_PORT) as server:
            server.starttls()
            server.login(settings.EMAIL_USERNAME, settings.EMAIL_PASSWORD)
            server.send_message(msg)
            print("Password reset email sent successfully!")
    except Exception as e:
        print("Failed to send reset email:", e)
