import jwt
import datetime
from django.conf import settings
from django.shortcuts import render
from rest_framework.response import Response
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework import status
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine
from users.models import User  # Import your SQLAlchemy User model

# Setup SQLAlchemy engine and session
engine = create_engine('sqlite:///your_database.db')  # Replace with actual DB URL
Session = sessionmaker(bind=engine)

# Secret key for JWT
SECRET_KEY = settings.SECRET_KEY  # Use Django's SECRET_KEY

# Helper function to generate JWT tokens
def generate_tokens(user):
    """Generate JWT access and refresh tokens"""
    payload = {
        "user_id": user.id,
        "username": user.username,
        "exp": datetime.datetime.now() + datetime.timedelta(minutes=15),  # Access token expires in 15 min
        "iat": datetime.datetime.now(),
    }
    access_token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")

    refresh_payload = {
        "user_id": user.id,
        "exp": datetime.datetime.now() + datetime.timedelta(days=7),  # Refresh token expires in 7 days
        "iat": datetime.datetime.now(),
    }
    refresh_token = jwt.encode(refresh_payload, SECRET_KEY, algorithm="HS256")

    return access_token, refresh_token

# **1. Login API - Generates JWT Tokens**
@api_view(["POST"])
def login(request):
    """Authenticate user and return JWT access & refresh tokens"""
    username = request.data.get("username")
    password = request.data.get("password")

    session = Session()
    try:
        user = session.query(User).filter_by(username=username).first()  # Fetch user from DB
        
        if user and user.check_password(password):  # Check password securely
            access_token, refresh_token = generate_tokens(user)
            return Response({
                "access": access_token,
                "refresh": refresh_token
            })
        return Response({"error": "Invalid Credentials"}, status=status.HTTP_401_UNAUTHORIZED)
    
    finally:
        session.close()

# **2. Home API - Protected Route**
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def home(request):
    """Protected home page that requires authentication"""
    return Response({"message": f"Welcome, {request.user.username}!"})

# **3. Refresh Token API**
@api_view(["POST"])
def refresh_token(request):
    """Use refresh token to get a new access token"""
    refresh_token = request.data.get("refresh")
    
    try:
        decoded_token = jwt.decode(refresh_token, SECRET_KEY, algorithms=["HS256"])
        session = Session()
        user = session.query(User).filter_by(id=decoded_token["user_id"]).first()
        
        if not user:
            return Response({"error": "Invalid Refresh Token"}, status=status.HTTP_401_UNAUTHORIZED)

        access_token, _ = generate_tokens(user)  # Generate new access token
        return Response({"access": access_token})

    except jwt.ExpiredSignatureError:
        return Response({"error": "Refresh Token Expired"}, status=status.HTTP_401_UNAUTHORIZED)
    except jwt.InvalidTokenError:
        return Response({"error": "Invalid Refresh Token"}, status=status.HTTP_401_UNAUTHORIZED)
    finally:
        session.close()

# **4. Signup API - User Registration**
@api_view(["POST"])
def signup(request):
    """Register a new user"""
    username = request.data.get("username")
    password = request.data.get("password")

    if not username or not password:
        return Response({"error": "All fields are required"}, status=status.HTTP_400_BAD_REQUEST)

    session = Session()
    try:
        if session.query(User).filter_by(username=username).first():
            return Response({"error": "Username already exists"}, status=status.HTTP_400_BAD_REQUEST)

        user = User(username=username)
        user.set_password(password)  # Hash password before saving
        session.add(user)
        session.commit()

        return Response({"message": "User created successfully"}, status=status.HTTP_201_CREATED)

    finally:
        session.close()
