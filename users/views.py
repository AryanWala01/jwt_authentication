from django.contrib.auth import authenticate
from django.contrib.auth.models import User
from django.shortcuts import render
from rest_framework.response import Response
from rest_framework.decorators import api_view, permission_classes
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated
from rest_framework import status

# **1. Login API - Generates JWT Tokens**
@api_view(["POST"])
def login(request):
    """Authenticate user and return JWT access & refresh tokens"""
    username = request.data.get("username")
    password = request.data.get("password")

    user = authenticate(username=username, password=password) #just for testing purpose, write a query to match the username and password from database
    if user:
        refresh = RefreshToken.for_user(user)  # Create JWT tokens
        return Response({
            "access": str(refresh.access_token),  # Short-lived access token
            "refresh": str(refresh)  # Long-lived refresh token
        })

    return Response({"error": "Invalid Credentials"}, status=status.HTTP_401_UNAUTHORIZED)

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
        refresh = RefreshToken(refresh_token)  # Validate refresh token
        return Response({"access": str(refresh.access_token)})  # Generate new access token
    except:
        return Response({"error": "Invalid Refresh Token"}, status=status.HTTP_401_UNAUTHORIZED)