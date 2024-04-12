from rest_framework import status
from rest_framework.response import Response
from rest_framework.decorators import api_view
from django.contrib.auth import authenticate
import jwt
from datetime import datetime, timedelta
from .models import CustomUser

@api_view(['POST'])
def register(request):
    username = request.data.get('username')
    email = request.data.get('email')
    password = request.data.get('password')
    if not (username and email and password):
        return Response({'message': 'All fields are required'}, status=status.HTTP_400_BAD_REQUEST)
    user = CustomUser.objects.create_user(username=username, email=email, password=password)
    return Response({'message': 'User registered successfully'}, status=status.HTTP_201_CREATED)

@api_view(['POST'])
def login(request):
    username = request.data.get('username')
    password = request.data.get('password')
    user = authenticate(username=username, password=password)
    if user is None:
        return Response({'message': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)
    token = jwt.encode({'username': user.username, 'exp': datetime.utcnow() + timedelta(hours=1)}, 'SECRET_KEY')
    return Response({'token': token}, status=status.HTTP_200_OK)

@api_view(['POST'])
def token_refresh(request):
    token = request.data.get('token')
    try:
        payload = jwt.decode(token, 'SECRET_KEY', algorithms=['HS256'])
        new_token = jwt.encode({'username': payload['username'], 'exp': datetime.utcnow() + timedelta(hours=1)}, 'SECRET_KEY')
        return Response({'token': new_token}, status=status.HTTP_200_OK)
    except jwt.ExpiredSignatureError:
        return Response({'message': 'Token has expired'}, status=status.HTTP_401_UNAUTHORIZED)
    except jwt.InvalidTokenError:
        return Response({'message': 'Invalid token'}, status=status.HTTP_401_UNAUTHORIZED)