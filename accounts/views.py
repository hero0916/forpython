from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from django.contrib.auth import authenticate

from django.contrib.auth.models import update_last_login
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.response import Response
from django.contrib.sites.shortcuts import get_current_site
import json
from .utils import Util
from django.core.signing import Signer

from .models import (
    UserPersonalDetails,
    UserQualification,
    UserAddress,
    IndustryExperience,
    UserDocuments,
    UserAccount
)

roles = ['boss', 'ceo', 'superadmin', 'admin', 'manager', 'teamleader', 'employee', 'teacher', 'others']

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_current_user(request):
    user = request.user

    return JsonResponse({
        'email': user.email,
        'first_name': user.first_name,
        'last_name': user.last_name,
        'role': user.role,
        'status': user.status
    })

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def create_custom_user(request):
    data = request.data
    personal_details = data.get('personal_details')

    if personal_details is None:
        return Response( { 'msg': 'Please provide personal_details' }, status=500 )
    
    try:
        email = personal_details.get('email_address')

        if email is None:
            return Response( {'msg': 'Please provide email address'}, status=500 )
        user = UserAccount.objects.get(email=personal_details.get('email_address'))
        if user is not None:
            return Response( {'msg': 'Email address is already exists!'}, status=500 )        
    except UserAccount.DoesNotExist:
        flag = 1

    personal_details = UserPersonalDetails.from_dict(data['personal_details'])
    qualification_details = UserQualification.from_dict(data['qualification_details'])
    address = UserAddress.from_dict(data['address'])
    document_upload = UserDocuments.from_dict(data['document_upload'])

    user_account = UserAccount(
        personal_details=personal_details,
        qualification_details=qualification_details,
        address=address,
        document_upload=document_upload
        )
    user_account.save()

    industry_experiences = data.get('industry_experience')
    for experience_data in industry_experiences:
        industry_experience = IndustryExperience.from_dict(experience_data)
        industry_experience.user_account = user_account
        industry_experience.save()

    return JsonResponse({"msg": "Successfully extracted"})

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_controllable_users(request):
    role = request.user.role

    if role not in roles:
        return JsonResponse({'msg': 'This role does not exist in role controlls'}, status=500)

    index = roles.index(role) + 1
    control_roles = roles[index:]

    users = UserAccount.objects.all()
    users_with_role = users.filter(role__in=control_roles)

    user_persons = []

    for user in users_with_role:
        json_data = { 
            "id": user.id,
            "email": user.email, 
            "first_name": user.first_name, 
            "last_name": user.last_name, 
            "role": user.role, 
            "status": user.status
        }
        user_persons.append(json_data)

    return JsonResponse({"users": user_persons}, status=200)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def get_user_information(request):
    if request.data.get('id') is None:
        return Response({'msg': 'Please provide id'}, status=500)
    
    try:
        user = UserAccount.objects.get(id=request.data.get('id'))
        if roles.index(request.user.role) >= roles.index(user.role):
            return Response({'msg': 'You are not allowed to read that user'}, status=500)

    except UserAccount.DoesNotExist:
        return Response({'msg': 'That user does not exist'}, status=500)

    json_data = user.to_dict()

    return JsonResponse( json_data, status=200 )

@api_view(['POST'])
@permission_classes([])
def signin(request):
    data = request.data
    email = data.get('email', None)
    password = data.get('password', None)

    user = authenticate(email=email, password=password)

    if user is None:
        return Response( { 'msg': 'A user with this email and password is not found.' }, status=500 )

    try:
        jwt_token = RefreshToken.for_user(user)
        update_last_login(None, user)
    except UserAccount.DoesNotExist:
        return Response( { 'msg': 'User with given email and password does not exists' }, status=500 )

    if user.status != 'active':
        return Response( { 'msg': 'Your user is not allowed to login. Contact to administrator' }, status=500 )

    ret = {
        'msg': 'Uesr logged in successfully',
        'email': user.email,
        'first_name': user.first_name,
        'last_name': user.last_name,
        'role': user.role,
        'status': user.status,
        'access': str(jwt_token.access_token)
    }

    return Response( ret, status=200 )

@api_view(['POST'])
@permission_classes([])
def signup(request):
    data = request.data

    if data.get('email') is None:
        return Response( {'msg': 'Email field must not be null'}, status=500 )
    if data.get('role') is None:
        return Response( {'msg': 'Role field must not be null'}, status=500 )
        
    try:
        user = UserAccount.objects.get(email=data.get('email'))
        if user is not None:
            return Response( {'msg': 'Email address is already exists!'}, status=500 )        
    except UserAccount.DoesNotExist:
        flag = 1
        
    user_account = UserAccount(
        email=data.get('email'),
        first_name=data.get('first_name'),
        last_name=data.get('last_name'),
        role=data.get('role'))

    user_account.set_password(data.get('password'))
    user_account.status = 'pending'
    user_account.is_active = 0
    user_account.save()
    signer = Signer()

    current_site = get_current_site(request).domain
    relativeLink = "/activate/"
    absurl = 'http://'+ current_site + relativeLink + signer.sign(str(user_account.id))
    email_body = 'Hi user use link below to verify your email \n' + absurl 
    data = {'email_body': email_body,'to_email': user_account.email, 'email_subject':'Verify Your Email'}
    
    try:
        if Util.send_email(data) == True:
            return Response( { 'user': user_account.to_dict(), 'msg': 'Successfully registered' }, status=200 )
    except Exception as e:
        return Response( {'user': user_account.to_dict(), 'msg': 'Verify email has not been sent'}, status=500 )

@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def change_status(request):
    if request.data.get('id') is None:
        return Response({'msg': 'Please provide id'}, status=500)
    try:
        print(request.data.get('id'))
        user = UserAccount.objects.get(id=request.data.get('id'))
        if roles.index(request.user.role) >= roles.index(user.role):
            return Response({'msg': 'You are not allowed to change user state'}, status=500)

    except UserAccount.DoesNotExist:
        return Response({'msg': 'That user does not exist'}, status=500)

    user.status = request.data.get('status')
    user.save()

    return Response( { 'msg': 'Changing status successfully changed', 'data': user.to_dict() }, status=200 )

@api_view(['POST'])
@permission_classes([])
def email_verify(request):
    token = request.data.get('token')
    if token is None:
        return Response({ 'msg': 'Please provide token' }, status=500)

    signer = Signer()
    try:
        strid = signer.unsign(token)
    except Exception as e:
        return Response( {'msg': 'Invalid token'}, status=500)

    try:
        user = UserAccount.objects.get(id=int(strid))
        user.is_active = 1
        user.save()
        return Response( {'msg': 'Successfully registered'}, status=200 )
    except UserAccount.DoesNotExist:
        return Response( { 'msg': 'Cannot find the user' }, status=500 )

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def forgot_pass(request):
    return Response( { 'msg': 'success' }, status=200 )

@api_view(['POST'])
@permission_classes([])
def change_pass(request):
    st = '14'
    
    signer = Signer()
    crypt = signer.sign(st)
    print(crypt)
    print(signer.unsign(crypt))
    return Response( { 'msg': 'success' }, status=200 )

@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def update_custom_user(request):
    if request.data.get('id') is None:
        return Response({'msg': 'Please provide id'}, status=500)
    try:
        print(request.data.get('id'))
        user_account = UserAccount.objects.get(id=request.data.get('id'),)
        if roles.index(request.user.role) >= roles.index(user.role):
            return Response({'msg': 'You are not allowed to change user state'}, status=500)

    except UserAccount.DoesNotExist:
        return Response({'msg': 'That user does not exist'}, status=500)

    personal_details = UserPersonalDetails.from_dict(data['personal_details'])

    qualification_details = UserQualification.from_dict(data['qualification_details'])
    address = UserAddress.from_dict(data['address'])
    document_upload = UserDocuments.from_dict(data['document_upload'])

    user_account = UserAccount(
        personal_details=personal_details,
        qualification_details=qualification_details,
        address=address,
        document_upload=document_upload
        )
    user_account.save()

    industry_experiences = data.get('industry_experience')
    for experience_data in industry_experiences:
        industry_experience = IndustryExperience.from_dict(experience_data)
        industry_experience.user_account = user_account
        industry_experience.save()

    return Response( { 'msg': 'Successfully updated' }, status=200 )

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def delete_custom_user(request):
    if request.data.get('id') is None:
        return Response({'msg': 'Please provide id'}, status=500)
    try:
        user = UserAccount.objects.get(id=request.data.get('id'))
        if roles.index(request.user.role) >= roles.index(user.role):
            return Response({'msg': 'You are not allowed to change user state'}, status=500)

    except UserAccount.DoesNotExist:
        return Response({'msg': 'That user does not exist'}, status=500)

    user.delete()

    return Response( { 'msg': 'Successfully deleted!' }, status=200 )
