from django.shortcuts import render, redirect
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth import login, logout, authenticate
from django.contrib import messages

from django.contrib.auth.decorators import login_required

@login_required
def home(request):
    return render(request,'home.html')

from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.contrib import messages

def signup_view(request):
    if request.method == 'POST':
        username = request.POST['username']
        email = request.POST['email']
        password = request.POST['password']
        confirm_password = request.POST['confirm_password']

        if password == confirm_password:
            user = User.objects.create_user(username=username, email=email, password=password)
            user.save()
            messages.success(request, 'Account created successfully!')
            return redirect('login')
        else:
            messages.error(request, 'Passwords do not match.')
    return render(request, 'signup.html')

from django.contrib.auth import authenticate, login
from django.contrib import messages

def login_view(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']

        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            messages.success(request, 'Login successful! Welcome, {}'.format(user.username))
            return redirect('home')  # Redirect to the home page or dashboard
        else:
            messages.error(request, 'Invalid username or password.')

    return render(request, 'login.html')  # Render the login page


# def logout_view(request):
#     if request.method == 'POST':
#         logout(request)
#         messages.success(request, "Logged out successfully!")
#         return redirect('login')
def logout_view(request):
    logout(request)
    return redirect('login')  # Redirect to the login page after logging out
