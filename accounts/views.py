from django.shortcuts import render, redirect
from django.contrib import messages, auth
from django.core.validators import validate_email
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required

def login(request):
    if request.method != 'POST':
        return render(request, 'accounts/login.html')
    
    user = request.POST.get('user')
    password = request.POST.get('password')

    users = auth.authenticate(request, username=user, password=password)

    if not users:
        messages.error(request, 'Usuário ou senha inválidos.')
        return render(request, 'accounts/login.html')
    else:
        auth.login(request, users)
        messages.success(request, 'Login efetuado com sucesso.')
        return redirect('dashboard')

def logout(request):
    auth.logout(request)
    return redirect('dashboard')


def register(request):
    if request.method != 'POST':
        return render(request, 'accounts/register.html')

    name = request.POST.get('name')
    last_name = request.POST.get('last_name')
    email = request.POST.get('email')
    user = request.POST.get('user')
    password = request.POST.get('password')
    password2 = request.POST.get('password2')

    if not name or not last_name or not email or not user or not password or not password2:
        messages.error(request, "Nenhum campo pode estar vazio")
        return render(request, 'accounts/register.html')

    try:
        validate_email(email)
    except:
        messages.error(request, 'Email inválido.')
        return render(request, 'accounts/register.html')
    
    if len(password) < 6:
        messages.error(request, 'Senha precisa ter 6 caracteres ou mais.')
        return render(request, 'accounts/register.html')

    if len(user) < 6:
        messages.error(request, 'Usuário precisa ter 6 caracteres ou mais.')
        return render(request, 'accounts/register.html')

    if password != password2:
        messages.error(request, 'Senhas não conferem.')
        return render(request, 'accounts/register.html')
    
    if User.objects.filter(username=user).exists():
        messages.error(request, 'Usuário já existe')
        return render(request, 'accounts/register.html')

    if User.objects.filter(email=email).exists():
        messages.error(request, 'Email já existe')
        return render(request, 'accounts/register.html')
    
    messages.success(request, 'Cadastro realizado com sucesso')
    
    users = User.objects.create_user(username=user, email=email, password=password, first_name=name, last_name=last_name)
    
    users.save()
    return redirect('login')

@login_required(redirect_field_name='login')
def dashboard(request):
    return render(request, 'accounts/dashboard.html')
