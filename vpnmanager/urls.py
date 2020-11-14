"""vpnmanager URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path,include
from l2tp import views
from administrator import views as adminviews
urlpatterns = [
    # path('admin/', admin.site.urls),
    path('', views.login),
    path('login/', views.login),
    path('index/', views.index),
    path('info/',views.userInfo),
    path('vpnDoc/',views.readDoc),
    path('logout/', views.logout),
    #admin
    path('admin',adminviews.admin_login),
    path('edit/', adminviews.edit),
    path('add/', adminviews.add),
    path('delete/', adminviews.delete),
    path('admin_index/',adminviews.admin_index),
    path('admin_logout/',adminviews.admin_logout),

]
