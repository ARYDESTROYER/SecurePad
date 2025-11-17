from django.contrib import admin
from django.urls import path, include
from django.contrib.auth import views as auth_views
from vault.views import CustomLoginView, CustomLogoutView

urlpatterns = [
    path('admin/', admin.site.urls),
    path('accounts/login/', CustomLoginView.as_view(), name='login'),
    path('accounts/logout/', CustomLogoutView.as_view(), name='logout'),
    path('', include('vault.urls', namespace='vault')),
]
