from django.urls import path
from . import views

app_name = 'vault'

urlpatterns = [
    path('', views.dashboard, name='dashboard'),
    path('item/<int:pk>/', views.item_detail, name='item_detail'),
    path('create/', views.create_item, name='create_item'),
    path('api/dek/', views.get_encrypted_dek, name='get_encrypted_dek'),
    path('api/raw-dek/', views.get_raw_dek, name='get_raw_dek'),
]
