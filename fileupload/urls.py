from django.urls import path
from . import views

urlpatterns = [
    path('', views.file_upload, name='file_upload'),
    path('search/', views.hash_search, name='hash_search'),
]
