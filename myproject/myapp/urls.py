from django.urls import path
from . import views
urlpatterns = [
    path('',views.home,name='home'),
    path('login/',views.login,name='login'),
    path('registration/',views.registration,name='registration'),
    path('healthinsights/',views.healthinsights,name='healthinsights'),
    path('wellnesstracking/',views.wellnesstracking,name='wellnesstracking'),
    path('logout/', views.logout, name='logout'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path("suggestions/", views.health_suggestions, name="suggestions"),
    
]
