from django.contrib import admin
from .models import UserProfile, FavoriteProfiles
# Register your models here.

admin.site.register(UserProfile)
admin.site.register(FavoriteProfiles)
