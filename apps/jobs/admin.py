from django.contrib import admin
from .models import Job, ContactMessage, Company
# Register your models here.

admin.site.register(Job)
admin.site.register(ContactMessage)
admin.site.register(Company)