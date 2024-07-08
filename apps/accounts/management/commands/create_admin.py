from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model


class Command(BaseCommand):
    help = 'Create an initial admin User'

    def handle(self, *args, **kwargs):
        User = get_user_model()
        if not User.objects.filter(email='', user_type="Moderator").exists():
            User.objects.create_superuser(
                email='',
                name='',
                password=''
            )
            self.stdout.write(self.style.SUCCESS('Successfully created the admin user'))
        else:
            self.stdout.write(self.style.WARNING('Admin user already exists'))
