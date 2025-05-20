from django.core.management.base import BaseCommand
from django.utils import timezone
from datetime import timedelta
from accounts.models import CustomUser


class Command(BaseCommand):
    help = 'Deletes unverified and inactive users who registered more than 2 days ago'

    def handle(self, *args, **kwargs):
        threshold = timezone.now() - timedelta(seconds=10)
        users_to_delete = CustomUser.objects.filter(is_verified=False, is_active=False, date_joined__lt=threshold)
        count = users_to_delete.count()
        users_to_delete.delete()
        self.stdout.write(self.style.SUCCESS(f"Deleted {count} unverified and inactive users."))
