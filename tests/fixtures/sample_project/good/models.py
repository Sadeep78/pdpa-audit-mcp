from django.db import models
from django.utils import timezone


class UserProfile(models.Model):
    """User profile model with explicit deletion and retention handling."""

    email = models.EmailField(unique=True)
    full_name = models.CharField(max_length=255)
    phone = models.CharField(max_length=20)
    created_at = models.DateTimeField(default=timezone.now)
    retention_period_days = models.IntegerField(default=365)

    def delete_user_data(self):
        """Explicit erasure and anonymization of personal data upon request."""
        self.email = f"anonymized_{self.id}@deleted.local"
        self.full_name = "Deleted User"
        self.phone = ""
        self.save()

    def purge_expired_records(self):
        """Retention management to purge records past retention window."""
        cutoff = timezone.now() - timezone.timedelta(days=self.retention_period_days)
        UserProfile.objects.filter(created_at__lt=cutoff).delete()
