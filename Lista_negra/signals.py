# signals.py (en tu app principal)
from auditlog.models import LogEntry
from django.db.models.signals import post_save
from django.dispatch import receiver
import structlog

logger = structlog.get_logger("audit")

@receiver(post_save, sender=LogEntry)
def log_audit_entry(sender, instance, **kwargs):
    logger.info(
        "model_change",
        action=instance.action,
        model=instance.content_type.model,
        object_id=instance.object_pk,
        user_id=instance.actor_id,
        changes=instance.changes_dict,
    )