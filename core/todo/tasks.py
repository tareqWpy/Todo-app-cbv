import logging

from celery import shared_task
from django.db import transaction
from todo.models import Task

logger = logging.getLogger(__name__)


@shared_task
def deleteCompletedTasks():
    try:
        completed_tasks = Task.objects.filter(complete=True)
        logger.info(f"Found {completed_tasks.count()} completed tasks.")
        task_ids = list(completed_tasks.values_list("id", flat=True))
        logger.info("Deleting tasks with IDs: %s", task_ids)
        if task_ids:
            with transaction.atomic():
                count, _ = Task.objects.filter(id__in=task_ids).delete()
                logger.info("%d tasks deleted.", count)
        else:
            logger.warning("No task IDs provided for deletion.")
    except Exception as e:
        logger.error("Error deleting tasks: %s", str(e))
