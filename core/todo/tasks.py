from celery import shared_task
from django.db import transaction
from todo.models import Task


@shared_task
def deleteCompletedTasks():
    try:
        completed_tasks = Task.objects.filter(complete=True)

        task_ids = list(completed_tasks.values_list("id", flat=True))
        print("Deleting tasks with IDs:", task_ids)

        if task_ids:
            with transaction.atomic():
                tasks = Task.objects.filter(id__in=task_ids)
                count, _ = tasks.delete()
                print(f"{count} tasks deleted.")
        else:
            print("No task IDs provided for deletion.")

    except Exception as e:
        print(f"An error occurred while deleting tasks: {e}")
