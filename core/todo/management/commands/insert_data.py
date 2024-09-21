import random

from accounts.models import User
from django.core.management.base import BaseCommand
from faker import Faker
from todo.models import Task


class Command(BaseCommand):
    help = "Inserting dummy data into the database"

    def __init__(self, *args, **kwargs):
        super(Command, self).__init__(*args, **kwargs)
        self.fake = Faker()

    def add_arguments(self, parser):
        parser.add_argument(
            "-u", "--users", type=int, default=1, help="Number of users to create"
        )
        parser.add_argument(
            "-t", "--tasks", type=int, default=2, help="Number of tasks to create"
        )

    def handle(self, *args, **options):
        user_count = options["users"]
        task_count = options["tasks"]

        # Check for user count
        if user_count <= 0:
            self.stdout.write(
                self.style.WARNING(
                    "No users to create! Please specify a positive user count."
                )
            )
        else:
            for _ in range(user_count):
                User.objects.create_user(email=self.fake.email(), password="9889TAAT@")
            self.stdout.write(
                self.style.SUCCESS(
                    f"{user_count} user{'s' if user_count != 1 else ''} created successfully!"
                )
            )

        # Check for task count
        if task_count <= 0:
            self.stdout.write(
                self.style.WARNING(
                    "No tasks to create! Please specify a positive task count."
                )
            )
        else:
            users = list(User.objects.all())
            if not users:
                self.stdout.write(
                    self.style.WARNING("No users available to assign tasks!")
                )
                return

            for _ in range(task_count):
                Task.objects.create(
                    title=self.fake.sentence(nb_words=3),
                    user=random.choice(users),
                    complete=random.choice([True, False]),
                )
            self.stdout.write(
                self.style.SUCCESS(
                    f"{task_count} task{'s' if task_count != 1 else ''} created successfully!"
                )
            )
