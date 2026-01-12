from celery import Celery
import os

celery = Celery(
    "log_analyzer",
    broker="redis://localhost:6379/0",
    backend="redis://localhost:6379/0"
)

# Configuration
celery.conf.update(
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='UTC',
    enable_utc=True,
    imports=['tasks'],  # This tells Celery to import tasks module
    task_always_eager=False,
)

def make_celery(app):
    celery.conf.update(app.config)

    class ContextTask(celery.Task):
        def __call__(self, *args, **kwargs):
            with app.app_context():
                return self.run(*args, **kwargs)

    celery.Task = ContextTask
    return celery
