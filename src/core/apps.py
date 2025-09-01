from django.apps import AppConfig


class CoreConfig(AppConfig):
    name = "core"

    def ready(self):
        # Import signal handlers to ensure they're registered
        import core.handlers
