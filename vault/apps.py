from django.apps import AppConfig

class VaultConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'vault'
    def ready(self):
        # Import signals to ensure UserVault is created for new users
        import vault.signals  # noqa: F401
