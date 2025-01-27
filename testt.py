import os

import django

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "vulnerablecode.settings")
django.setup()

print("Django initialized successfully")
