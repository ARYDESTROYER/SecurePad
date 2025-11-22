"""
Management command to migrate items that contain base64 ciphertext in `content` into `content_encrypted` (binary).

Usage:
  python manage.py migrate_content_ciphertext --dry-run
  python manage.py migrate_content_ciphertext --commit
  python manage.py migrate_content_ciphertext --user alice --commit

The command makes conservative checks: it attempts base64 decoding and enforces a minimum decoded length.
"""
from django.core.management.base import BaseCommand
from django.contrib.auth.models import User
from vault.models import SecretItem
import base64
import re
from django.db import transaction

BASE64_RE = re.compile(r'^[A-Za-z0-9+/=\-_]+$')


class Command(BaseCommand):
    help = 'Migrate base64 ciphertext mistakenly stored in content into content_encrypted.'

    def add_arguments(self, parser):
        parser.add_argument('--dry-run', action='store_true', help='Show items that would be migrated but do not change them')
        parser.add_argument('--commit', action='store_true', help='Perform migration and update DB')
        parser.add_argument('--user', type=str, help='Limit to a single owner username')
        parser.add_argument('--min-bytes', type=int, default=16, help='Minimum number of decoded bytes to consider as ciphertext')

    def handle(self, *args, **options):
        dry_run = options['dry_run']
        commit = options['commit']
        username = options.get('user')
        min_bytes = options['min_bytes']

        if not dry_run and not commit:
            self.stdout.write(self.style.WARNING('No --commit provided; running as dry-run. Use --commit to apply changes.'))
            dry_run = True

        qs = SecretItem.objects.filter(content__isnull=False).exclude(content='')
        if username:
            try:
                user = User.objects.get(username=username)
                qs = qs.filter(owner=user)
            except User.DoesNotExist:
                self.stdout.write(self.style.ERROR(f'User {username} not found'))
                return

        candidates = []
        for item in qs:
            s = item.content.strip()
            # Quick check: typical base64 characters
            if not s:
                continue
            if not BASE64_RE.match(s):
                continue
            # Try normal padding len check by modulo 4; if odd we still try
            try:
                decoded = base64.b64decode(s, validate=True)
            except Exception:
                # try urlsafe
                try:
                    decoded = base64.urlsafe_b64decode(s + '===' )
                except Exception:
                    continue
            if len(decoded) < min_bytes:
                continue
            candidates.append((item, decoded))

        self.stdout.write(self.style.SUCCESS(f'Found {len(candidates)} candidate(s) for migration'))

        for item, decoded in candidates:
            self.stdout.write(f'Candidate: PK={item.pk} owner={item.owner.username} title="{item.title}" decoded_len={len(decoded)}')

        if dry_run:
            self.stdout.write(self.style.WARNING('Dry-run mode: no changes will be made.'))
            return

        # commit
        migrated = 0
        with transaction.atomic():
            for item, decoded in candidates:
                # Move into content_encrypted if empty or replace? We will only set if content_encrypted is null.
                if item.content_encrypted is None:
                    item.content_encrypted = decoded
                    item.content = ''
                    item.save(update_fields=['content_encrypted', 'content'])
                    migrated += 1
                else:
                    # Already has content_encrypted; skip
                    continue

        self.stdout.write(self.style.SUCCESS(f'Migrated {migrated} item(s)'))
