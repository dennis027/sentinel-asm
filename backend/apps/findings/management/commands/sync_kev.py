import json

from django.core.management.base import BaseCommand, CommandError

from apps.findings.kev import load, sync


class Command(BaseCommand):
    help = "Load CISA's Known Exploited Vulnerabilities catalogue (from the internet, or a downloaded file)."

    def add_arguments(self, parser):
        parser.add_argument("--file", help="A downloaded known_exploited_vulnerabilities.json, for offline servers.")

    def handle(self, *args, **options):
        try:
            if options["file"]:
                with open(options["file"], encoding="utf-8") as handle:
                    count = load(json.load(handle))
            else:
                count = sync()
        except (OSError, ValueError) as exc:
            raise CommandError(f"Could not load the catalogue: {exc}")
        self.stdout.write(self.style.SUCCESS(f"Loaded {count} known exploited vulnerabilities."))
