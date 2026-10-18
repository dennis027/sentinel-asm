import json
import re

from django.db import migrations

CVE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def backfill(apps, schema_editor):
    """Fills Finding.cves for findings saved before it existed."""
    Finding = apps.get_model("findings", "Finding")
    batch = []
    for finding in Finding.objects.filter(cves=[]).only("id", "title", "raw_data").iterator(chunk_size=2000):
        found = sorted({m.upper() for m in CVE.findall(f"{finding.title} {json.dumps(finding.raw_data)}")})
        if found:
            finding.cves = found
            batch.append(finding)
        if len(batch) >= 500:
            Finding.objects.bulk_update(batch, ["cves"])
            batch = []
    if batch:
        Finding.objects.bulk_update(batch, ["cves"])


class Migration(migrations.Migration):
    dependencies = [("findings", "0009_knownexploitedvulnerability_finding_cves_and_more")]
    operations = [migrations.RunPython(backfill, migrations.RunPython.noop)]
