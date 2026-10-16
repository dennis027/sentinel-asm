from django.db import migrations


def create_root_domain_assets(apps, schema_editor):
    # Organizations created before the API started doing this on
    # creation have no asset for their apex domain, so it was never
    # scanned -- see apps/assets/utils.py.
    Organization = apps.get_model("organizations", "Organization")
    Asset = apps.get_model("assets", "Asset")
    for organization in Organization.objects.all():
        Asset.objects.get_or_create(
            organization=organization,
            value=organization.root_domain,
            defaults={"asset_type": "domain"},
        )


class Migration(migrations.Migration):

    dependencies = [
        ("assets", "0001_initial"),
        ("organizations", "0003_organization_domain_verification"),
    ]

    operations = [
        migrations.RunPython(create_root_domain_assets, migrations.RunPython.noop),
    ]
