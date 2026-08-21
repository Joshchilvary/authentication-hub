from django.db import migrations


def update_site_domain(apps, schema_editor):
    Site = apps.get_model('sites', 'Site')
    site = Site.objects.filter(pk=1).first()
    if site:
        site.domain = 'authentication-hub.onrender.com'
        site.name = 'Authentication Hub'
        site.save()


def reverse_update_site_domain(apps, schema_editor):
    Site = apps.get_model('sites', 'Site')
    site = Site.objects.filter(pk=1).first()
    if site:
        site.domain = '127.0.0.1:8000'
        site.name = 'Authentication Hub'
        site.save()


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0011_add_emergency_event_types'),
    ]

    operations = [
        migrations.RunPython(update_site_domain, reverse_update_site_domain),
    ]
