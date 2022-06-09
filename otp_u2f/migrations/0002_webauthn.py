# Generated by Django 3.2.9 on 2021-12-16 13:34

from django.db import migrations, models
from django.db.models import F, Value
from django.db.models.functions import Concat, Length, Mod


def add_base64_padding(apps, schema_editor):
    U2fDevice = apps.get_model('otp_u2f', 'U2fDevice')
    credential_qs = U2fDevice.objects.annotate(
        padding=Value(4) - Mod(Length('credential'), Value(4))
    )
    credential_qs.filter(padding=1).update(
        credential=Concat(F('credential'), Value('=')))
    credential_qs.filter(padding=2).update(
        credential=Concat(F('credential'), Value('==')))
    credential_qs.filter(padding=3).update(
        credential=Concat(F('credential'), Value('===')))

    public_key_qs = U2fDevice.objects.annotate(
        padding=Value(4) - Mod(Length('public_key'), Value(4))
    )
    public_key_qs.filter(padding=1).update(
        public_key=Concat(F('public_key'), Value('=')))
    public_key_qs.filter(padding=2).update(
        public_key=Concat(F('public_key'), Value('==')))
    public_key_qs.filter(padding=3).update(
        public_key=Concat(F('public_key'), Value('===')))


class Migration(migrations.Migration):

    dependencies = [
        ('otp_u2f', '0001_initial'),
    ]

    operations = [
        migrations.RenameField(
            model_name='u2fdevice',
            old_name='app_id',
            new_name='rp_id',
        ),
        migrations.RemoveField(
            model_name='u2fdevice',
            name='certificate',
        ),
        migrations.RenameField(
            model_name='u2fdevice',
            old_name='key_handle',
            new_name='credential',
        ),
        migrations.RemoveField(
            model_name='u2fdevice',
            name='transports',
        ),
        migrations.AddField(
            model_name='u2fdevice',
            name='aaguid',
            field=models.UUIDField(default='00000000-0000-0000-0000-000000000000'),
            preserve_default=False,
        ),
        migrations.RunPython(add_base64_padding),
    ]