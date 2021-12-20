from django.contrib import admin

from .models import U2fDevice


class U2fDeviceAdmin(admin.ModelAdmin):
    list_display = ['user', 'name', 'confirmed']

    fieldsets = [
        ('Identity', {
            'fields': ['user', 'name', 'confirmed'],
        }),
        ('Configuration', {
            'fields': [
                'rp_id', 'version', 'credential', 'aaguid', 'public_key'],
        }),
        ('State', {
            'fields': ['counter'],
        }),
    ]
    raw_id_fields = ['user']


admin.site.register(U2fDevice, U2fDeviceAdmin)
