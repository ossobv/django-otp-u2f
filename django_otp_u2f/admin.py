from django.contrib import admin

from .models import U2fDevice


class U2fDeviceAdmin(admin.ModelAdmin):
    list_display = ['user', 'name', 'confirmed']

    fieldsets = [
        ('Identity', {
            'fields': ['user', 'name', 'confirmed'],
        }),
        ('Configuration', {
            'fields': ['app_id', 'version', 'key_handle', 'public_key',
                       'transports'],
        }),
        ('State', {
            'fields': ['counter'],
        }),
    ]
    raw_id_fields = ['user']


admin.site.register(U2fDevice, U2fDeviceAdmin)
