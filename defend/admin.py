from django.contrib import admin

# Register your models here.
from defend.models import BlockIP, AuditEntry


@admin.register(AuditEntry)
class AuditEntryAdmin(admin.ModelAdmin):
    list_display = ['action', 'username', 'ip', 'created_at']
    list_filter = ['action', ]


admin.site.register(BlockIP)

# @admin.register(BlockIP)
# class BlockIPAdmin(admin.ModelAdmin):
#     pass
