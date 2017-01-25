from django.contrib import admin
from models import Software, Machine

# Register your models here.
admin.site.register(Software)
admin.site.register(Machine)
admin.site.site_header = 'OTSI Tool v0.1'