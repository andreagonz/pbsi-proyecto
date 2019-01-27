from django.contrib import admin
from .models import *

admin.site.register(Url)
admin.site.register(Dominio)
admin.site.register(UrlRedireccion)
admin.site.register(UrlActiva)
admin.site.register(ArchivoAdjunto)
