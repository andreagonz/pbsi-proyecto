from django.contrib import admin
from .models import (
    Entidades, Correo, Ofuscacion, Url,
    Dominio, Recurso, Proxy
    )


admin.site.register(Entidades)
admin.site.register(Correo)
admin.site.register(Ofuscacion)
admin.site.register(Url)
admin.site.register(Dominio)
admin.site.register(Recurso)
admin.site.register(Proxy)
