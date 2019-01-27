from django.db.models import Count, Q, Count, When, Case, CharField

def cuenta_urls(urls):
    return urls.count()

def urls_activas(urls):
    return urls.filter(codigo__gte=200, codigo__lt=300, timestamp_desactivado__isnull=True)

def urls_inactivas(urls):
    return urls.filter(timestamp_desactivado__isnull=False)

def urls_redirecciones(urls):
    return urls.filter(codigo__gte=300, codigo__lt=400, timestamp_desactivado__isnull=True)

def urls_entidades(urls):
    return [(x['urlactiva__entidad_afectada__nombre'], x['cuenta'])
            for x in urls.filter(urlactiva__entidad_afectada__isnull=False).values(
                    'urlactiva__entidad_afectada__nombre').annotate(
                        cuenta=Count('urlactiva__entidad_afectada__nombre'))]

def urls_titulos(urls):
    return [(x['urlactiva__titulo'], x['cuenta'])
            for x in urls.filter(urlactiva__titulo__isnull=False).values(
                    'urlactiva__titulo').annotate(
                        cuenta=Count('urlactiva__titulo'))]

def urls_dominios(urls):
    return [(x['dominio__dominio'], x['cuenta'])
            for x in urls.values('dominio__dominio').annotate(cuenta=Count('dominio__dominio'))]

def urls_paises(urls):
    return [(x['dominio__pais'], x['cuenta'])
            for x in urls.values('dominio__pais').annotate(cuenta=Count('dominio__pais'))
            if x['dominio__pais']]

def context_reporte(urls):
    activas = urls_activas(urls)
    inactivas = urls_inactivas(urls)
    redirecciones = urls_redirecciones(urls)
    context = {
        'urls_total': cuenta_urls(urls),
        'num_urls_activas': len(set([x.url for x in activas])),
        'num_urls_inactivas': len(set([x.url for x in inactivas])),
        'num_urls_redirecciones': len(set([x.url for x in redirecciones])),
        'entidades': urls_entidades(urls),
        'titulos': urls_titulos(urls),
        'dominios': urls_dominios(urls),
        'paises': urls_paises(urls),
        'activas': activas,
        'inactivas': inactivas,
        'redirecciones': redirecciones
    }
    return context

def delta_horas(td):
    return td.total_seconds() / 3600.0
