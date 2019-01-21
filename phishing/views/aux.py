from django.db.models import Count, Q, Count, When, Case, CharField

def cuenta_urls(sitios):
    return sitios.count()

def urls_activas(sitios):
    return sitios.filter(codigo__gte=200, codigo__lt=300)

def urls_inactivas(sitios):
    return sitios.filter(Q(codigo__lt=200)|Q(codigo__gte=400))

def urls_redirecciones(sitios):
    return sitios.filter(codigo__gte=300, codigo__lt=400)

def urls_entidades(sitios):
    return [(x['sitios__sitioactivoinfo__entidad_afectada__nombre'], x['cuenta'])
            for x in sitios.values('sitios__sitioactivoinfo__entidad_afectada__nombre').annotate(
                    cuenta=Count('sitios__sitioactivoinfo__entidad_afectada__nombre'))
            if x['sitios__sitioactivoinfo__entidad_afectada__nombre']]
        
def urls_titulos(sitios):
    return [(x['sitios__sitioactivoinfo__titulo'], x['cuenta'])
            for x in sitios.values('sitios__sitioactivoinfo__titulo').annotate(
                    cuenta=Count('sitios__sitioactivoinfo__titulo'))
            if x['sitios__sitioactivoinfo__titulo']]

def urls_dominios(sitios):
    return [(x['dominio__dominio'], x['cuenta'])
            for x in sitios.values('dominio__dominio').annotate(cuenta=Count('dominio__dominio'))]

def urls_paises(sitios):
    return [(x['dominio__pais'], x['cuenta'])
            for x in sitios.values('dominio__pais').annotate(cuenta=Count('dominio__pais'))
            if x['dominio__pais']]

def context_reporte(sitios):
    activas = urls_activas(sitios)
    inactivas = urls_inactivas(sitios)
    redirecciones = urls_redirecciones(sitios)
    context = {
        'urls_total': cuenta_urls(sitios),
        'num_urls_activas': len(set([x.url for x in activas])),
        'num_urls_inactivas': len(set([x.url for x in inactivas])),
        'num_urls_redirecciones': len(set([x.url for x in redirecciones])),
        'entidades': urls_entidades(sitios),
        'titulos': urls_titulos(sitios),
        'dominios': urls_dominios(sitios),
        'paises': urls_paises(sitios),
        'activas': activas,
        'inactivas': inactivas,
        'redirecciones': redirecciones
    }
    return context
