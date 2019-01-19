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
