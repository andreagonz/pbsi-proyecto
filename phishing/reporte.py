from .models import Url

def cuenta_urls(sitios):
    return len(set([x.url for x in sitios]))

def urls_activas(sitios):
    urls = []
    for sitio in sitios:
        if sitio.codigo < 300 and sitio.codigo >= 200:
            urls.append(sitio)
    return urls

def urls_inactivas(sitios):
    urls = []
    for sitio in sitios:
        if sitio.codigo >= 400 or sitio.codigo < 0:
            urls.append(sitio)
    return urls

def urls_redirecciones(sitios):
    urls = []
    for sitio in sitios:
        if sitio.codigo < 400 and sitio.codigo >= 300:
            urls.append(sitio)
    return urls

def urls_entidades(sitios):
    entidades = {}
    for x in sitios:
        for e in x.entidades_afectadas.all():
            entidades[e.nombre.title()] = entidades.get(e.nombre.title(), 0) + 1
    return entidades
        
def urls_titulos(sitios):
    titulos = {}
    for x in sitios:
        titulos[x.titulo] = titulos.get(x.titulo, 0) + 1
    return titulos

def urls_dominios(sitios):
    dominios = {}
    for x in sitios:
        if not x.dominio is None:
            dominios[x.dominio.dominio] = dominios.get(x.dominio.dominio, 0) + 1
    return dominios

def urls_paises(sitios):
    paises = {}
    for x in sitios:
        paises[x.pais] = paises.get(x.pais, 0) + 1
    return paises
