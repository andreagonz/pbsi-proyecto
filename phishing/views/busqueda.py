from django.contrib.postgres.search import SearchQuery, SearchVector
from django.contrib.auth.decorators import login_required
from django.urls import reverse_lazy
from django.shortcuts import render
from phishing.models import Url

@login_required(login_url=reverse_lazy('login'))
def busqueda(request):
    message = "No se encontraron coincidencias"
    resultados = []
    q = ''
    if request.method == "GET" and request.GET.get('q', None):
        q = request.GET['q'].strip()
        resultados = Url.objects.annotate(
            search=SearchVector('url') + SearchVector('dominio__dominio') +
            SearchVector('entidades_afectadas__clasificacion__nombre') +
            SearchVector('entidades_afectadas__nombre') +
            SearchVector('ofuscacion__nombre') + SearchVector('dominio__correos__correo') +
            SearchVector('dominio__rir__nombre') + SearchVector('dominio__dns__nombre') +
            SearchVector('dominio__ip') + SearchVector('dominio__pais') +
            SearchVector('dominio__asn') + SearchVector('dominio__isp') +
            SearchVector('identificador') + SearchVector('titulo') +
            SearchVector('hash_archivo') + SearchVector('redireccion') +
            SearchVector('dominio__servidor') +
            SearchVector('mensajeurl__mensaje__ticket')
        ).filter(search=SearchQuery(q)).distinct('url')            
    return render(request, 'busqueda.html',
                  {'resultados': resultados,
                   'query': q
                  })
