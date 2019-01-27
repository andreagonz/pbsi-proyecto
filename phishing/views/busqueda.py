from django.contrib.postgres.search import SearchQuery, SearchVector
from django.contrib.auth.decorators import login_required
from django.urls import reverse_lazy
from django.shortcuts import render
from phishing.models import Url
from django.db.models import Q

@login_required(login_url=reverse_lazy('login'))
def busqueda(request):
    message = "No se encontraron coincidencias"
    resultados = []
    q = ''
    if request.method == "GET" and request.GET.get('q', None):
        q = request.GET['q'].strip()
        try:
            n = int(q)
            resultados = Url.objects.filter(Q(codigo=n)|Q(dominio__asn__asn=n)).order_by('url', '-timestamp_creacion').distinct('url')
            return render(request, 'busqueda.html',
                  {'resultados': resultados,
                   'query': q
                  })
        except Exception as e:
            pass
        resultados = Url.objects.annotate(
            search=SearchVector('url') + SearchVector('dominio__dominio') +
            SearchVector('dominio__rir__nombre') + SearchVector('dominio__dns__nombre') +
            SearchVector('dominio__ip') + SearchVector('dominio__pais') +
            SearchVector('dominio__asn__nombre') + SearchVector('dominio__correos__correo') +
            SearchVector('dominio__isp') + SearchVector('dominio__servidor') +
            SearchVector('urlactiva__titulo') +
            SearchVector('urlactiva__entidad_afectada__nombre') +
            SearchVector('urlactiva__entidad_afectada__clasificacion__nombre') +
            SearchVector('urlactiva__ofuscaciones__nombre') +
            SearchVector('urlactiva__hash_archivo') +
            SearchVector('urlredireccion__redireccion__url') + SearchVector('ticket__ticket') +
            SearchVector('urlredireccion__redireccion_final__url')
        ).filter(search=SearchQuery(q)).order_by('url', '-timestamp_creacion').distinct('url')
    return render(request, 'busqueda.html',
                  {'resultados': resultados,
                   'query': q
                  })
