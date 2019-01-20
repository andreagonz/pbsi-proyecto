from django.contrib.auth.decorators import login_required
from django.urls import reverse_lazy
from django.utils import timezone
from phishing.forms import HistoricoForm
from phishing.models import SitioInfo
from django.shortcuts import render
from django.db.models import Q, Count

@login_required(login_url=reverse_lazy('login'))
def historico(request):
    fin = timezone.localtime(timezone.now()).date()
    inicio = fin
    form = HistoricoForm()
    if request.method == 'POST':
        form = HistoricoForm(request.POST)
        if form.is_valid():
            inicio = form.cleaned_data['inicio']
            fin = form.cleaned_data['fin']
    sitios = SitioInfo.objects.filter(timestamp_creacion__date__lte=fin,
                                      timestamp_creacion__date__gte=inicio)
    activos = sitios.filter(timestamp_desactivado=None).filter(redireccion=None)
    inactivos = sitios.exclude(timestamp_desactivado=None)
    redirecciones = sitios.exclude(redireccion=None)
    entidades = sitios.exclude(Q(sitioactivoinfo=None)|
                               Q(sitioactivoinfo__entidad_afectada=None)).values(
                                   'sitioactivoinfo__entidad_afectada').distinct()
    print(entidades)
    titulos = sitios.exclude(Q(sitioactivoinfo=None)|
                             Q(sitioactivoinfo__titulo=None)).values(
                                 'sitioactivoinfo__titulo').distinct()
    print(titulos)
    dominios = [(x['url__dominio__dominio'], x['cuenta'])
                for x in sitios.values('url__dominio__dominio').annotate(
                        cuenta=Count('url__dominio__dominio'))]
    print(dominios)
    paises = sitios.values('url__dominio__pais').distinct()
    paises = [(x['url__dominio__pais'], x['cuenta'])
                for x in sitios.exclude(url__dominio__pais=None).values('url__dominio__pais').annotate(
                        cuenta=Count('url__dominio__pais'))]
    print(paises)
    context = {
        'sitios_total': sitios.count(),
        'num_activos': activos.count(),
        'num_inactivos': inactivos.count(),
        'num_redirecciones': redirecciones.count(),
        'entidades': entidades,
        'titulos': titulos,
        'dominios': dominios,
        'paises': paises,
        'activas': activos,
        'inactivas': inactivos,
        'redirecciones': redirecciones
    }
    context['inicio'] = inicio
    context['fin'] = fin
    context['form'] = form
    return render(request, 'historico.html', context)
