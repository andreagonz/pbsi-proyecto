from django.contrib.auth.decorators import login_required
from django.urls import reverse_lazy
from django.utils import timezone
from phishing.forms import HistoricoForm
from phishing.models import SitioInfo, Url
from django.shortcuts import render
from phishing.views import aux

@login_required(login_url=reverse_lazy('login'))
def historico(request):
    fin = timezone.localtime(timezone.now())
    inicio = fin - timezone.timedelta(days=1)
    form = HistoricoForm()
    if request.method == 'POST':
        form = HistoricoForm(request.POST)
        if form.is_valid():
            inicio = form.cleaned_data['inicio']
            fin = form.cleaned_data['fin']
    activos = SitioInfo.objects.filter(timestamp_creacion__lte=fin,
                                       timestamp_creacion__gte=inicio)

    inactivos = Url.objects.filter(timestamp_creacion__lte=fin,
                                   timestamp_creacion__gte=inicio,
                                   sitios=None)    
    urls_activos = Url.objects.filter(pk__in=[x.url.pk for x in activos])
    urls = (inactivos|urls_activos).distinct()
    context = aux.context_reporte(urls)
    context['inicio'] = inicio
    context['fin'] = fin
    context['form'] = form
    return render(request, 'historico.html', context)
