from django.contrib.auth.decorators import login_required
from django.urls import reverse_lazy
from django.utils import timezone
from phishing.forms import HistoricoForm
from phishing.models import Url
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
    urls = Url.objects.filter(timestamp_creacion__gte=inicio, timestamp_creacion__lte=fin)
    context = aux.context_reporte(urls)
    context['inicio'] = inicio
    context['fin'] = fin
    context['form'] = form
    return render(request, 'historico.html', context)
