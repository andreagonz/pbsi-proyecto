from django.contrib.auth.decorators import login_required
from django.urls import reverse_lazy
from django.utils import timezone
from phishing.forms import HistoricoForm
from phishing.models import Url
from django.shortcuts import render

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
    sitios = Url.objects.filter(timestamp_reactivacion__date__lte=fin,
                                timestamp_reactivacion__date__gte=inicio)
    context = context_reporte(sitios)
    context['inicio'] = inicio
    context['fin'] = fin
    context['form'] = form
    return render(request, 'historico.html', context)
