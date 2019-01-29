from django.contrib.auth.decorators import login_required
from django.contrib.auth.mixins import LoginRequiredMixin
from django.shortcuts import render, get_object_or_404, redirect
from django.views.generic.detail import DetailView
from django.views.generic.edit import UpdateView
from phishing.models import Url, Ticket, ASN, Dominio, ArchivoAdjunto, UrlActiva
from django.urls import reverse_lazy
from phishing.aux import phishing
from phishing.forms import ActualizaURL, HistoricoForm
from django.http import Http404
from django.utils import timezone
from django.http import HttpResponse
from wsgiref.util import FileWrapper
import os

@login_required(login_url=reverse_lazy('login'))
def url_detalle(request, pk):
    url = get_object_or_404(Url, pk=pk)
    url = Url.objects.filter(url=url.url).latest()
    hashes = phishing.archivo_hashes(url)
    sitios = Url.objects.filter(url=url.url).order_by('-timestamp_creacion')
    context = {
        'url': url,
        'hashes': hashes,
        'sitios': sitios
    }
    return render(request, 'detalle/url_detalle.html', context)

class TicketView(LoginRequiredMixin, DetailView):

    model = Ticket
    template_name = 'detalle/ticket.html'

class ASNView(LoginRequiredMixin, DetailView):

    model = ASN
    template_name = 'detalle/asn.html'

class DominioView(LoginRequiredMixin, DetailView):

    model = Dominio
    template_name = 'detalle/dominio.html'

    def get_context_data(self, **kwargs):
        context = super(DominioView, self).get_context_data(**kwargs)
        context['urls'] = context['dominio'].urls.order_by('url', '-timestamp_creacion').distinct('url')
        return context

@login_required(login_url=reverse_lazy('login'))
def actualiza_url(request, pk):
    url = get_object_or_404(Url, pk=pk)
    info = url.obten_info
    if not info:
        raise Http404()
    context = {
        'url': url,
        'info': info,
    }
    if request.method == 'POST':
        form = ActualizaURL(request.POST, info=info)
        if form.is_valid():
            info.entidad_afectada = form.cleaned_data['entidad']
            info.deteccion = form.cleaned_data['deteccion']
            info.save()
            return redirect('url-detalle', pk=url.pk)
    context['form'] = ActualizaURL(info=info)
    return render(request, 'detalle/actualiza_url.html', context)

@login_required(login_url=reverse_lazy('login'))
def archivos_adjuntos(request):
    if not request.user.is_superuser:
        raise Http404()
    fin = timezone.localtime(timezone.now())
    inicio = fin - timezone.timedelta(days=1)
    form = HistoricoForm()
    if request.method == 'POST':
        form = HistoricoForm(request.POST)
        if form.is_valid():
            inicio = form.cleaned_data['inicio']
            fin = form.cleaned_data['fin']
    archivos = ArchivoAdjunto.objects.filter(timestamp__gte=inicio, timestamp__lte=fin)
    context = {
        'inicio': inicio,
        'fin': fin,
        'form': form,
        'archivos': archivos
    }
    return render(request, 'detalle/archivos_adjuntos.html', context)
