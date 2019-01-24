from django.contrib.auth.decorators import login_required
from django.contrib.auth.mixins import LoginRequiredMixin
from django.shortcuts import render, get_object_or_404, redirect
from django.views.generic.detail import DetailView
from django.views.generic.edit import UpdateView
from phishing.models import Url, Ticket, ASN, Dominio
from django.urls import reverse_lazy
from phishing.aux import phishing
from phishing.forms import ActualizaURL
from django.http import Http404

@login_required(login_url=reverse_lazy('login'))
def url_detalle(request, pk):
    url = get_object_or_404(Url, pk=pk)
    hashes = phishing.archivo_hashes(url)
    comentarios = phishing.comentarios_sitio(url)
    context = {
        'url': url,
        'hashes': hashes,
        'comentarios': comentarios
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

@login_required(login_url=reverse_lazy('login'))
def actualiza_url(request, pk):
    url = get_object_or_404(Url, pk=pk)
    info = url.sitio_info
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
