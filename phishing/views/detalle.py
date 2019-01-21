from django.contrib.auth.decorators import login_required
from django.contrib.auth.mixins import LoginRequiredMixin
from django.shortcuts import render, get_object_or_404
from django.views.generic.detail import DetailView
from phishing.models import Url, Ticket, ASN, Dominio
from django.urls import reverse_lazy
from phishing.aux import phishing

@login_required(login_url=reverse_lazy('login'))
def url_detalle(request, pk):
    url = get_object_or_404(Url, pk=pk)
    hashes = phishing.archivo_hashes(url)
    context = {
        'url': url,
        'hashes': hashes
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
