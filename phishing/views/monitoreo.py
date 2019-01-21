from django.contrib.auth.decorators import login_required
from django.http import Http404
from django.urls import reverse_lazy
from phishing.models import Dominio, Url, Ticket
from phishing.forms import ProxyForm, MensajeForm
from django.shortcuts import render, get_object_or_404, redirect
from django.utils import timezone
from phishing.aux import phishing, correo
from django.conf import settings

@login_required(login_url=reverse_lazy('login'))
def monitoreo(request):
    dominios = Dominio.objects.all()
    activos = [d for d in dominios if d.activo_monitoreo]
    return render(request, 'monitoreo/monitoreo.html', context={'dominios':activos})

def url_reporta(url, ticket):
    s = url.mas_reciente
    if s:
        s.ticket = ticket
        s.save()
        i = url.sitio_info
        if i and (i.deteccion != 'P' or i.deteccion != 'M'):
            i.deteccion = 'P'
            i.timestamp_deteccion = ticket.timestamp
            i.save()
            
def url_ignora(url):
    s = url.mas_reciente
    if s:
        s.ignorado = True
        s.save()
        i = url.sitio_info
        if i:
            i.deteccion = 'N'
            i.save()
    
@login_required(login_url=reverse_lazy('login'))
def monitoreo_id(request, pk):
    dominio = get_object_or_404(Dominio, pk=pk)
    urls = dominio.urls_monitoreo
    context = {
        'dominio': dominio,
        'monitoreo': False,
        'activo': urls.count() > 0,
    }
    proxy_form = ProxyForm()
    hoy = timezone.localtime(timezone.now())
    cadena_urls = ''.join([str(x) for x in urls])
    md = phishing.md5((dominio.dominio + cadena_urls).encode('utf-8', 'backslashreplace'))
    ticket = ('%d%02d%02d%s' % (hoy.year, hoy.month, hoy.day, md[:7])).upper()
    correos = []
    for url in urls:
        for x in url.dominio.correos.all():
            correos.append(str(x))
    correos = list(set(correos))
    datos = {
        'de': settings.CORREO_DE,
        'para': ', '.join(correos),
        'asunto': correo.obten_asunto(dominio, ticket),
        'mensaje': correo.obten_mensaje(dominio, ticket)
    }
    mensaje_form = MensajeForm(initial=datos, urls=urls)
    if request.method == 'POST':
        if request.POST.get('boton-curl'):
            activo = dominio.activo_monitoreo
            if not activo:
                urls = dominio.urls.all()
            proxy_form = ProxyForm(request.POST)
            if proxy_form.is_valid():
                http = proxy_form.cleaned_data['http']
                https = proxy_form.cleaned_data['https']
                tor = proxy_form.cleaned_data['tor']
                proxies = proxy_form.cleaned_data['proxy']
                proxy = None
                if tor:
                    proxy = {'http':  'socks5://127.0.0.1:9050', 'https': 'socks5://127.0.0.1:9050'}
                elif http or https:
                    proxy = {}
                    if http:
                        proxy['http'] = http
                    if https:
                        proxy['https'] = https
                elif not proxies is None and (not proxies.http is None or
                                              not proxies.http is None):
                    proxy = {}
                    if not proxies.http is None:
                        proxy['http'] = proxies.http
                    if not proxies.https is None:
                        proxy['https'] = proxies.https
                phishing.monitorea_dominio(dominio, urls, proxy)
            cadena_urls = ''.join([str(x) for x in dominio.urls_monitoreo])
            md = phishing.md5((dominio.dominio + cadena_urls).encode('utf-8', 'backslashreplace'))
            ticket = ('%d%02d%02d%s' % (hoy.year, hoy.month, hoy.day, md[:7])).upper()
            datos = {
                'de': settings.CORREO_DE,
                'para': ', '.join(correos),
                'asunto': correo.obten_asunto(dominio, ticket),
                'mensaje': correo.obten_mensaje(dominio, ticket)
            }
            mensaje_form = MensajeForm(initial=datos, urls=urls)
            context['monitoreo'] = True
            mensaje_form.actualiza()
            context['mensaje_form'] = mensaje_form
            context['activo'] = dominio.activo_monitoreo
            context['proxy_form'] = proxy_form
            return render(request, 'monitoreo/monitoreo_id.html', context)
        elif request.POST.get('boton-mensaje'):
            if not dominio.activo_monitoreo:
                return render(request, 'monitoreo/monitoreo_error_inactivo.html', {'dominio': dominio})
            mensaje_form = MensajeForm(request.POST, urls=urls)
            if mensaje_form.is_valid():
                if not mensaje_form.cleaned_data.get('para', None):
                    if not mensaje_form._errors.get('para', None):
                        from django.forms.utils import ErrorList
                        mensaje_form._errors['para'] = ErrorList()
                    mensaje_form._errors['para'].append('Campo necesario')
                    context['mensaje_form'] = mensaje_form
                    context['proxy_form'] = proxy_form
                    return render(request, 'monitoreo/monitoreo_id.html', context)
                de = mensaje_form.cleaned_data['de']
                para = [x.strip() for x in mensaje_form.cleaned_data['para'].split(',')]
                cc = [x.strip() for x in mensaje_form.cleaned_data['cc'].split(',')]
                cco = [x.strip() for x in mensaje_form.cleaned_data['cco'].split(',')]
                asunto = mensaje_form.cleaned_data['asunto']
                mensaje = mensaje_form.cleaned_data['mensaje']
                capturas = mensaje_form.cleaned_data['capturas']
                urls_reportadas = mensaje_form.cleaned_data['urls']
                msg = correo.genera_mensaje(dominio, de, para, cc, cco, asunto, mensaje, capturas)
                enviado = correo.manda_correo(para, cc, cco, msg)
                ts = timezone.localtime(timezone.now())
                if not enviado:
                    context['dominio'] = dominio
                    return render(request, 'monitoreo/monitoreo_error.html', context)
                try:
                    ticketO = Ticket.objects.get(ticket=ticket)
                except:
                    ticketO = Ticket(ticket=ticket, timestamp=ts)
                    ticketO.save()
                for x in urls_reportadas:
                    url_reporta(x, ticketO)
                context = {
                    'dominio': dominio,
                    'urls': ', '.join([x.url for x in urls_reportadas]),
                    'de': de,
                    'para': ', '.join(para),
                    'cc': ', '.join(cc),
                    'cco': ', '.join(cco),
                    'asunto': asunto,
                    'mensaje': mensaje,
                    'capturas': capturas
                }
                return render(request, 'monitoreo/monitoreo_exito.html', context)
        elif request.POST.get('boton-ignorar') and request.user.is_superuser:
            if not dominio.activo_monitoreo:
                return render(request, 'monitoreo/monitoreo_error_inactivo.html', {'dominio': dominio})
            mensaje_form = MensajeForm(request.POST, urls=urls)
            if mensaje_form.is_valid():
                urls_ignoradas = mensaje_form.cleaned_data['urls']
                for x in urls_ignoradas:
                    url_ignora(x)
                context = {'urls' : urls_ignoradas}
                return render(request, 'monitoreo/monitoreo_ignorar_exito.html', context)
    context['mensaje_form'] = mensaje_form
    context['proxy_form'] = proxy_form
    return render(request, 'monitoreo/monitoreo_id.html', context)
