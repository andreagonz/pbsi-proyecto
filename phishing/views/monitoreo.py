from django.contrib.auth.decorators import login_required
from django.http import Http404
from django.urls import reverse_lazy
from phishing.models import Dominio, Url
from phishing.forms import ProxyForm

@login_required(login_url=reverse_lazy('login'))
def monitoreo(request):
    dominios = Dominio.objects.all()
    activos = [d for d in dominios if d.activo_monitoreo]
    return render(request, 'monitoreo/monitoreo.html', context={'dominios':activos})

def url_reporta(url, ts):
    url.reportado = True
    if url.deteccion == 'I':
        url.timestamp_deteccion = ts
        url.deteccion = 'P'
    url.save()

def url_ignora(url):
    url.ignorado = True
    url.deteccion = 'N'
    url.save()

@login_required(login_url=reverse_lazy('login'))
def monitoreo_id(request, pk):
    dominio = get_object_or_404(Dominio, pk=pk)
    if not dominio.activo:
        raise Http404()
    urls = dominio.urls_activas
    context = {
        'dominio': dominio,
        'monitoreo': False,
        'activo': True,
    }
    proxy_form = ProxyForm()
    hoy = timezone.localtime(timezone.now())
    md = md5(dominio.dominio.encode('utf-8', 'backslashreplace'))
    ticket = ('%d%02d%02d%s' % (hoy.year, hoy.month, hoy.day, md[:7])).upper()
    correos = []
    for url in urls:
        for x in url.dominio.correos.all():
            correos.append(str(x))
    correos = list(set(correos))
    datos = {
        'de': settings.CORREO_DE,
        'para': ', '.join(correos),
        'asunto': obten_asunto(dominio, ticket),
        'mensaje': obten_mensaje(dominio, ticket)
    }
    mensaje_form = MensajeForm(initial=datos, urls=urls)
    if request.method == 'POST':
        if request.POST.get('boton-curl'):
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
                monitorea_dominio(dominio.dominio, dominio.urls_activas, proxy)
            context['monitoreo'] = True
            mensaje_form.actualiza()
            context['mensaje_form'] = mensaje_form
            context['activo'] = dominio.activo
            context['proxy_form'] = proxy_form
            return render(request, 'monitoreo_id.html', context)
        elif request.POST.get('boton-mensaje'):
            # if not dominio.activo:
            # return render(request, 'monitoreo_error.html', {'dominio': dominio})
            mensaje_form = MensajeForm(request.POST, urls=urls)
            if mensaje_form.is_valid():
                if not mensaje_form.cleaned_data.get('para', None):
                    if not mensaje_form._errors.get('para', None):
                        from django.forms.utils import ErrorList
                        mensaje_form._errors['para'] = ErrorList()
                    mensaje_form._errors['para'].append('Campo necesario')
                    context['mensaje_form'] = mensaje_form
                    context['proxy_form'] = proxy_form
                    return render(request, 'monitoreo_id.html', context)
                de = mensaje_form.cleaned_data['de']
                para = [x.strip() for x in mensaje_form.cleaned_data['para'].split(',')]
                cc = [x.strip() for x in mensaje_form.cleaned_data['cc'].split(',')]
                cco = [x.strip() for x in mensaje_form.cleaned_data['cco'].split(',')]
                asunto = mensaje_form.cleaned_data['asunto']
                mensaje = mensaje_form.cleaned_data['mensaje']
                capturas = mensaje_form.cleaned_data['capturas']
                urls_reportadas = mensaje_form.cleaned_data['urls']
                msg = genera_mensaje(dominio, de, para, cc, cco, asunto, mensaje, capturas)
                enviado = manda_correo(para, cc, cco, msg)
                ts = timezone.localtime(timezone.now())
                if not enviado:
                    context['dominio'] = dominio
                    return render(request, 'monitoreo_error.html', context)
                try:
                    men = Ticket.objects.get(ticket=ticket)
                except:
                    men = Ticket(ticket=ticket)
                    men.save()
                men.timestamp = ts
                for x in urls_reportadas:
                    tsd = x.timestamp_deteccion if x.timestamp_deteccion else ts
                    mu = MensajeURL(mensaje=men, timestamp_creacion_sitio=x.timestamp_reactivacion,
                                    url=x, timestamp_deteccion=tsd)
                    mu.pais = x.dominio.pais
                    mu.asn = x.dominio.asn
                    mu.save()
                    mu.entidades_afectadas.add(*x.entidades_afectadas.all())
                    url_reporta(x, ts)
                men.save()
                context = {
                    'dominio': dominio,
                    'urls': ', '.join([url.url for x in urls_reportadas]),
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
            for x in urls:
                url_ignora(x)
            return redirect('monitoreo')
    context['mensaje_form'] = mensaje_form
    context['proxy_form'] = proxy_form
    return render(request, 'monitoreo/monitoreo_id.html', context)
