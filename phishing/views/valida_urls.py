from phishing.forms import UrlsForm, ArchivoForm
from django.shortcuts import render
from phishing.aux import entrada, phishing
from phishing.models import Url
from django.db.models import Count, Q

def cuenta_urls(sitios):
    return sitios.count()

def urls_activas(sitios):
    return sitios.filter(codigo__gte=200, codigo__lt=300)

def urls_inactivas(sitios):
    return sitios.filter(Q(codigo__lt=200)|Q(codigo__gte=400))

def urls_redirecciones(sitios):
    return sitios.filter(codigo__gte=300, codigo__lt=400)

def urls_entidades(sitios):  
    return [(x['sitios__sitioactivoinfo__entidad_afectada'], x['cuenta'])
            for x in sitios.exclude(
                    sitios__sitioactivoinfo__entidad_afectada__isnull=True).values(
                        'sitios__sitioactivoinfo__entidad_afectada').annotate(
                            cuenta=Count('sitios__sitioactivoinfo__entidad_afectada'))]
        
def urls_titulos(sitios):
    return [(x['sitios__sitioactivoinfo__titulo'], x['cuenta'])
            for x in sitios.exclude(sitios__sitioactivoinfo__titulo__isnull=True).values(
                        'sitios__sitioactivoinfo__titulo').annotate(
                            cuenta=Count('sitios__sitioactivoinfo__titulo'))]

def urls_dominios(sitios):
    return [(x['dominio__dominio'], x['cuenta'])
            for x in sitios.values('dominio__dominio').annotate(cuenta=Count('dominio__dominio'))]

def urls_paises(sitios):
    return [(x['dominio__pais'], x['cuenta'])
            for x in sitios.exclude(dominio__pais__isnull=True).values(
                    'dominio__pais').annotate(cuenta=Count('dominio__pais'))]

def context_reporte(sitios):
    activas = urls_activas(sitios)
    inactivas = urls_inactivas(sitios)
    redirecciones = urls_redirecciones(sitios)
    context = {
        'urls_total': cuenta_urls(sitios),
        'num_urls_activas': len(set([x.url for x in activas])),
        'num_urls_inactivas': len(set([x.url for x in inactivas])),
        'num_urls_redirecciones': len(set([x.url for x in redirecciones])),
        'entidades': urls_entidades(sitios),
        'titulos': urls_titulos(sitios),
        'dominios': urls_dominios(sitios),
        'paises': urls_paises(sitios),
        'activas': activas,
        'inactivas': inactivas,
        'redirecciones': redirecciones
    }
    return context

def valida_urls(request):
    if request.method == 'POST':
        if request.POST.get("boton_urls"):
            form = UrlsForm(request.POST) 
            if form.is_valid():                
                urls = form.cleaned_data['urls']
                urls_limpias = []
                for x in urls.split('\n'):
                    x = x.strip()
                    if x:
                        for y in x.split(','):
                            for z in y.split(' '):
                                z = z.strip()
                                if z:
                                    urls_limpias.append(z)
                urls_limpias = list(set(urls_limpias))
                sitios = phishing.verifica_urls(urls_limpias, None, False)
                no_reportados = False
                for x in sitios:
                    if not x.reportado:
                        no_reportados = True
                        break
                urls = Url.objects.filter(pk__in=[x.pk for x in sitios]).distinct()
                urls = urls.prefetch_related('sitios__sitioactivoinfo')
                context = context_reporte(urls)
                context['no_reportados'] = no_reportados
                return render(request, 'valida_urls/reporte_validacion.html', context)
        elif request.POST.get("boton_archivo") and request.FILES.get('file', None):
            form = ArchivoForm(request.POST)
            f = request.FILES['file'].read().decode('utf-8')
            name = request.FILES['file'].name
            urls = []            
            if name.endswith('.json'):
                urls = entrada.lee_json(f)
            elif name.endswith('.csv'):
                urls = entrada.lee_csv(f)
            else:
                urls = entrada.lee_txt(f)
            urls = list(set(urls))
            sitios = phishing.verifica_urls(urls, None, False)
            no_reportados = False
            for x in sitios:
                if not x.reportado:
                    no_reportados = True
                    break
            urls = Url.objects.filter(pk__in=[x.pk for x in sitios]).distinct()
            urls = urls.prefetch_related('sitios__sitioactivoinfo')
            context = context_reporte(urls)
            context['no_reportados'] = no_reportados
            return render(request, 'valida_urls/reporte_validacion.html', context)
    form1 = UrlsForm()
    form2 = ArchivoForm()
    return render(request, 'valida_urls/valida_urls.html', {'form1': form1, 'form2': form2})
