from phishing.forms import UrlsForm, ArchivoForm
from django.shortcuts import render
from phishing.aux import entrada, phishing
from phishing.models import Url
from phishing.views import aux

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
                context = aux.context_reporte(urls)
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
            context = aux.context_reporte(urls)
            context['no_reportados'] = no_reportados
            return render(request, 'valida_urls/reporte_validacion.html', context)
    form1 = UrlsForm()
    form2 = ArchivoForm()
    return render(request, 'valida_urls/valida_urls.html', {'form1': form1, 'form2': form2})
