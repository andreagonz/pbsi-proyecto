from phishing.forms import UrlsForm, ArchivoForm
from django.shortcuts import render
from phishing.aux import entrada, phishing, log
from phishing.models import Url
from phishing.views import aux
import magic

def get_mime(archivo):
    try:
        f = magic.Magic(mime=True)
        return f.from_buffer(archivo)
    except Exception as e:
        log.log("Error al leer archivo de entrada: %s" % str(e), "verifica_urls.log")
    return ''
    
def verifica_urls(request):
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
                sitios = phishing.verifica_urls(urls_limpias, "verifica_urls.log")
                urls = Url.objects.filter(pk__in=[x.pk for x in sitios]).distinct()
                context = aux.context_reporte(urls)
                return render(request, 'verifica_urls/reporte_verificacion.html', context)
        elif request.POST.get("boton_archivo") and request.FILES.get('file', None):
            form = ArchivoForm(request.POST)
            f = request.FILES['file'].read()
            if not get_mime(f).startswith('text'):
                archivo = request.FILES['file'].name
                log.log("Ingresado archivo de entrada invalido: '%s'" % archivo, "verifica_urls.log")
                context = {'archivo': archivo}
                return render(request, 'verifica_urls/error_archivo.html', context)
            f = f.decode('utf-8', errors='ignore')
            name = request.FILES['file'].name
            urls = []
            if name.endswith('.json'):
                urls = entrada.lee_json(f)
            elif name.endswith('.csv'):
                urls = entrada.lee_csv(f)
            else:
                urls = entrada.lee_txt(f)
            urls = [x for x in list(set(urls)) if x]
            sitios = phishing.verifica_urls(urls, "verifica_urls.log")
            urls = Url.objects.filter(pk__in=[x.pk for x in sitios]).distinct()
            context = aux.context_reporte(urls)
            return render(request, 'verifica_urls/reporte_verificacion.html', context)
    form1 = UrlsForm()
    form2 = ArchivoForm()
    return render(request, 'verifica_urls/verifica_urls.html', {'form1': form1, 'form2': form2})
