from phishing.forms import CorreoForm, CorreoArchivoForm
from django.shortcuts import render
from phishing.aux import correo, phishing
from phishing.views import aux
from phishing.models import Url

def procesa_correo(request):
    if request.method == 'POST':
        if request.POST.get("boton_correo"):
            form = CorreoForm(request.POST)
            if form.is_valid():
                c = form.cleaned_data['correo']
                resultados, urls, headers, archivos, error = correo.parsecorreo(c)
                sitios = Url.objects.none()
                urls_limpias = list(set(urls))
                if len(urls_limpias) > 0:                    
                    sitios = phishing.verifica_urls(urls, None, False)
                urls = Url.objects.filter(pk__in=[x.pk for x in sitios]).distinct()
                urls = urls.prefetch_related('sitios__sitioactivoinfo')
                context = aux.context_reporte(urls)
                context['resultados'] = resultados
                context['urls'] = urls
                context['headers'] = headers
                context['archivos'] = archivos
                context['error'] = error
                return render(request, 'procesa_correo/correo_resultados.html', context)
        elif request.POST.get("boton_archivo") and request.FILES.get('file', None):
            form = CorreoArchivoForm(request.POST)
            f = request.FILES['file'].read().decode('utf-8', 'ignore')
            name = request.FILES['file'].name
            resultados, urls, headers, archivos, error = correo.parsecorreo(f)
            sitios = Url.objects.none()
            urls_limpias = list(set(urls))
            if len(urls_limpias) > 0:                
                sitios = phishing.verifica_urls(urls, None, False)
            urls = Url.objects.filter(pk__in=[x.pk for x in sitios]).distinct()
            urls = urls.prefetch_related('sitios__sitioactivoinfo')
            context = aux.context_reporte(urls)
            context['resultados'] = resultados
            context['urls'] = urls
            context['headers'] = headers
            context['archivos'] = archivos
            context['error'] = error
            return render(request, 'procesa_correo/correo_resultados.html', context)
    form1 = CorreoForm()
    form2 = CorreoArchivoForm()
    return render(request, 'procesa_correo/correo.html', {'form1': form1, 'form2': form2})
