def procesa_correo(request):
    if request.method == 'POST':
        if request.POST.get("boton_correo"):
            form = CorreoForm(request.POST)
            if form.is_valid():
                c = form.cleaned_data['correo']
                resultados, urls, headers, archivos, error = parsecorreo(c)
                sitios = []
                if len(urls) > 0:
                    sitios = verifica_urls(urls, None, False)
                context = context_reporte(sitios)                    
                context['resultados'] = resultados
                context['urls'] = urls
                context['headers'] = headers
                context['archivos'] = archivos
                context['error'] = error
                return render(request, 'correo_resultados.html', context)
        elif request.POST.get("boton_archivo") and request.FILES.get('file', None):
            form = CorreoArchivoForm(request.POST)
            f = request.FILES['file'].read().decode('utf-8', 'ignore')
            name = request.FILES['file'].name
            urls = []
            resultados, urls, headers, archivos, error = parsecorreo(f)
            context = {}
            if len(urls) > 0:
                sitios = verifica_urls(urls, None, False)
                context = context_reporte(sitios)
            context['resultados'] = resultados
            context['urls'] = urls
            context['headers'] = headers
            context['archivos'] = archivos
            context['error'] = error
            return render(request, 'correo_resultados.html', context)
    form1 = CorreoForm()
    form2 = CorreoArchivoForm()
    return render(request, 'correo.html', {'form1': form1, 'form2': form2})
