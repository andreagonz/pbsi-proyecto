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
                            y = y.strip()
                            if y:
                                urls_limpias.append(y)
                sitios = verifica_urls(urls_limpias, None, False)
                no_reportados = False
                for x in sitios:
                    if not x.reportado:
                        no_reportados = True
                context = context_reporte(sitios)
                context['no_reportados'] = no_reportados
                return render(request, 'valida_urls/reporte_urls.html', context)
        elif request.POST.get("boton_archivo") and request.FILES.get('file', None):
            form = ArchivoForm(request.POST)
            f = request.FILES['file'].read().decode('utf-8')
            name = request.FILES['file'].name
            urls = []            
            if name.endswith('.json'):
                urls = lee_json(f)
            elif name.endswith('.csv'):
                urls = lee_csv(f)
            else:
                urls = lee_txt(f)
            sitios = verifica_urls(urls, None, False)
            no_reportados = False
            for x in sitios:
                if not x.reportado:
                    no_reportados = True
            context = context_reporte(sitios)
            context['no_reportados'] = no_reportados
            return render(request, 'valida_urls/reporte_urls.html', context)
    form1 = UrlsForm()
    form2 = ArchivoForm()
    return render(request, 'valida_urls/valida_urls.html', {'form1': form1, 'form2': form2})
