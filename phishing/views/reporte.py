from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.decorators import login_required
from django.views.generic import View
from django.urls import reverse_lazy
from django.shortcuts import render
from phishing.aux import log
from phishing.forms import GraficasForm

class DocumentView(LoginRequiredMixin, View):
    
    def get(self,request, *args, **kwargs):
            return render(request,'reporte.html', {'form': GraficasForm()})

def agrega_imagen(fig, documento):
    try:
        a = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(8))
        path = '/tmp/%s.png' % a
        fig.savefig(path)
        plt.clf()
        documento.add_picture(path)
        os.remove(path)
    except Exception as e:
        log.log('Error: %s' % str(e), 'reportes.log')

def url_info(u, q, d):
    if u.captura and hasattr(u.captura, 'file'):
        d.add_picture(u.captura.file, width=Inches(4.0))
    q = d.add_paragraph("")
    q.add_run("URL: %s\n" % u.url)
    q.add_run("Identificador: %s\n" % u.identificador)
    q.add_run("IP: %s\n" % u.dominio.ip)
    q.add_run("Código: %s\n" % u.codigo_estado)
    q.add_run("Fecha de creación: %s\n" % u.timestamp_creacion)
    if u.activo_redirecciones:
        q.add_run("Fecha de activación: %s\n" % u.timestamp_reactivacion)
    q.add_run("Detección: %s\n" % u.get_deteccion_display())
    q.add_run("Título: %s\n" % u.titulo)
    q.add_run("Estado: %s\n" % u.estado)                  
    q.add_run("Entidad: %s\n" % u.entidades)                    
    q.add_run("Ofuscacion: %s\n" % u.ofuscaciones)
    q.add_run("Correos: %s\n" % u.dominio.correos_abuso)
    q.add_run("ISP: %s\n" % u.dominio.isp)
    q.add_run("País: %s\n\n" % u.dominio.pais.name)
    q.add_run("ASN: %s\n" % u.dominio.asn)
    q.add_run("Servidor: %s\n" % u.dominio.servidor)
    q.add_run("RIR: %s\n" % u.dominio.rir)
    q.add_run("Servidores DNS: %s\n" % u.dominio.servidores_dns)
    if u.timestamp_deteccion:
        q.add_run("Fecha de detección: %s\n" % u.timestamp_deteccion)
    if u.timestamp_desactivado:
        q.add_run("Fecha de desactivación: %s\n" % u.timestamp_desactivado)
    if u.hash_archivo:
        q.add_run("Hash MD5 de archivo: %s\n" % u.hash_archivo)
    if u.codigo >= 300 and u.codigo < 400:
        q.add_run("Redirección: %s\n" % u.redireccion)
        r = u.get_redireccion
        if r:
            q.add_run("Redirección final: %s\n" % r.url)
                     
@login_required(login_url=reverse_lazy('login'))
def crear_doc(request):
    if request.method == 'POST':
        form = GraficasForm(request.POST)
        if form.is_valid():
            archivo = form.cleaned_data['archivo']
            sitios = form.cleaned_data['sitios']
            top_sitios = form.cleaned_data['top_sitios']
            sectores = form.cleaned_data['sectores']
            entidades = form.cleaned_data['entidades']
            detecciones = form.cleaned_data['detecciones']
            tiempo_reporte = form.cleaned_data['tiempo_reporte']
            top_paises = form.cleaned_data['top_paises']
            top_hosting = form.cleaned_data['top_hosting']
            urls_info = form.cleaned_data['urls']
            graficas = []
            rand_color = randomcolor.RandomColor()
            document = Document()
            document.add_heading('Reporte', 0)
            p = document.add_paragraph('Reporte elaborado por la herramienta ')
            p.add_run('SAAPM').bold = True
            inicio = form.cleaned_data['inicio']
            fin = form.cleaned_data['fin']
            urlsU = Url.objects.exclude(timestamp_deteccion=None).filter(
                reportado=False,
                timestamp_deteccion__date__gte=inicio,
                timestamp_deteccion__date__lte=fin
            )
            urlsMU = MensajeURL.objects.exclude(timestamp_deteccion=None).filter(
                timestamp_deteccion__date__gte=inicio,
                timestamp_deteccion__date__lte=fin
            )
            document.add_heading('Periodo',level=1)
            q = document.add_paragraph('De: ')
            q.add_run(str(inicio)).bold = True
            q.add_run('      ')
            q.add_run('A :  ')
            q.add_run(str(fin)).bold = True

            if sitios:
                sitios_activos = urlsU.filter(Q(timestamp_desactivado=None) |
                                              Q(timestamp_desactivado__date__lt=fin)).count() + \
                                              urlsMU.filter(Q(timestamp_desactivado=None) |
                                                            Q(timestamp_desactivado__date__lt=fin)).count()
                sitios_reportados = urlsMU.count()
                sitios_detectados = urlsU.count() + urlsMU.count()
                x = ['Activos', 'Reportados', 'Detectados']
                y = [sitios_activos, sitios_reportados, sitios_detectados]
                y_pos = np.arange(len(x))
                fig, ax = plt.subplots()
                ax.set_ylabel('Número de sitios')
                ax.bar(y_pos, y, align='center', alpha=0.5)
                plt.xticks(y_pos, x)
                ax.set_title('Estados de sitios phishing')
                agrega_imagen(fig, document)

            if top_sitios:
                hoy = timezone.localtime(timezone.now())
                finf = hoy if hoy.date() == fin else fin + timedelta(days=1)
                top_sitiosU = urlsU.filter(Q(timestamp_desactivado=None) |
                                           Q(timestamp_desactivado__date__lte=fin)).annotate(
                                               tiempo_vida=(
                                                   finf - F('timestamp_reactivacion')))
                tsU = [(x.url, delta_horas(x.tiempo_vida)) for x in top_sitiosU]
                top_sitiosMU = urlsMU.filter(Q(timestamp_desactivado=None) |
                                             Q(timestamp_desactivado__date__lte=fin)).annotate(
                                                 tiempo_vida=(
                                                   finf - F('timestamp_creacion_sitio')))
                tsMU = [(x.url.url, delta_horas(x.tiempo_vida)) for x in top_sitiosMU]
                top_sitios = (tsMU + tsU)
                top_sitios.sort(key=lambda x:x[1], reverse=True)
                print(top_sitios)
                top_sitios = top_sitios[:5]
                y = [x[0] for x in top_sitios]
                x = [x[1] for x in top_sitios]
                y_pos = np.arange(len(x))
                fig, ax = plt.subplots()
                fig.subplots_adjust(left=0.5)
                ax.set_xlabel('T (Horas)')
                ax.barh(y_pos, x, align='center', alpha=0.5)
                plt.yticks(y_pos, y)
                ax.set_title('Top 5 – Sitios phishing vs Tiempo de vida')
                agrega_imagen(fig, document)
                
            if sectores:
                sectoresU = urlsU.filter(~Q(entidades_afectadas=None),
                                         ~Q(entidades_afectadas__clasificacion=None)).values(
                                             'entidades_afectadas__clasificacion__nombre').annotate(
                                                 cuenta_sectores=Count(
                                                     'entidades_afectadas__clasificacion__nombre'))
                sectoresMU = urlsMU.filter(~Q(entidades_afectadas=None),
                                           ~Q(entidades_afectadas__clasificacion=None)).values(
                                               'entidades_afectadas__clasificacion__nombre').annotate(
                                                   cuenta_sectores=Count(
                                                       'entidades_afectadas__clasificacion__nombre'))
                x, y = [], []
                for s in sectoresMU:
                    try:
                        n = next(t['cuenta_sectores'] for t in sectoresU if
                                 t['entidades_afectadas__clasificacion__nombre'] == s['entidades_afectadas__clasificacion__nombre'])
                    except:
                        n = 0
                    x.append(s['entidades_afectadas__clasificacion__nombre'])
                    y.append(s['cuenta_sectores'] + n)
                for s in sectoresU:
                    if not s['entidades_afectadas__clasificacion__nombre'] in x:
                        x.append(s['entidades_afectadas__clasificacion__nombre'])
                        y.append(s['cuenta_sectores'])
                colores = rand_color.generate(count=len(x))
                fig, ax = plt.subplots()
                ax.pie(y, labels=x, colors=colores, autopct='%1.1f%%', startangle=90)
                ax.set_title('Sectores afectados')
                ax.axis('equal')
                agrega_imagen(fig, document)
                
            if entidades:
                entidadesU = urlsU.exclude(entidades_afectadas=None).values(
                    'entidades_afectadas__nombre').annotate(
                        cuenta_entidades=Count('entidades_afectadas__nombre'))
                entidadesMU = urlsMU.exclude(entidades_afectadas=None).values(
                    'entidades_afectadas__nombre').annotate(
                        cuenta_entidades=Count('entidades_afectadas__nombre'))
                x, y = [], []
                for s in entidadesMU:
                    try:
                        n = next(t['cuenta_entidades'] for t in entidadesU if
                                 t['entidades_afectadas__nombre'] == s['entidades_afectadas__nombre'])
                    except:
                        n = 0
                    x.append(s['entidades_afectadas__nombre'])
                    y.append(s['cuenta_entidades'] + n)
                for s in entidadesU:
                    if not s['entidades_afectadas__nombre'] in x:
                        x.append(s['entidades_afectadas__nombre'])
                        y.append(s['cuenta_entidades'])
                colores = rand_color.generate(count=len(x))
                fig, ax = plt.subplots()
                ax.pie(y, labels=x, colors=colores, autopct='%1.1f%%', startangle=90)
                ax.set_title('Entidad afectada')
                ax.axis('equal')
                agrega_imagen(fig, document)

            if detecciones:
                ndias = (fin - inicio).days
                fechas = [inicio + datetime.timedelta(days=i) for i in range(ndias + 1)]
                y = []
                for d in fechas:
                    y.append(urlsU.filter(timestamp_deteccion__date=d).count() +
                             urlsMU.filter(timestamp_deteccion__date=d).count()
                    )
                x = [str(f) for f in fechas]
                y_pos = np.arange(len(x))
                fig, ax = plt.subplots()
                fig.subplots_adjust(bottom=0.2)
                ax.set_ylabel('Número de detecciones')
                ax.bar(y_pos, y, align='center', alpha=0.5)
                plt.xticks(y_pos, x, rotation=45)
                ax.set_title('Número de detecciones por fecha')
                agrega_imagen(fig, document)

            if tiempo_reporte:
                ndias = (fin - inicio).days
                fechas = [inicio + datetime.timedelta(days=i) for i in range(ndias + 1)]
                y = []
                x = [str(f) for f in fechas]
                tiempo_promedio_reporte = []
                tiempo_promedio_postreporte = []
                for d in fechas:
                    tickets = urlsMU.filter(mensaje__timestamp__date=d)
                    tiempo_promedio_reporte.append(tickets.annotate(
                        tiempo_reportado=F('mensaje__timestamp') - F('timestamp_creacion_sitio')).aggregate(
                            Avg('tiempo_reportado')).get('tiempo_reportado__avg', 0))
                    tiempo_promedio_postreporte.append(tickets.filter(
                        ~Q(timestamp_desactivado=None)).annotate(
                            tiempo_reportado=F('timestamp_desactivado') - F('mensaje__timestamp')).aggregate(
                                Avg('tiempo_reportado')).get('tiempo_reportado__avg', 0))
                y1 = [delta_horas(x) if x else 0 for x in tiempo_promedio_reporte]
                y2 = [delta_horas(x) if x else 0 for x in tiempo_promedio_postreporte]
                fig, ax = plt.subplots()
                fig.subplots_adjust(bottom=0.3)
                line1, = ax.plot(x, y1, linewidth=2,
                                 label='Tiempo promedio de reporte')
                line2, = ax.plot(x, y2, linewidth=2,
                                 label='Tiempo promedio de vida postreporte')
                plt.xticks(rotation=45)
                ax.set_ylabel('T (Horas)')
                ax.set_title('Tiempo promedio de reporte vs tiempo promedio de vida postreporte')
                ax.legend(loc='best')
                agrega_imagen(fig, document)

            if top_paises:                
                paisesU = urlsU.exclude(dominio__pais=None).values('dominio__pais').annotate(
                    cuenta_pais=Count('dominio__pais'))
                paisesMU = urlsMU.exclude(pais=None).values('pais').annotate(
                    cuenta_pais=Count('pais'))
                l = []
                for s in paisesMU:
                    try:
                        n = next(t['cuenta_pais'] for t in paisesU if
                                 t['dominio__pais'] == s['pais'])
                    except:
                        n = 0
                    l.append((s['pais'], s['cuenta_pais'] + n))
                for s in paisesU:
                    try:
                        n = next(1 for t in l if t[0] == s['dominio__pais'])
                    except:                        
                        l.append((s['dominio__pais'], s['cuenta_pais']))
                l.sort(key=lambda x:x[1], reverse=True)
                l = l[:10]
                x = [a[0] for a in l]
                y = [a[1] for a in l]
                fig, ax = plt.subplots()
                ax.set_ylabel('Número de sitios')
                y_pos = np.arange(len(x))
                ax.bar(y_pos, y, align='center', alpha=0.5)
                plt.xticks(y_pos, x)
                ax.set_title('Top 10 países que hospedan phishing')
                agrega_imagen(fig, document)
                
            if top_hosting:
                hostingU = urlsU.exclude(dominio__asn=None).values('dominio__asn').annotate(
                    cuenta_asn=Count('dominio__asn'))
                hostingMU = urlsMU.exclude(asn=None).values('asn').annotate(
                    cuenta_asn=Count('asn'))    
                l = []
                for s in hostingMU:
                    try:
                        n = next(t['cuenta__asn'] for t in hostingU if
                                 t['dominio__asn'] == s['asn'])
                    except:
                        n = 0
                    l.append((s['asn'], s['cuenta_asn'] + n))
                for s in hostingU:
                    try:
                        n = next(1 for t in l if t[0] == s['dominio__asn'])
                    except:                        
                        l.append((s['dominio__asn'], s['cuenta_asn']))
                l.sort(key=lambda x:x[1], reverse=True)
                l = l[:10]
                x = [a[0] for a in l]
                y = [a[1] for a in l]                
                fig, ax = plt.subplots()
                fig.subplots_adjust(bottom=0.5)
                ax.set_ylabel('Número de sitios')
                y_pos = np.arange(len(x))
                ax.bar(y_pos, y, align='center', alpha=0.5)
                plt.xticks(y_pos, x, rotation=70)
                ax.set_title('Top 10 servicios de hosting que hospedan phishing')
                agrega_imagen(fig, document)
                
            if urls_info:
                activas = urls_activas(urlsU)
                inactivas = urls_inactivas(urlsU)
                redirecciones = urls_redirecciones(urlsU)
                dominios = urls_dominios(urlsU)
                q.add_run("\n\nURLS NO REPORTADAS\n").bold = True
                q = document.add_paragraph("URLs analizadas: %d\n" % cuenta_urls(urlsU))
                q.add_run("URLs activas: %d\n" % len(activas))
                q.add_run("URLs inactivas: %d\n" % len(inactivas))
                q.add_run("URLs redirecciones: %d\n" % len(redirecciones))
                q.add_run("Dominios afectados: %d" % len(dominios))
                q = document.add_paragraph("")
                q.add_run("Entidad:\n").bold = True
                for e in urls_entidades(urlsU):
                    q.add_run("%s\n" % e)
                q = document.add_paragraph("")
                q.add_run("Dominios:\n").bold = True
                for e in dominios:
                    q.add_run("%s\n" % e)
                q = document.add_paragraph("")
                q.add_run("Países:\n").bold = True
                for e in urls_paises(urlsU):
                    q.add_run("%s\n" % e)

                q = document.add_paragraph("")         
                q.add_run("SITIOS ACTIVOS:\n").bold = True
                for u in activas:
                    url_info(u, q, document)
                q = document.add_paragraph("")
                q.add_run("SITIOS INACTIVOS:\n\n").bold = True
                for u in inactivas:
                    url_info(u, q, document)
                q = document.add_paragraph("")
                q.add_run("REDIRECCIONES:\n\n").bold = True
                for u in redirecciones:
                    url_info(u, q, document)
                q = document.add_paragraph("")
                q.add_run("URLS REPORTADAS:\n\n").bold = True
                for u in urlsMU:
                    q = document.add_paragraph("")
                    q.add_run("URL: %s\n" % u.url)
                    q.add_run("Fecha de activación: %s\n" % u.timestamp_creacion_sitio)
                    if u.timestamp_desactivado:
                        q.add_run("Fecha de desactivación: %s\n" % u.timestamp_desactivado)
                    q.add_run("Fecha de detección: %s\n" % u.timestamp_deteccion)
                    q.add_run("Entidad afectada: %s\n" % u.entidades)
                    q.add_run("País: %s\n" % u.pais)
                    q.add_run("ASN: %s\n" % u.asn)
                    
            response = HttpResponse(
                content_type='application/vnd.openxmlformats-officedocument.wordprocessingml.document'
            )
            response['Content-Disposition'] = 'attachment; filename=%s.docx' % archivo
            document.save(response)
            return response
        else:
            return render(request,'reporte.html', {'form': GraficasForm()})
