from django.views.generic import TemplateView, View
from rest_framework.response import Response
from rest_framework.views import APIView
from django.shortcuts import render
from phishing.models import Url

class HomeView(View):
    def get(self, request, *args, **kwargs):
        return render(request, 'dashboard.html', {})

def obtener_dias():
    """
    Obtinene una lista de los últimos 7 días
    """
    dias = ['Lunes', 'Martes', 'Miércoles', 'Jueves', 'Viernes', 'Sábado', 'Domingo']
    hoy = timezone.localtime(timezone.now()).weekday() + 1
    return dias[hoy:] + dias[:hoy]

def delta_horas(td):
    return td.total_seconds() / 3600

class ChartData(APIView):
    
    def get(self, request, format=None):
        rand_color = randomcolor.RandomColor()
        urls = Url.objects.exclude(Q(deteccion='I')|Q(deteccion='N'))

        paisesU = urls.filter(reportado=False).exclude(dominio__pais=None).values(
            'dominio__pais').annotate(
                cuenta_pais=Count('dominio__pais'))
        paisesMU = MensajeURL.objects.exclude(pais=None).values('pais').annotate(
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
        l = l[:5]
        top_paises_data = {
            "labels": [a[0] for a in l],
            "default": [a[1] for a in l]
        }

        hostingU = urls.filter(reportado=False).exclude(dominio__asn=None).values(
            'dominio__asn').annotate(cuenta_asn=Count('dominio__asn'))
        hostingMU = MensajeURL.objects.exclude(asn=None).values(
            'asn').annotate(cuenta_asn=Count('asn'))
        l = []
        for s in hostingMU:
            try:
                n = next(t['cuenta_asn'] for t in hostingU if
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
        l = l[:5]
        top_hosting_data = {
            "labels": [a[0] for a in l],
            "default": [a[1] for a in l]
        }
        
        sitios_activos = urls.filter(timestamp_desactivado=None).count()
        sitios_reportados = MensajeURL.objects.all().count()
        sitios_detectados = urls.filter(reportado=False).count() + MensajeURL.objects.all().count()
        sitios_data = {
            'labels': ['Activos', 'Reportados', 'Detectados'],
            'default': [sitios_activos, sitios_reportados, sitios_detectados]
        }
        
        hoy_tiempo = timezone.localtime(timezone.now())
        top_sitios = urls.filter(timestamp_desactivado=None).annotate(
                                            tiempo_vida=(hoy_tiempo -
                                                F('timestamp_reactivacion'))).order_by(
                                                    '-tiempo_vida')[:5]
        top_sitios_data = {
            'labels': [x.url for x in top_sitios],
            'default': [delta_horas(x.tiempo_vida) for x in top_sitios]
        }
        
        sectoresU = urls.filter(~Q(entidades_afectadas=None),
                                ~Q(entidades_afectadas__clasificacion=None),
                                reportado=False).values(
                                    'entidades_afectadas__clasificacion__nombre').annotate(
                                        cuenta_sectores=Count(
                                            'entidades_afectadas__clasificacion__nombre'))
        sectoresMU = MensajeURL.objects.filter(~Q(entidades_afectadas=None),
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
        sectores_data = {
            "labels":  x,
            "default": y,
            "colores": rand_color.generate(count=len(x))
        }
        
        dias = obtener_dias()
        num_detecciones = [] 
        hoy = hoy_tiempo.date()
        for x in range(6, -1, -1):
            num_detecciones.append(urls.filter(reportado=False,
                timestamp_deteccion__date=hoy - datetime.timedelta(days=x),
            ).count() + MensajeURL.objects.filter(
                timestamp_deteccion__date=hoy - datetime.timedelta(days=x)).count())
        detecciones_data = {
            'labels': dias,
            'default': num_detecciones
        }

        entidadesU = urls.filter(reportado=False).exclude(entidades_afectadas=None).values(
            'entidades_afectadas__nombre').annotate(
                cuenta_entidades=Count('entidades_afectadas__nombre'))
        entidadesMU = MensajeURL.objects.exclude(entidades_afectadas=None).values(
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
        entidades_data = {
            "labels":  x,
            "default": y,
            "colores": rand_color.generate(count=len(x))
        }

        tiempo_promedio_reporte = []
        tiempo_promedio_postreporte = []
        for x in range(6, -1, -1):
            tickets = MensajeURL.objects.filter(mensaje__timestamp__date=hoy - datetime.timedelta(days=x))
            tiempo_promedio_reporte.append(tickets.annotate(
                tiempo_reportado=F('mensaje__timestamp') - F('timestamp_creacion_sitio')).aggregate(
                    Avg('tiempo_reportado')).get('tiempo_reportado__avg', 0))
            tiempo_promedio_postreporte.append(tickets.filter(
                ~Q(timestamp_desactivado=None)).annotate(
                    tiempo_reportado=F('timestamp_desactivado') - F('mensaje__timestamp')).aggregate(
                        Avg('tiempo_reportado')).get('tiempo_reportado__avg', 0))                
        tiempo_reporte_data = {
            'default1': [delta_horas(x) if x else 0 for x in tiempo_promedio_reporte],
            'default2': [delta_horas(x) if x else 0 for x in tiempo_promedio_postreporte]
        }
        
        graphs = [top_paises_data, top_hosting_data, sitios_data, top_sitios_data,
                  sectores_data, detecciones_data, entidades_data, tiempo_reporte_data]
        return Response(graphs)
