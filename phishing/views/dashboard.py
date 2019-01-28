from django.views.generic import TemplateView, View
from rest_framework.response import Response
from rest_framework.views import APIView
from django.shortcuts import render
from phishing.models import Url, ASN
import randomcolor
from django.db.models import Count, Q, F, Avg
from django.utils import timezone
import datetime
from phishing.views import aux

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

class ChartData(APIView):
    
    def get(self, request, format=None):
        rand_color = randomcolor.RandomColor()
        
        urls0 = Url.objects.all()
        lst = []
        for u in urls0:
            d = u.obten_info
            if d and (d.deteccion == 'P' or d.deteccion == 'I'):
                lst.append(u.pk)
        urls = Url.objects.filter(pk__in=lst)

        paises = urls.exclude(dominio__pais__isnull=True).values(
            'dominio__pais').annotate(
                cuenta=Count('dominio__pais')).order_by('-cuenta')[:5]
        top_paises_data = {
            "labels": [a['dominio__pais'] for a in paises],
            "default": [a['cuenta'] for a in paises]
        }

        hosting = urls.exclude(dominio__asn__isnull=True).values(
            'dominio__asn').annotate(
                cuenta=Count('dominio__asn')).order_by('-cuenta')[:5]
        asns = ASN.objects.filter(pk__in=[x['dominio__asn'] for x in hosting])
        l = []
        for a in asns:
            l.append((str(a), next(x['cuenta'] for x in hosting if
                           x['dominio__asn'] == a.pk)))
        l.sort(key=lambda x:x[1], reverse=True)
        top_hosting_data = {
            "labels": [a[0] for a in l],
            "default": [a[1] for a in l]
        }        

        sitios_activos = urls.exclude(timestamp_desactivado__isnull=False)
        sitios_reportados = Url.objects.filter(ticket__isnull=False)
        sitios_data = {
            'labels': ['Activos', 'Reportados', 'Detectados'],
            'default': [sitios_activos.count(), sitios_reportados.count(), urls.count()]
        }

        hoy_tiempo = timezone.localtime(timezone.now())
        
        top_sitios = sitios_activos.annotate(
            tiempo_vida=(hoy_tiempo - F('timestamp_creacion'))).order_by('-tiempo_vida')[:5]
        top_sitios_data = {
            'autenticado': request.user.is_authenticated,
            'labels': list(range(1, len(top_sitios) + 1)),
            'urls': [x.url for x in top_sitios],
            'pks': [x.pk for x in top_sitios],
            'valores': [aux.delta_horas(x.tiempo_vida) for x in top_sitios]
        }
        
        sectores = urls.values('urlactiva__entidad_afectada__clasificacion__nombre').annotate(
                    cuenta=Count('urlactiva__entidad_afectada__clasificacion__nombre'))        
        sectores_data = {
            "labels":  [x['urlactiva__entidad_afectada__clasificacion__nombre'] for x in sectores if x['urlactiva__entidad_afectada__clasificacion__nombre']],
            "default": [x['cuenta'] for x in sectores if x['urlactiva__entidad_afectada__clasificacion__nombre']],
            "colores": rand_color.generate(count=len(sectores))
        }

        dias = obtener_dias()
        num_detecciones = []
        hoy = hoy_tiempo.date()
        for x in range(6, -1, -1):
            num_detecciones.append(
                urls.filter(timestamp_creacion__date=hoy - datetime.timedelta(days=x)).count()
            )
        detecciones_data = {
            'labels': dias,
            'default': num_detecciones
        }

        entidades = urls.values('urlactiva__entidad_afectada__nombre').annotate(
                    cuenta=Count('urlactiva__entidad_afectada__nombre'))
        entidades_data = {
            "labels":  [x['urlactiva__entidad_afectada__nombre'] for x in entidades
                        if x['urlactiva__entidad_afectada__nombre']],
            "default": [x['cuenta'] for x in entidades
                        if x['urlactiva__entidad_afectada__nombre']],
            "colores": rand_color.generate(count=len(entidades))
        }
        
        tiempo_promedio_reporte = []
        tiempo_promedio_postreporte = []
        for x in range(6, -1, -1):
            sitios = urls.filter(
                timestamp_creacion__date=hoy - datetime.timedelta(days=x)
            ).exclude(ticket__isnull=True)
            tiempo_promedio_reporte.append(sitios.annotate(
                tiempo_reportado=F('ticket__timestamp') - F('timestamp_creacion')).aggregate(
                    Avg('tiempo_reportado')).get('tiempo_reportado__avg', 0))
            tiempo_promedio_postreporte.append(sitios.filter(
                timestamp_desactivado__isnull=False).annotate(
                    tiempo_reportado=F('timestamp_desactivado') - F('ticket__timestamp')).aggregate(
                        Avg('tiempo_reportado')).get('tiempo_reportado__avg', 0))
        tiempo_reporte_data = {
            'default1': [aux.delta_horas(x) if x else 0 for x in tiempo_promedio_reporte],
            'default2': [aux.delta_horas(x) if x else 0 for x in tiempo_promedio_postreporte]
        }
        
        graphs = [top_paises_data, top_hosting_data, sitios_data, top_sitios_data,
                  sectores_data, detecciones_data, entidades_data, tiempo_reporte_data]
        return Response(graphs)
