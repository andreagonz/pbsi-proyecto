from django.shortcuts import render, redirect, get_object_or_404
from django.forms import Textarea
from django.urls import reverse_lazy
from django.contrib.auth.decorators import login_required
from .forms import *
from .models import *
from .phishing import *
from .correo import *
from django.views.generic import TemplateView
from django.template import loader
from django.http import HttpResponse, Http404
from django.contrib.postgres.search import SearchQuery, SearchRank, SearchVector
from django.core.exceptions import MultipleObjectsReturned
from django.conf import settings
from shutil import copyfile
import os
from .reporte import *
from datetime import timedelta, datetime
from django.utils import timezone
from time import mktime
import time
from django.urls import reverse_lazy
from django.views.generic.edit import UpdateView, CreateView
from django.contrib.auth.mixins import LoginRequiredMixin
from django.db.models import Avg
from django.views.generic import TemplateView,View
from django.template import RequestContext
from django.http import HttpResponse
from phishing.forms import *
from django.core.exceptions import MultipleObjectsReturned
from django.http import JsonResponse
from django.db.models import Count, Q,F
from django.db.models.functions import Extract
import json
from rest_framework.views import APIView
from rest_framework.response import Response
import randomcolor
import datetime
from phishing.phishing import lineas_md5, md5, archivo_hashes, leeComentariosHTML, archivo_texto
from docx import Document
from docx.shared import Inches
from .entrada import( lee_csv, lee_txt, lee_json )
import matplotlib.pyplot as plt
import tempfile
import random
import string
import numpy as np
from docx.shared import Inches

def log_x(mensaje, bitacora):
    t = timezone.localtime(timezone.now())
    l = os.path.join(settings.DIR_LOG, bitacora)
    with open(l, 'a') as w:
        w.write('[%s] %s\n' % (t, mensaje))

@login_required(login_url=reverse_lazy('login'))
def monitoreo(request):
    dominios = Dominio.objects.all()
    activos = [x for x in dominios if x.activo]
    return render(request, 'monitoreo.html', context={'dominios':activos})

def rmimg(img):
    if img is None:
        return
    f = os.path.join(settings.MEDIA_ROOT, img)
    if os.path.exists(f):
        os.remove(f)

def cpimg(img, img2):
    if img is None or img2 is None:
        return
    f = os.path.join(settings.BASE_DIR, img[1:])
    f2 = os.path.join(settings.BASE_DIR, img2[1:])
    if os.path.exists(f):
        copyfile(f, f2)
    
def redirecciones_reporta(url):
    if url.reportado:
        return
    url.reportado = True
    url.timestamp_reportado = timezone.localtime(timezone.now())
    if url.estado_phishing < 1:
        url.timestamp_deteccion = url.timestamp_reportado
        url.estado_phishing = 1
    url.save()
    for p in Url.objects.filter(redireccion=url.url):
        redirecciones_reporta(p)

def redirecciones_ignora(url):
    if url.ignorado:
        return
    url.ignorado = True
    url.timestamp_reportado = timezone.localtime(timezone.now())
    url.save()
    for p in Url.objects.filter(redireccion=url.url):
        redirecciones_ignora(p)

@login_required(login_url=reverse_lazy('login'))
def monitoreo_id(request, pk):
    dominio = get_object_or_404(Dominio, pk=pk)
    if not dominio.activo:
        raise Http404()
    urls = dominio.urls_activas
    context = {
        'dominio': dominio,
        'urls': urls,
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
                for url in dominio.urls_activas:
                    sitio = monitorea_url(url, proxy)
            if not dominio.activo:
                urls = Url.objects.filter(reportado=False,
                                          ignorado=False,
                                          codigo__lt=300,
                                          codigo__gte=200).order_by('-timestamp_creacion')
                if len(urls) > 0:
                    return redirect('monitoreo-id', pk=urls[0].dominio.pk)
                return redirect('monitoreo')
            return redirect('monitoreo-id', pk=dominio.pk)
        elif request.POST.get('boton-mensaje'):
            mensaje_form = MensajeForm(request.POST, urls=urls)
            if mensaje_form.is_valid():
                de = mensaje_form.cleaned_data['de']
                para = [x.strip() for x in mensaje_form.cleaned_data['para'].split(',')]
                cc = [x.strip() for x in mensaje_form.cleaned_data['cc'].split(',')]
                cco = [x.strip() for x in mensaje_form.cleaned_data['cco'].split(',')]
                asunto = mensaje_form.cleaned_data['asunto']
                mensaje = mensaje_form.cleaned_data['mensaje']
                capturas = mensaje_form.cleaned_data['capturas']
                msg = genera_mensaje(dominio, de, para, cc, cco, asunto, mensaje, capturas)
                manda_correo(para, cc, cco, msg)
                try:
                    men = Mensaje.objects.get(ticket=ticket)
                except:
                    men = Mensaje(ticket=ticket)
                    men.save()
                for x in urls:
                    men.urls.add(x)
                    redirecciones_reporta(x)
                men.save()
                context = {
                    'dominio': dominio,
                    'urls': urls,
                    'de': de,
                    'para': ', '.join(para),
                    'cc': ', '.join(cc),
                    'cco': ', '.join(cco),
                    'asunto': asunto,
                    'mensaje': mensaje,
                    'capturas': capturas
                }
                return render(request, 'monitoreo_exito.html', context)
        elif request.POST.get('boton-ignorar') and request.user.is_superuser:
            for x in urls:
                redirecciones_ignora(x)
            return redirect('monitoreo')
        elif request.POST.get('boton-saltar'):
            us = dominio.url_set.all()
            i = us[0].id if len(us) > 0 else 0
            urls = Url.objects.filter(reportado=False,
                                      ignorado=False,
                                      codigo__lt=300,
                                      codigo__gte=200).exclude(
                                          dominio=dominio).order_by('-timestamp_creacion')
            if len(urls) > 0:
                return redirect('monitoreo-id', pk=urls[0].dominio.pk)
            return redirect('monitoreo')
    context['mensaje_form'] = mensaje_form
    context['proxy_form'] = proxy_form
    return render(request, 'monitoreo_id.html', context)

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
                return render(request, 'reporte_urls.html', context)
        elif request.POST.get("boton_archivo") and request.FILES['file']:
            form = ArchivoForm(request.POST)
            f = request.FILES['file'].read().decode('utf-8')
            name = request.FILES['file'].name
            urls = []
            if name.endswith('.txt'):
                urls = lee_txt(f)
            elif name.endswith('.json'):
                urls = lee_json(f)
            elif name.endswith('.csv'):
                urls = lee_csv(f)
            sitios = verifica_urls(urls, None, False)
            no_reportados = False
            for x in sitios:
                if not x.reportado:
                    no_reportados = True
            context = context_reporte(sitios)
            context['no_reportados'] = no_reportados
            return render(request, 'reporte_urls.html', context)
    else:
        form1 = UrlsForm()
        form2 = ArchivoForm()
    return render(request, 'valida_urls.html', {'form1': form1, 'form2': form2})

def url_detalle(request, pk):
    url = get_object_or_404(Url, pk=pk)
    comentarios = archivo_comentarios(url)
    hashes = archivo_hashes(url)
    context = {
        'url': url,
        'comentarios': comentarios,
        'hashes': hashes,
    }
    return render(request, 'url_detalle.html', context)

@login_required(login_url=reverse_lazy('login'))
def busca(request):
    message = "No se encontraron coincidencias"
    resultados = []
    q = ''
    if request.method == "GET" and request.GET.get('q', None):
        q = request.GET['q'].strip()
        """
        if request.GET.get('a', None) and request.GET['a'].strip() == '1':
            urls = Url.objects.exclude(archivo=None)
            for u in urls:
                f = archivo_texto(u)
                for h in lineas_md5(f):
                    if h == q:
                        resultados.append(u)
                for x in leeComentariosHTML(f):
                    if q in x:
                        resultados.append(u)
                if u.hash_archivo == q:
                    resultados.append(u)
            resultados = list(set(resultados))
        """
        resultados = Url.objects.annotate(
            search=SearchVector('url') + SearchVector('dominio__dominio') +
            SearchVector('entidades_afectadas__clasificacion__nombre') +
            SearchVector('entidades_afectadas__nombre') +
            SearchVector('ofuscacion__nombre') + SearchVector('dominio__correos__correo') +
            SearchVector('dominio__rir__nombre') + SearchVector('dominio__dns__nombre') +
            SearchVector('dominio__ip') + SearchVector('dominio__pais') +
            SearchVector('dominio__asn') + SearchVector('dominio__isp') +
            SearchVector('identificador') + SearchVector('titulo') +
            SearchVector('hash_archivo') + SearchVector('redireccion') +
            SearchVector('dominio__servidor') +
            SearchVector('mensaje__ticket')
        ).filter(search=SearchQuery(q)).distinct('url')            
    return render(request, 'results.html',
                  {'resultados': resultados,
                   'query': q
                  })

@login_required(login_url=reverse_lazy('login'))
def muestraResultados(request,srch):
	return render(request,'results.html',{})
    
@login_required(login_url=reverse_lazy('login'))
def historico(request):
    fin = timezone.localtime(timezone.now()).date()
    inicio = fin - timedelta(days=1)
    form = HistoricoForm()
    if request.method == 'POST':
        form = HistoricoForm(request.POST)
        if form.is_valid():
            inicio = form.cleaned_data['inicio']
            fin = form.cleaned_data['fin']
    sitios = Url.objects.filter(timestamp_creacion__date__lte=fin,
                                timestamp_creacion__date__gte=inicio)
    context = context_reporte(sitios)
    context['inicio'] = inicio
    context['fin'] = fin
    context['form'] = form
    return render(request, 'historico.html', context)

@login_required(login_url=reverse_lazy('login'))
def ajustes(request):
    proxies = Proxy.objects.all()
    recursos = Recurso.objects.all()
    asunto_form = CambiaAsuntoForm(initial={'asunto': lee_plantilla_asunto()})
    mensaje_form = CambiaMensajeForm(initial={'mensaje': lee_plantilla_mensaje()})
    unam_asunto_form = CambiaUnamAsuntoForm(initial={'asunto': lee_plantilla_unam_asunto()})
    unam_mensaje_form = CambiaUnamMensajeForm(initial={'mensaje': lee_plantilla_unam_mensaje()})
    actualizacion_form = FrecuenciaForm()
    verificacion_form = FrecuenciaForm()
    if request.method == 'POST':
        if request.POST.get('cambia-asunto'):
            asunto_form = CambiaAsuntoForm(request.POST)
            if asunto_form.is_valid():
                asunto = asunto_form.cleaned_data['asunto']
                cambia_asunto(asunto)
        elif request.POST.get('cambia-mensaje'):
            mensaje_form = CambiaMensajeForm(request.POST)
            if mensaje_form.is_valid():
                mensaje = mensaje_form.cleaned_data['mensaje']
                cambia_mensaje(mensaje)
        elif request.POST.get('cambia-unam-asunto'):
            unam_asunto_form = CambiaUnamAsuntoForm(request.POST)
            if unam_asunto_form.is_valid():
                asunto = unam_asunto_form.cleaned_data['asunto']
                cambia_unam_asunto(asunto)
        elif request.POST.get('cambia-unam-mensaje'):
            unam_mensaje_form = CambiaUnamMensajeForm(request.POST)
            if unam_mensaje_form.is_valid():
                mensaje = unam_mensaje_form.cleaned_data['mensaje']
                cambia_unam_mensaje(mensaje)
        elif request.POST.get('cambia-actualizacion'):
            actualizacion_form = FrecuenciaForm(request.POST)
            if actualizacion_form.is_valid():
                actualizacion = actualizacion_form.cleaned_data['frecuencia']
                if actualizacion < 1:
                    actualizacion = 8
                cambia_frecuencia('actualiza', actualizacion)
        elif request.POST.get('cambia-verificacion'):
            verificacion_form = FrecuenciaForm(request.POST)
            if verificacion_form.is_valid():
                verificacion = verificacion_form.cleaned_data['frecuencia']
                if verificacion < 1:
                    verificacion = 1
                cambia_frecuencia('verifica', verificacion)
    context = {
        'recursos': recursos,
        'proxies': proxies,
        'asunto_form': asunto_form,
        'mensaje_form': mensaje_form,
        'asunto_unam_form': unam_asunto_form,
        'mensaje_unam_form': unam_mensaje_form,
        'actualizacion_form': actualizacion_form,
        'verificacion_form': verificacion_form,
    }
    return render(request, 'ajustes.html', context)

@login_required(login_url=reverse_lazy('login'))
def elimina_proxy(request, pk):
    proxy = get_object_or_404(Proxy, pk=pk)
    proxy.delete()
    return redirect('ajustes')

class ActualizaProxy(LoginRequiredMixin, UpdateView):
    model = Proxy
    template_name = 'actualiza_proxy.html'
    success_url = reverse_lazy('ajustes')
    fields = ('http', 'https')
    
class NuevoProxy(LoginRequiredMixin, CreateView):
    model = Proxy
    template_name = 'nuevo_proxy.html'
    success_url = reverse_lazy('ajustes')
    fields = ('http', 'https')

@login_required(login_url=reverse_lazy('login'))
def elimina_recurso(request, pk):
    recurso = get_object_or_404(Recurso, pk=pk)
    recurso.delete()
    return redirect('ajustes')

class ActualizaRecurso(LoginRequiredMixin, UpdateView):
    model = Recurso
    template_name = 'actualiza_recurso.html'
    success_url = reverse_lazy('ajustes')
    fields = ('es_phishtank', 'recurso', 'max_urls')
    
class NuevoRecurso(LoginRequiredMixin, CreateView):
    model = Recurso
    template_name = 'nuevo_recurso.html'
    success_url = reverse_lazy('ajustes')
    fields = ('es_phishtank', 'recurso', 'max_urls')

@login_required(login_url=reverse_lazy('login'))
def ofuscaciones_view(request):
    of = Ofuscacion.objects.all()
    context = {
        'ofuscaciones': of
    }
    return render(request, 'ofuscaciones.html', context)

@login_required(login_url=reverse_lazy('login'))
def entidades_view(request):
    context = {
        'clasificaciones': Clasificacion_entidad.objects.all(),
        'entidades': Entidades.objects.all()
    }
    return render(request, 'entidades.html', context)

@login_required(login_url=reverse_lazy('login'))
def elimina_ofuscacion(request, pk):
    recurso = get_object_or_404(Ofuscacion, pk=pk)
    recurso.delete()
    return redirect('ofuscaciones')

class ActualizaOfuscacion(LoginRequiredMixin, UpdateView):
    model = Ofuscacion
    template_name = 'actualiza_ofuscacion.html'
    success_url = reverse_lazy('ofuscaciones')
    fields = ('nombre', 'regex')
    
class NuevaOfuscacion(LoginRequiredMixin, CreateView):
    model = Ofuscacion
    template_name = 'nueva_ofuscacion.html'
    success_url = reverse_lazy('ofuscaciones')
    fields = ('nombre', 'regex')
    
@login_required(login_url=reverse_lazy('login'))
def elimina_entidad(request, pk):
    entidad = get_object_or_404(Entidades, pk=pk)
    entidad.delete()
    return redirect('entidades')

class ActualizaEntidad(LoginRequiredMixin, UpdateView):
    model = Entidades
    template_name = 'actualiza_entidad.html'
    success_url = reverse_lazy('entidades')
    fields = ('nombre', 'formularios', 'clasificacion',)

    def get_form(self, form_class=None):
        form = super(ActualizaEntidad, self).get_form(form_class)
        form.fields['formularios'].required = False
        form.fields['clasificacion'].required = False
        form.fields['formularios'].widget = Textarea()
        form.fields['formularios'].label = 'Formularios de abuso (separados por un salto de línea)'
        return form
    
class NuevaEntidad(LoginRequiredMixin, CreateView):
    model = Entidades
    template_name = 'nueva_entidad.html'
    success_url = reverse_lazy('entidades')
    fields = ('nombre', 'formularios', 'clasificacion',)

    def get_form(self, form_class=None):
        form = super(NuevaEntidad, self).get_form(form_class)
        form.fields['formularios'].required = False
        form.fields['clasificacion'].required = False
        form.fields['formularios'].widget = Textarea()
        form.fields['formularios'].label = 'Formularios de abuso (separados por un salto de línea)'
        return form

@login_required(login_url=reverse_lazy('login'))
def elimina_clasificacion(request, pk):
    c = get_object_or_404(Clasificacion_entidad, pk=pk)
    c.delete()
    return redirect('entidades')

class NuevaClasificacionEntidad(LoginRequiredMixin, CreateView):
    model = Clasificacion_entidad
    template_name = 'nueva_clasificacion.html'
    success_url = reverse_lazy('entidades')
    fields = ('nombre',)

    def get_form(self, form_class=None):
        form = super(NuevaClasificacionEntidad, self).get_form(form_class)
        form.fields['nombre'].label = 'Clasificación'
        return form

class ActualizaClasificacionEntidad(LoginRequiredMixin, UpdateView):
    model = Clasificacion_entidad
    template_name = 'actualiza_clasificacion.html'
    success_url = reverse_lazy('entidades')
    fields = ('nombre',)

    def get_form(self, form_class=None):
        form = super(ActualizaClasificacionEntidad, self).get_form(form_class)
        form.fields['nombre'].label = 'Clasificación'
        return form

class HomeView(View):
    def get(self,request, *args, **kwargs):
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
        urls = Url.objects.filter(estado_phishing__gte=1)
        top_paises = urls.filter(~Q(dominio__pais=None)).values('dominio__pais').annotate(
            cuenta_pais=Count('dominio__pais')).order_by('-cuenta_pais')[:5]
        top_paises_data = {
            "labels": [p['dominio__pais'] for p in top_paises],
            "default": [p['cuenta_pais'] for p in top_paises]
        }

        top_hosting = urls.filter(~Q(dominio__asn=None)).values('dominio__asn').annotate(
            cuenta_asn=Count('dominio__asn')).order_by('-cuenta_asn')[:5]
        top_hosting_data = {
            "labels": [p['dominio__asn'] for p in top_hosting],
            "default": [p['cuenta_asn'] for p in top_hosting]
        }

        sitios_activos = 0
        for x in urls:
            sitios_activos += 1 if x.es_activa else 0
        sitios_reportados = urls.filter(reportado=True, ignorado=False).count()
        sitios_detectados = urls.count()
        sitios_data = {
            'labels': ['Activos', 'Reportados', 'Detectados'],
            'default': [sitios_activos, sitios_reportados, sitios_detectados]
        }
        
        hoy_tiempo = timezone.localtime(timezone.now())
        top_sitios = urls.filter(timestamp_desactivado=None).values('url').annotate(
                                            tiempo_vida=(hoy_tiempo -
                                                F('timestamp_creacion'))).order_by(
                                                    '-tiempo_vida')[:5]
        top_sitios_data = {
            'labels': [x['url'] for x in top_sitios],
            'default': [delta_horas(x['tiempo_vida']) for x in top_sitios]
        }
        
        sectores = urls.filter(~Q(entidades_afectadas__clasificacion=None)).values(
            'entidades_afectadas__clasificacion__nombre').annotate(
                cuenta_sectores=Count('entidades_afectadas__clasificacion__nombre'))
        labels = [e['entidades_afectadas__clasificacion__nombre'] for e in sectores]
        sectores_data = {
            "labels":  labels,
            "default": [e['cuenta_sectores'] for e in sectores],
            "colores": rand_color.generate(count=len(labels))
        }
        
        dias = obtener_dias()
        num_detecciones = [] 
        hoy = hoy_tiempo.date()
        for x in range(6, -1, -1):
            num_detecciones.append(urls.filter(
                timestamp_deteccion__date=hoy - datetime.timedelta(days=x),
            ).count())
        detecciones_data = {
            'labels': dias,
            'default': num_detecciones
        }
        
        entidades = urls.filter(~Q(entidades_afectadas=None)).values(
            'entidades_afectadas__nombre').annotate(
                cuenta_entidades=Count('entidades_afectadas__nombre'))
        labels = [e['entidades_afectadas__nombre'] for e in entidades]
        entidades_data = {
            "labels":  labels,
            "default": [e['cuenta_entidades'] for e in entidades],
            "colores": rand_color.generate(count=len(labels))
        }
        
        tiempo_promedio_reporte = []
        tiempo_promedio_postreporte = []
        for x in range(6, -1, -1):
             tiempo_promedio_reporte.append(urls.filter(
                 ~Q(reportado=False),
                 timestamp_reportado__date=hoy - datetime.timedelta(days=x)).annotate(
                     tiempo_reportado=(F('timestamp_reportado') - F('timestamp_creacion'))).aggregate(
                         Avg('tiempo_reportado')).get('tiempo_reportado__avg', 0))
             tiempo_promedio_postreporte.append(urls.filter(
                 ~Q(reportado=False), ~Q(timestamp_desactivado=None),
                 timestamp_reportado__date=hoy - datetime.timedelta(days=x)).annotate(
                     tiempo_reportado=(F('timestamp_desactivado') -
                                       F('timestamp_reportado'))).aggregate(
                                           Avg('tiempo_reportado')).get('tiempo_reportado__avg', 0))
        tiempo_reporte_data = {
            'default1': [delta_horas(x) if x else 0 for x in tiempo_promedio_reporte],
            'default2': [delta_horas(x) if x else 0 for x in tiempo_promedio_postreporte]
        }
        
        graphs = [top_paises_data, top_hosting_data, sitios_data, top_sitios_data,
                  sectores_data, detecciones_data, entidades_data, tiempo_reporte_data]
        return Response(graphs)

class DocumentView(LoginRequiredMixin, View):
    def get(self,request, *args, **kwargs):
        if request.method == 'POST':
            return render(request,'dashboard.html',{})
        else:
            return render(request,'generar_rep.html', {'form': GraficasForm()})

def agrega_imagen(fig, documento):
    try:
        a = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(8))
        path = '/tmp/%s.png' % a
        fig.savefig(path)
        plt.clf()
        documento.add_picture(path)
        os.remove(path)
    except Exception as e:
        log_x('Error: %s' % str(e), 'reportes.log')
        
@login_required(login_url=reverse_lazy('login'))
def createDoc(request):
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
            urls = Url.objects.filter(timestamp_deteccion__date__gte=inicio,
                                      timestamp_deteccion__date__lte=fin)
            document.add_heading('Periodo',level=1)
            q = document.add_paragraph('De: ')
            q.add_run(str(inicio)).bold = True
            q.add_run('      ')
            q.add_run('A :  ')
            q.add_run(str(fin)).bold = True

            if sitios:
                sitios_activos = 0
                for x in urls.filter(Q(timestamp_desactivado=None) |
                                     Q(timestamp_desactivado__date__lte=fin)):
                    sitios_activos += 1 if x.es_activa else 0
                sitios_reportados = urls.filter(
                    timestamp_reportado__date__gte=inicio,
                    timestamp_reportado__date__lte=fin,
                    ignorado=False).count()
                sitios_detectados = urls.count()
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
                if fin < hoy.date():
                    f_fin = fin + timedelta(days=1)
                else:
                    f_fin = hoy
                top_sitios = urls.filter(Q(timestamp_desactivado=None) |
                                         Q(timestamp_desactivado__date__lte=f_fin)).values(
                                             'url').annotate(tiempo_vida=(
                                                 f_fin - F('timestamp_creacion'))).order_by(
                                                     '-tiempo_vida')[:5]
                y = [x['url'] for x in top_sitios]
                x = [delta_horas(x['tiempo_vida']) for x in top_sitios]
                y_pos = np.arange(len(x))
                fig, ax = plt.subplots()
                fig.subplots_adjust(left=0.5)
                ax.set_xlabel('T (Horas)')
                ax.barh(y_pos, x, align='center', alpha=0.5)
                plt.yticks(y_pos, y)
                ax.set_title('Top 5 – Sitios phishing vs Tiempo de vida')
                agrega_imagen(fig, document)
                
            if sectores:
                sectores = urls.filter(~Q(entidades_afectadas__clasificacion=None)).values(
                    'entidades_afectadas__clasificacion__nombre').annotate(
                        cuenta_sectores=Count('entidades_afectadas__clasificacion__nombre'))
                x = [e['entidades_afectadas__clasificacion__nombre'] for e in sectores]
                y = [e['cuenta_sectores'] for e in sectores]
                colores = rand_color.generate(count=len(x))
                fig, ax = plt.subplots()
                ax.pie(y, labels=x, colors=colores, autopct='%1.1f%%', startangle=90)
                ax.set_title('Sectores afectados')
                ax.axis('equal')
                agrega_imagen(fig, document)
                
            if entidades:
                entidades = urls.filter(~Q(entidades_afectadas=None)).values(
                    'entidades_afectadas__nombre').annotate(
                        cuenta_entidades=Count('entidades_afectadas__nombre'))
                x = [e['entidades_afectadas__nombre'] for e in entidades]
                y = [e['cuenta_entidades'] for e in entidades]
                colores = rand_color.generate(count=len(x))
                fig, ax = plt.subplots()
                ax.pie(y, labels=x, colors=colores, autopct='%1.1f%%', startangle=90)
                ax.set_title('Entidades afectadas')
                ax.axis('equal')
                agrega_imagen(fig, document)

            if detecciones:
                ndias = (fin - inicio).days
                fechas = [inicio + datetime.timedelta(days=i) for i in range(ndias + 1)]
                y = []
                for d in fechas:
                    y.append(urls.filter(timestamp_deteccion__date=d).count())
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
                    tiempo_promedio_reporte.append(urls.filter(
                        ~Q(timestamp_reportado=None),
                        timestamp_reportado__date=d).annotate(tiempo_reportado=(
                            F('timestamp_reportado') - F('timestamp_creacion'))).aggregate(
                                Avg('tiempo_reportado')).get('tiempo_reportado__avg', 0))
                    tiempo_promedio_postreporte.append(urls.filter(
                        ~Q(timestamp_reportado=None), ~Q(timestamp_desactivado=None),
                        timestamp_reportado__date=d).annotate(
                            tiempo_reportado=(F('timestamp_desactivado') -
                                      F('timestamp_reportado'))).aggregate(
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
                top_paises = urls.filter(~Q(dominio__pais=None)).values(
                    'dominio__pais').annotate(
                        cuenta_pais=Count('dominio__pais')).order_by('-cuenta_pais')[:10]
                x = [p['dominio__pais'] for p in top_paises]
                y = [p['cuenta_pais'] for p in top_paises]
                fig, ax = plt.subplots()
                ax.set_ylabel('Número de sitios')
                y_pos = np.arange(len(x))
                ax.bar(y_pos, y, align='center', alpha=0.5)
                plt.xticks(y_pos, x)
                ax.set_title('Top 10 países que hospedan phishing')
                agrega_imagen(fig, document)
                
            if top_hosting:
                top_hosting = urls.filter(~Q(dominio__asn=None)).values(
                    'dominio__asn').annotate(
                        cuenta_asn=Count('dominio__asn')).order_by('-cuenta_asn')[:10]
                x =  [p['dominio__asn'] for p in top_hosting]
                y = [p['cuenta_asn'] for p in top_hosting]
                fig, ax = plt.subplots()
                fig.subplots_adjust(bottom=0.5)
                ax.set_ylabel('Número de sitios')
                y_pos = np.arange(len(x))
                ax.bar(y_pos, y, align='center', alpha=0.5)
                plt.xticks(y_pos, x, rotation=70)
                ax.set_title('Top 10 servicios de hosting que hospedan phishing')
                agrega_imagen(fig, document)

            if urls_info:
                activas = urls_activas(urls)
                inactivas = urls_inactivas(urls)
                redirecciones = urls_redirecciones(urls)
                dominios = urls_dominios(urls)
                q = document.add_paragraph("URLs analizadas: %d\n" % cuenta_urls(urls))
                q.add_run("URLs activas: %d\n" % len(activas))
                q.add_run("URLs inactivas: %d\n" % len(inactivas))
                q.add_run("URLs redirecciones: %d\n" % len(redirecciones))
                q.add_run("Dominios afectados: %d" % len(dominios))
                q = document.add_paragraph("")
                q.add_run("Entidades:\n").bold = True            
                for e in urls_entidades(urls):
                    q.add_run("%s\n" % e)
                q = document.add_paragraph("")
                q.add_run("Dominios:\n").bold = True
                for e in dominios:
                    q.add_run("%s\n" % e)
                q = document.add_paragraph("")
                q.add_run("Países:\n").bold = True
                for e in urls_paises(urls):
                    q.add_run("%s\n" % e)

                q = document.add_paragraph("")                
                q.add_run("SITIOS ACTIVOS:\n").bold = True
                for u in activas:
                    if u.captura and hasattr(u.captura, 'file'):
                        document.add_picture(u.captura.file, width=Inches(4.0))
                    q = document.add_paragraph("")
                    q.add_run("Identificador: %s\n" % u.identificador)
                    q.add_run("Timestamp: %s\n" % u.timestamp)
                    q.add_run("IP: %s\n" % u.dominio.ip)
                    q.add_run("Código: %d\n" % u.codigo)
                    q.add_run("URL: %s\n" % u.url)
                    q.add_run("Reportado: %s\n" % u.reportado)
                    q.add_run("Título: %s\n" % u.titulo)
                    q.add_run("Entidades: %s\n" % u.entidades)
                    q.add_run("Ofuscacion: %s\n" % u.ofuscaciones)
                    q.add_run("Correos: %s\n" % u.dominio.correos_abuso)
                    q.add_run("ASN: %s\n" % u.dominio.asn)
                    q.add_run("País: %s\n\n" % u.dominio.pais)

                q = document.add_paragraph("")
                q.add_run("SITIOS INACTIVOS:\n\n").bold = True
                for u in inactivas:
                    q.add_run("Identificador: %s\n" % u.identificador)
                    q.add_run("Timestamp: %s\n" % u.timestamp)
                    q.add_run("IP: %s\n" % u.dominio.ip)
                    q.add_run("Código: %d\n" % u.codigo)
                    q.add_run("URL: %s\n" % u.url)
                    q.add_run("Reportado: %s\n" % u.reportado)
                    q.add_run("Correos: %s\n" % u.dominio.correos_abuso)
                    q.add_run("ASN: %s\n" % u.dominio.asn)
                    q.add_run("País: %s\n\n" % u.dominio.pais)

                q = document.add_paragraph("")
                q.add_run("REDIRECCIONES:\n\n").bold = True
                for u in redirecciones:
                    q.add_run("Identificador: %s\n" % u.identificador)
                    q.add_run("Timestamp: %s\n" % u.timestamp)
                    q.add_run("IP: %s\n" % u.dominio.ip)
                    q.add_run("Código: %d\n" % u.codigo)
                    q.add_run("URL: %s\n" % u.url)
                    q.add_run("Correos: %s\n" % u.dominio.correos_abuso)
                    q.add_run("ASN: %s\n" % u.dominio.asn)
                    q.add_run("País: %s\n\n" % u.dominio.pais)
            response = HttpResponse(
                content_type='application/vnd.openxmlformats-officedocument.wordprocessingml.document'
            )
            response['Content-Disposition'] = 'attachment; filename=%s.docx' % archivo
            document.save(response)
            return response
        else:
            return render(request,'generar_rep.html', {'form': GraficasForm()})

def entrada(request):
    if request.method == 'POST':
        if request.POST.get("boton_correo"):
            form = CorreoForm(request.POST)
            if form.is_valid():
                c = form.cleaned_data['correo']
                resultados, urls, headers, archivos, error = parsecorreo(c)
                context = {}
                if len(urls) > 0:
                    sitios = verifica_urls(urls, None, False)
                    context = context_reporte(sitios)
                context['resultados'] = resultados
                context['urls'] = urls
                context['headers'] = headers
                context['archivos'] = archivos
                context['error'] = error
                return render(request, 'entrada_resultados.html', context)
        elif request.POST.get("boton_archivo") and request.FILES['file']:
            form = CorreoArchivoForm(request.POST)
            f = request.FILES['file'].read().decode('utf-8')
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
            return render(request, 'entrada_resultados.html', context)
    else:
        form1 = CorreoForm()
        form2 = CorreoArchivoForm()
    return render(request, 'entrada.html', {'form1': form1, 'form2': form2})
