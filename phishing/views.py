from django.shortcuts import render, redirect, get_object_or_404
from django.forms import Textarea
from django.urls import reverse_lazy
from django.contrib.auth.decorators import login_required
from .forms import (
    UrlsForm, MensajeForm, ProxyForm, Search, HistoricoForm,
    CambiaAsuntoForm, CambiaMensajeForm, FrecuenciaForm, CorreoForm, ArchivoForm, CorreoArchivoForm
)
from .models import Url, Correo, Proxy, Recurso, Ofuscacion, Entidades, Dominio, Clasificacion_entidad
from .phishing import (
    verifica_urls, archivo_texto, monitorea_url,
    whois, archivo_comentarios, archivo_hashes, cambia_frecuencia
)
from .correo import (
    genera_mensaje, manda_correo, obten_asunto, obten_mensaje,
    lee_plantilla_asunto, lee_plantilla_mensaje, cambia_asunto, cambia_mensaje,
    parsecorreo
)
from django.views.generic import TemplateView
from django.template import loader
from django.http import HttpResponse, Http404
from django.contrib.postgres.search import SearchQuery, SearchRank, SearchVector
from django.core.exceptions import MultipleObjectsReturned
from django.conf import settings
from shutil import copyfile
import os
from .reporte import (
    cuenta_urls, urls_activas, urls_inactivas, urls_redirecciones,
    urls_entidades, urls_titulos, urls_dominios, urls_paises
)
from datetime import timedelta, datetime
from django.utils import timezone
from time import mktime
import time
from django.urls import reverse_lazy
from django.views.generic.edit import UpdateView, CreateView
from django.contrib.auth.mixins import LoginRequiredMixin

from django.views.generic import TemplateView,View
from django.template import RequestContext
from django.http import HttpResponse
from django.contrib.postgres.search import SearchQuery, SearchRank, SearchVector
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
from phishing.phishing import lineas_md5,md5,archivo_hashes
from docx import Document
from docx.shared import Inches
from .entrada import( lee_csv, lee_txt, lee_json )

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
    print('url:' + str(url))
    url.reportado = True
    url.timestamp_reportado = timezone.now()
    url.save()
    for p in Url.objects.filter(redireccion=url.url):
        redirecciones_reporta(p)
        
@login_required(login_url=reverse_lazy('login'))
def monitoreo_id(request, pk):
    dominio = get_object_or_404(Dominio, pk=pk)
    if not dominio.activo:
        raise Http404()
    mensaje_form = MensajeForm()
    proxy_form = ProxyForm()
    urls = dominio.urls_activas
    context = {
        'dominio': dominio,
        'urls': urls
    }
    correos = []
    for url in urls:
        for x in url.dominio.correos.all():
            correos.append(str(x))
    datos = {
        'de': settings.CORREO_DE,
        'para': ', '.join(correos),
        'asunto': obten_asunto(dominio),
        'mensaje': obten_mensaje(dominio)
    }
    mensaje_form = MensajeForm(initial=datos)
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
        elif request.POST.get('boton-mensaje'):
            mensaje_form = MensajeForm(request.POST)
            if mensaje_form.is_valid():
                de = mensaje_form.cleaned_data['de']
                para = [x.strip() for x in mensaje_form.cleaned_data['para'].split(',')]
                cc = [x.strip() for x in mensaje_form.cleaned_data['cc']]
                cco = [x.strip() for x in mensaje_form.cleaned_data['cco']]
                asunto = mensaje_form.cleaned_data['asunto']
                mensaje = mensaje_form.cleaned_data['mensaje']
                mensaje_form = MensajeForm(request.POST)
                msg = genera_mensaje(dominio, de, para, cc, cco, asunto, mensaje)
                manda_correo(para, cc, cco, msg)
                for x in urls:
                    redirecciones_reporta(x)
                context = {
                    'dominio': dominio,
                    'urls': urls,
                    'de': de,
                    'para': ', '.join(para),
                    'cc': ', '.join(cc),
                    'cco': ', '.join(cco),
                    'asunto': asunto,
                    'mensaje': mensaje,
                    'captura': dominio.captura_url
                }
                return render(request, 'monitoreo_exito.html', context)
        elif request.POST.get('boton-ignorar') and request.user.is_superuser:
            for x in urls:
                redirecciones_reporta(x)
            return redirect('monitoreo')
        elif request.POST.get('boton-saltar'):
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
                sitios = verifica_urls([x.strip() for x in urls.split('\n') if x.strip()], None, False)
                context = context_reporte(sitios)
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
            context = context_reporte(sitios)
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
	resultados_ip=list()
	resultados_mail=list()
	resultados_dom=list()
	resultados_com=list()
	resultados_hash=list()
	message = "No se encontraron coincidencias"
	message2=""
	if request.method == "POST":
		campoBusqueda= Search(request.POST)
		if campoBusqueda.is_valid():
			match = campoBusqueda.cleaned_data['search']
			template = loader.get_template('results.html')
			query = SearchQuery(match)
			vector = SearchVector('ip')
			qs = Url.objects.annotate(
				search=vector).filter(
				search=query).values('id')
			vector_mail=SearchVector('correo')
			qs_mail = Correo.objects.annotate(
				search=vector_mail).filter(
				search=query).values('id')
			vector_com = SearchVector('comentario')	
			qs_com = Comentario.objects.filter(
				comentario__contains=match).values('url_id','id')
			vector_hash= SearchVector('hash')			
			qs_hash = Hash.objects.annotate(
				search=vector_hash).filter(
				search=query).values('url_id','id')
			#if len(qs)!=0:
			#return redirect('muestraResultados',reg=qs)
			###################################
			try:
				for i in qs.get():
					row = Url.objects.filter(id=qs.get()[i])
					resultados_ip.append(row.values().get())
			except Exception as e:
				print(e)
			#resultados = qs.get()
			#return render(request,'results.html',{'resultados':resultados,'match':match})
			#elif len(qs_mail)!=0:					
			try:
				for i in qs_mail.get():
					row = Url.objects.filter(id=qs_mail.get()[i])
					resultados_mail.append(row.values().get())		
			except Exception as e:
				print(e)
			try:					
				
				row = Url.objects.filter(id=qs_com.get()['url_id']).values().get()
				comm = Comentario.objects.filter(id=qs_com.get()['id']).values('comentario','num_linea').get()
				row['comentario']=comm['comentario']
				row['numero_linea']=comm['num_linea']	
				resultados_com.append(row)	
				
			except MultipleObjectsReturned:
				for i in qs_com:
					row = Url.objects.filter(id=i['url_id']).values().get()
					print(type(row))
					comm = Comentario.objects.filter(id=i['id']).values('comentario','num_linea').get()
					row['comentario']=comm['comentario']
					row['numero_linea']=comm['num_linea']
					resultados_com.append(row)
			except Exception as e:
				print(e)	
			return render(request,'results.html',{'resultados_ip':resultados_ip,'resultados_mail':resultados_mail,'resultados_com':resultados_com,'match':match})
			#return HttpResponse(template.render({'campoBusqueda':campoBusqueda}, request))
		else:
			message2 = "Campo Vacío. \nIngresa una IP, URL, Hash ,etc."
			return render(request,'busqueda.html',{'message2':message2})	
	else:	 
		campoBusqueda= Search()
		return render(request, 'busqueda.html', {})

@login_required(login_url=reverse_lazy('login'))
def muestraResultados(request,srch):
	return render(request,'results.html',{})
    
@login_required(login_url=reverse_lazy('login'))
def historico(request):
    fin = timezone.now()
    inicio = fin - timedelta(days=1)
    form = HistoricoForm()
    if request.method == 'POST':
        form = HistoricoForm(request.POST)
        if form.is_valid():
            inicio = form.cleaned_data['inicio']
            fin = form.cleaned_data['fin']
    sitios = Url.objects.filter(timestamp__lte=fin + timedelta(days=1), timestamp__gte=inicio)
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
    hoy = datetime.datetime.today().weekday() + 1
    return dias[hoy:] + dias[:hoy]

class ChartData(LoginRequiredMixin, APIView):
    
    def get(self, request, format=None):
        rand_color = randomcolor.RandomColor()
        
        top_paises = Url.objects.filter(~Q(dominio__pais=None)).values('dominio__pais').annotate(
            cuenta_pais=Count('dominio__pais')).order_by('-cuenta_pais')[:5]
        top_paises_data = {
            "labels": [p['dominio__pais'] for p in top_paises],
            "default": [p['cuenta_pais'] for p in top_paises]
        }

        top_hosting = Url.objects.filter(~Q(dominio__asn=None)).values('dominio__asn').annotate(
            cuenta_asn=Count('dominio__asn')).order_by('-cuenta_asn')[:5]
        top_hosting_data = {
            "labels": [p['dominio__asn'] for p in top_hosting],
            "default": [p['cuenta_asn'] for p in top_hosting]
        }
        
        sectores = Url.objects.filter(~Q(entidades_afectadas__clasificacion=None)).values(
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
        hoy = timezone.now().date()
        for x in range(6, -1, -1):
            num_detecciones.append(Url.objects.filter(
                timestamp_creacion__date=hoy - datetime.timedelta(days=x),
            ).count())
        detecciones_data = {
            'labels': dias,
            'default': num_detecciones
        }
        
        entidades = Url.objects.filter(~Q(entidades_afectadas=None)).values(
            'entidades_afectadas__nombre').annotate(
                cuenta_entidades=Count('entidades_afectadas__nombre'))
        labels = [e['entidades_afectadas__nombre'] for e in entidades]
        entidades_data = {
            "labels":  labels,
            "default": [e['cuenta_entidades'] for e in entidades],
            "colores": rand_color.generate(count=len(labels))
        }
        
        graphs = [top_paises_data, top_hosting_data, [], [], sectores_data, detecciones_data, entidades_data, []]
        return Response(graphs)

"""
days=['Sunday',
      'Monday',
      'Tuesday',
      'Wednesday',
      'Thursday',
      'Friday',
      'Saturday']
today = datetime.date.today()
monitor_hour = datetime.datetime(today.year,today.month,today.day-1,0,0,0) ##quitar -1
start_hour=monitor_hour
end_hour = monitor_hour.replace(hour=23,minute=59,second=59)
authentication_classes = []
permission_classes =  []
"""

def dash(request):
        #top5 = top5_countries(request)
        return render(request,'dashboard.html',{})

@login_required(login_url=reverse_lazy('login'))
def busca(request):
    context_instance = RequestContext(request)
    resultados_ip=list()
    resultados_mail=list()
    resultados_dom=list()
    resultados_com=list()
    resultados_hash_file=list()
    resultados_hash=list()
    message = "No se encontraron coincidencias"
    message2=""
    if request.method == "POST":
        campoBusqueda= Search(request.POST)
        if campoBusqueda.is_valid():
            match = campoBusqueda.cleaned_data['search']
            template = loader.get_template('results.html')
            query = SearchQuery(match)
            vector = SearchVector('ip')
            qs = Url.objects.annotate(
                search=vector).filter(
                    search=query).values('id')
            vector_mail=SearchVector('correos__correo')
            qs_mail = Url.objects.annotate(
                search=vector_mail).filter(
                    search=query).values('id')
            vector_dom = SearchVector('dominio__dominio')
            qs_domain = Url.objects.annotate(
                search=vector_dom).filter(
                    search=query).values('id')
            vector_hash_file = SearchVector('hash_archivo')
            qs_hash_file = Url.objects.annotate(
                search=vector_hash_file).filter(
                    search=query).values('id')
            qs_hash_lines = Url.objects.all()
            try:
                values_ip = qs.values().all()
                for rec  in values_ip:
                    row = rec
                    entidades = Url.objects.values('entidades_afectadas__nombre').filter(id=row['id']).get()
                    correo = Url.objects.values('correos__correo').filter(id=row['id']).get()
                    dominio = Url.objects.values('dominio__dominio').filter(id=row['id']).get()
                    row['entidades'] = list(entidades.values())
                    row['correo'] = correo['correos__correo']
                    row['dominio'] = dominio['dominio__dominio']
                    resultados_ip.append(row)
            except Exception as e:
                print(e)
            try:
                values_m = qs_mail.values().all()
                for rec in values_m:
                    row = rec
                    entidades = Url.objects.values('entidades_afectadas__nombre').filter(id=row['id']).get()
                    dominio = Url.objects.values('dominio__dominio').filter(id=row['id']).get()
                    row['entidades'] = list(entidades.values())
                    row['dominio'] = dominio['dominio__dominio']
                    resultados_mail.append(row)       
            except Exception as e:
                print(e)      
            ## Búsqueda de dominios
            try:
                values_d = qs_domain.values().all()
                for rec in values_d:
                    row = rec
                    correo = Url.objects.values('correos__correo').filter(id=row['id']).get()
                    row['correo'] = correo['correos__correo']
                    resultados_dom.append(row)
            except Exception as e:
                print(e)
            ### Búsqueda de Hash de archivos
            try:
                values_h_f = qs_hash_file.values().all()
                for rec in values_h_f:
                    row = rec
                    resultados_hash_file.append(row)
            except Exception as e:                
                print(e)
            return render(request,'results.html',{'resultados_ip':resultados_ip,'resultados_mail':resultados_mail,'resultados_com':resultados_com,
                                                  'resultados_dom':resultados_dom,'resultados_hf':resultados_hash_file,'match':match})
        else:
            message2 = "Campo Vacío. \nIngresa una IP, URL, Hash ,etc."
            return render(request,'busqueda.html',{'message2':message2})    
    else:
        campoBusqueda= Search()
        return render(request, 'dashboard.html', {})

class DocumentView(LoginRequiredMixin, View):
    def get(self,request, *args, **kwargs):
        if request.method == 'POST':
            return render(request,'dashboard.html',{})
        else:
            formulario = Doc()
            return render(request,'generar_rep.html',{'form':formulario})
        #return render(request, 'generar_rep.html', {})

@login_required(login_url=reverse_lazy('login'))
def createDoc(request):
    if request.method == 'POST':
        _post = Doc(request.POST)
        if _post.is_valid():
            nombre_archivo = _post.cleaned_data['nombre']
            init = _post.cleaned_data['inicio']
            fin = _post.cleaned_data['fin']
            ##
            sitios = Url.objects.filter(timestamp__lte=fin, timestamp__gte=init)
            context = context_reporte(sitios)
            context['inicio'] = init
            context['fin'] = fin
            context['form'] = _post                
            document = Document()
            document.add_heading('Reporte',0)
            p=document.add_paragraph('Reporte elaborado por la herramienta ')
            p.add_run('SAAPM').bold = True
            document.add_heading('Periodo',level=1)
            q = document.add_paragraph('De: ')
            q.add_run(str(context['inicio'])).bold = True
            q.add_run('      ')
            q.add_run('A :  ')
            q.add_run(str(context['fin'])).bold = True
            """
            for key,value in context.items():
                #document.add_paragraph(key + ':' )
                # if type(value) is str:
                document.add_paragraph(key + ':' +str(value))
                if type(value) is dict:
                    pass
                # document.save(nombre_archivo+'.docx')
                response = HttpResponse(content_type='application/vnd.openxmlformats-officedocument.wordprocessingml.document')
                response['Content-Disposition'] = 'attachment; filename='+nombre_archivo+'.docx'
                document.save(response)
            """
            response = HttpResponse(content_type='application/vnd.openxmlformats-officedocument.wordprocessingml.document')
            response['Content-Disposition'] = 'attachment; filename='+nombre_archivo+'.docx'
            activas = urls_activas(sitios)
            inactivas = urls_inactivas(sitios)
            redirecciones = urls_redirecciones(sitios)
            dominios = urls_dominios(sitios)
            q = document.add_paragraph("URLs analizadas: %d\n" % cuenta_urls(sitios))
            q.add_run("URLs activas: %d\n" % len(activas))
            q.add_run("URLs inactivas: %d\n" % len(inactivas))
            q.add_run("URLs redirecciones: %d\n" % len(redirecciones))
            q.add_run("Dominios afectados: %d" % len(dominios))
            q = document.add_paragraph("")
            q.add_run("Entidades:\n").bold = True            
            for e in urls_entidades(sitios):
                q.add_run("%s\n" % e)
            q = document.add_paragraph("")
            q.add_run("Dominios:").bold = True
            for e in dominios:
                q.add_run("%s\n" % e)
            q = document.add_paragraph("")
            q.add_run("Países:\n").bold = True
            for e in urls_paises(sitios):
                q.add_run("%s\n" % e)
            q = document.add_paragraph("")
            q.add_run("SITIOS ACTIVOS:\n\n").bold = True
            for u in activas:
                q.add_run("Identificador: %s\n" % u.identificador)
                q.add_run("Timestamp: %s\n" % u.timestamp)
                q.add_run("IP: %s\n" % u.ip)
                q.add_run("Código: %d\n" % u.codigo)
                q.add_run("URL: %s\n" % u.url)
                q.add_run("Reportado: %s\n" % u.reportado)
                q.add_run("Título: %s\n" % u.titulo)
                q.add_run("Entidades: %s\n" % u.entidades)
                q.add_run("Ofuscacion: %s\n" % u.ofuscacion)
                q.add_run("Correos: %s\n" % u.correos)
                q.add_run("Netname: %s\n" % u.netname)
                q.add_run("País: %s\n\n" % u.pais)

            q = document.add_paragraph("")
            q.add_run("SITIOS INACTIVOS:\n\n").bold = True
            for u in inactivas:
                q.add_run("Identificador: %s\n" % u.identificador)
                q.add_run("Timestamp: %s\n" % u.timestamp)
                q.add_run("IP: %s\n" % u.ip)
                q.add_run("Código: %d\n" % u.codigo)
                q.add_run("URL: %s\n" % u.url)
                q.add_run("Reportado: %s\n" % u.reportado)
                q.add_run("Correos: %s\n" % u.correos)
                q.add_run("Netname: %s\n" % u.netname)
                q.add_run("País: %s\n\n" % u.pais)

            q = document.add_paragraph("")
            q.add_run("REDIRECCIONES:\n\n").bold = True
            for u in redirecciones:
                q.add_run("Identificador: %s\n" % u.identificador)
                q.add_run("Timestamp: %s\n" % u.timestamp)
                q.add_run("IP: %s\n" % u.ip)
                q.add_run("Código: %d\n" % u.codigo)
                q.add_run("URL: %s\n" % u.url)
                q.add_run("Correos: %s\n" % u.correos)
                q.add_run("Netname: %s\n" % u.netname)
                q.add_run("País: %s\n\n" % u.pais)
                
            document.save(response)
            return response
            # return render(request,'generar_rep.html',{'nom':nombre_archivo,'env':True})
        else:            
            formulario = Doc()
            return render(request,'generar_rep.html',{'form':formulario})

# @login_required(login_url=reverse_lazy('login'))
def entrada(request):
    if request.method == 'POST':
        if request.POST.get("boton_correo"):
            form = CorreoForm(request.POST)
            if form.is_valid():
                c = form.cleaned_data['correo']
                resultados, urls = parsecorreo(c)
                verifica_urls(urls, None, False)
                return render(request, 'entrada_resultados.html',
                              {'resultados': resultados, 'urls': urls})
        elif request.POST.get("boton_archivo") and request.FILES['file']:
            form = CorreoArchivoForm(request.POST)
            f = request.FILES['file'].read().decode('utf-8')
            name = request.FILES['file'].name
            urls = []
            resultados, urls = parsecorreo(f)
            verifica_urls(urls, None, False)
            return render(request, 'entrada_resultados.html',
                          {'resultados': resultados, 'urls': urls})
    else:
        form1 = CorreoForm()
        form2 = CorreoArchivoForm()
    return render(request, 'entrada.html', {'form1': form1, 'form2': form2})
