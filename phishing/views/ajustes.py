from django.shortcuts import render, redirect, get_object_or_404
from django.views.generic.edit import UpdateView, CreateView
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.decorators import login_required
from django.urls import reverse_lazy
from phishing.aux import correo
from phishing.forms import(
    CambiaAsuntoForm, CambiaMensajeForm, CambiaUnamAsuntoForm, CambiaUnamMensajeForm, FrecuenciaForm
)
from phishing.models import Proxy, Ofuscacion, Entidad, Clasificacion_entidad, ASN
from phishing.aux import phishing, log
from django.forms import Textarea
from subprocess import Popen, PIPE
from django.conf import settings
from django import forms
from django.http import Http404

def cambia_frecuencia(funcion, n):
    n = 1 if n < 1 or n > 24 else n
    comando = "/bin/bash -c 'source %s/bin/activate && python %s/manage.py %s'" % \
              (settings.DIR_ENV, settings.BASE_DIR, funcion)
    process = Popen('crontab -l | egrep -v "%s"  | crontab -'
                    % (comando), shell=True, stdout=PIPE, stderr=PIPE)
    out, err = process.communicate()
    if err:
        log.log("Error: %s" % err.decode('utf-8', errors='ignore'), "ajustes.log")
    if out:
        log.log(out.decode('utf-8', errors='ignore'), "ajustes.log")
    i = "*/%d" % n if n < 24 else '0'
    process = Popen('(crontab -l ; echo "0 %s * * * %s") | sort - | uniq - | crontab -'
                    % (i, comando), shell=True, stdout=PIPE, stderr=PIPE)
    out, err = process.communicate()
    if err:
        log.log("Error: %s" % err.decode('utf-8', errors='ignore'), "ajustes.log")
    if out:
        log.log(out.decode('utf-8', errors='ignore'), "ajustes.log")

@login_required(login_url=reverse_lazy('login'))
def ajustes(request):
    proxies = Proxy.objects.all()
    asunto_form = CambiaAsuntoForm(initial={'asunto': correo.lee_plantilla_asunto()})
    mensaje_form = CambiaMensajeForm(initial={'mensaje': correo.lee_plantilla_mensaje()})
    unam_asunto_form = CambiaUnamAsuntoForm(initial={'asunto': correo.lee_plantilla_unam_asunto()})
    unam_mensaje_form = CambiaUnamMensajeForm(initial={'mensaje': correo.lee_plantilla_unam_mensaje()})
    actualizacion_form = FrecuenciaForm()
    verificacion_form = FrecuenciaForm()
    if request.method == 'POST':
        if request.POST.get('cambia-asunto'):
            asunto_form = CambiaAsuntoForm(request.POST)
            if asunto_form.is_valid():
                asunto = asunto_form.cleaned_data['asunto']
                correo.cambia_asunto(asunto)
        elif request.POST.get('cambia-mensaje'):
            mensaje_form = CambiaMensajeForm(request.POST)
            if mensaje_form.is_valid():
                mensaje = mensaje_form.cleaned_data['mensaje']
                correo.cambia_mensaje(mensaje)
        elif request.POST.get('cambia-unam-asunto'):
            unam_asunto_form = CambiaUnamAsuntoForm(request.POST)
            if unam_asunto_form.is_valid():
                asunto = unam_asunto_form.cleaned_data['asunto']
                correo.cambia_unam_asunto(asunto)
        elif request.POST.get('cambia-unam-mensaje'):
            unam_mensaje_form = CambiaUnamMensajeForm(request.POST)
            if unam_mensaje_form.is_valid():
                mensaje = unam_mensaje_form.cleaned_data['mensaje']
                correo.cambia_unam_mensaje(mensaje)
        elif request.POST.get('cambia-verificacion'):
            verificacion_form = FrecuenciaForm(request.POST)
            if verificacion_form.is_valid():
                verificacion = verificacion_form.cleaned_data['frecuencia']
                cambia_frecuencia('verifica', verificacion)
    context = {
        'proxies': proxies,
        'asunto_form': asunto_form,
        'mensaje_form': mensaje_form,
        'asunto_unam_form': unam_asunto_form,
        'mensaje_unam_form': unam_mensaje_form,
        'actualizacion_form': actualizacion_form,
        'verificacion_form': verificacion_form,
    }
    return render(request, 'ajustes/ajustes.html', context)

@login_required(login_url=reverse_lazy('login'))
def elimina_proxy(request, pk):
    proxy = get_object_or_404(Proxy, pk=pk)
    proxy.delete()
    return redirect('ajustes')

class ActualizaProxy(LoginRequiredMixin, UpdateView):
    model = Proxy
    template_name = 'ajustes/actualiza_proxy.html'
    success_url = reverse_lazy('ajustes')
    fields = ('http', 'https')
    
class NuevoProxy(LoginRequiredMixin, CreateView):
    model = Proxy
    template_name = 'ajustes/nuevo_proxy.html'
    success_url = reverse_lazy('ajustes')
    fields = ('http', 'https')

@login_required(login_url=reverse_lazy('login'))
def ofuscaciones_view(request):
    of = Ofuscacion.objects.all()
    context = {
        'ofuscaciones': of
    }
    return render(request, 'ajustes/ofuscaciones.html', context)

@login_required(login_url=reverse_lazy('login'))
def entidades_view(request):
    context = {
        'clasificaciones': Clasificacion_entidad.objects.all(),
        'entidades': Entidad.objects.all()
    }
    return render(request, 'ajustes/entidades.html', context)

@login_required(login_url=reverse_lazy('login'))
def elimina_ofuscacion(request, pk):
    recurso = get_object_or_404(Ofuscacion, pk=pk)
    recurso.delete()
    return redirect('ofuscaciones')

class ActualizaOfuscacion(LoginRequiredMixin, UpdateView):
    model = Ofuscacion
    template_name = 'ajustes/actualiza_ofuscacion.html'
    success_url = reverse_lazy('ofuscaciones')
    fields = ('nombre', 'regex')
    
class NuevaOfuscacion(LoginRequiredMixin, CreateView):
    model = Ofuscacion
    template_name = 'ajustes/nueva_ofuscacion.html'
    success_url = reverse_lazy('ofuscaciones')
    fields = ('nombre', 'regex')
    
@login_required(login_url=reverse_lazy('login'))
def elimina_entidad(request, pk):
    entidad = get_object_or_404(Entidad, pk=pk)
    entidad.delete()
    return redirect('entidades')

class ActualizaEntidad(LoginRequiredMixin, UpdateView):
    model = Entidad
    template_name = 'ajustes/actualiza_entidad.html'
    success_url = reverse_lazy('entidades')
    fields = ('nombre', 'clasificacion', 'lista_blanca')

    def get_form(self, form_class=None):
        form = super(ActualizaEntidad, self).get_form(form_class)
        form.fields['clasificacion'].required = False
        form.fields['lista_blanca'].required = False
        form.fields['lista_blanca'].widget = forms.Textarea()
        form.fields['lista_blanca'].label = 'Lista blanca de dominios (separados por salto de línea)'
        return form
    
class NuevaEntidad(LoginRequiredMixin, CreateView):
    model = Entidad
    template_name = 'ajustes/nueva_entidad.html'
    success_url = reverse_lazy('entidades')
    fields = ('nombre', 'clasificacion', 'lista_blanca')

    def get_form(self, form_class=None):
        form = super(NuevaEntidad, self).get_form(form_class)
        form.fields['clasificacion'].required = False
        form.fields['lista_blanca'].required = False
        form.fields['lista_blanca'].widget = forms.Textarea()
        form.fields['lista_blanca'].label = 'Lista blanca de dominios (separados por salto de línea)'
        return form

@login_required(login_url=reverse_lazy('login'))
def elimina_clasificacion(request, pk):
    c = get_object_or_404(Clasificacion_entidad, pk=pk)
    c.delete()
    return redirect('entidades')

class NuevaClasificacionEntidad(LoginRequiredMixin, CreateView):
    model = Clasificacion_entidad
    template_name = 'ajustes/nueva_clasificacion.html'
    success_url = reverse_lazy('entidades')
    fields = ('nombre',)

    def get_form(self, form_class=None):
        form = super(NuevaClasificacionEntidad, self).get_form(form_class)
        form.fields['nombre'].label = 'Clasificación'
        return form

class ActualizaClasificacionEntidad(LoginRequiredMixin, UpdateView):
    model = Clasificacion_entidad
    template_name = 'ajustes/actualiza_clasificacion.html'
    success_url = reverse_lazy('entidades')
    fields = ('nombre',)

    def get_form(self, form_class=None):
        form = super(ActualizaClasificacionEntidad, self).get_form(form_class)
        form.fields['nombre'].label = 'Clasificación'
        return form

@login_required(login_url=reverse_lazy('login'))
def asn_view(request):
    context = {
        'asn': ASN.objects.all(),
    }
    return render(request, 'ajustes/asn.html', context)

@login_required(login_url=reverse_lazy('login'))
def elimina_asn(request, pk):
    a = get_object_or_404(ASN, pk=pk)
    if a.dominios.count() > 0:
        raise Http404()
    a.delete()
    return redirect('asns')

class ActualizaASN(LoginRequiredMixin, UpdateView):
    model = ASN
    template_name = 'ajustes/actualiza_asn.html'
    success_url = reverse_lazy('asns')
    fields = ('asn', 'nombre', 'formularios')

    def get_form(self, form_class=None):
        form = super(ActualizaASN, self).get_form(form_class)
        form.fields['nombre'].required = False
        form.fields['formularios'].required = False
        form.fields['formularios'].widget = Textarea()
        form.fields['formularios'].label = 'Formularios de abuso (separados por un salto de línea)'
        return form
    
class NuevoASN(LoginRequiredMixin, CreateView):
    model = ASN
    template_name = 'ajustes/nuevo_asn.html'
    success_url = reverse_lazy('asns')
    fields = ('asn', 'nombre', 'formularios')

    def get_form(self, form_class=None):
        form = super(NuevoASN, self).get_form(form_class)
        form.fields['nombre'].required = False
        form.fields['formularios'].required = False
        form.fields['formularios'].widget = Textarea()
        form.fields['formularios'].label = 'Formularios de abuso (separados por un salto de línea)'
        return form
