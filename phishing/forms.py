from django import forms
from .models import *
from django.forms.widgets import SelectDateWidget
from django.utils import timezone
from django.forms import ModelForm
from django.utils.translation import ugettext_lazy as _
from django.core.validators import MaxValueValidator, MinValueValidator

class UrlsForm(forms.Form):
    urls = forms.CharField(label='URLs', widget=forms.Textarea)

class ProxyForm(forms.Form):
    http = forms.URLField(label='HTTP', required=False)
    https = forms.URLField(label='HTTPS', required=False)
    tor = forms.BooleanField(label='Tor', required=False)
    proxy = forms.ModelChoiceField(label='Proxies', queryset=Proxy.objects.all(),
                                   empty_label="Ninguno", required=False)
    
class Search(forms.Form):
    search = forms.CharField(max_length=500,required=True)
    archivos = forms.BooleanField(label='Búsqueda en archivos', required=False)

class HistoricoForm(forms.Form):
    inicio = forms.DateTimeField(label='Fecha inicio',
                                 widget=forms.DateTimeInput(
                                     attrs={'class': 'datetimepicker'},
                                     format="%Y-%m-%d %H:%M"
                                 ),
                                 initial=timezone.localtime(timezone.now()) -
                                 timezone.timedelta(days=1))
    fin = forms.DateTimeField(label='Fecha fin',
                              widget=forms.DateTimeInput(
                                  attrs={'class': 'datetimepicker'},
                                  format="%Y-%m-%d %H:%M",
                              ),
                              initial=timezone.localtime(timezone.now()))
    
class CambiaAsuntoForm(forms.Form):
    asunto = forms.CharField(label='Plantilla de asunto', max_length=512, required=True)

class CambiaMensajeForm(forms.Form):
    mensaje = forms.CharField(label='Plantilla de mensaje', required=True, widget=forms.Textarea)

class CambiaUnamAsuntoForm(forms.Form):
    asunto = forms.CharField(label='Plantilla de asunto UNAM', max_length=512, required=True)

class CambiaUnamMensajeForm(forms.Form):
    mensaje = forms.CharField(label='Plantilla de mensaje UNAM', required=True, widget=forms.Textarea)

class FrecuenciaForm(forms.Form):
    frecuencia = forms.IntegerField(required=True,
                                    validators=[MinValueValidator(1), MaxValueValidator(23)])

class CorreoForm(forms.Form):
    correo = forms.CharField(label='Correo', widget=forms.Textarea, required=False)
    
class ArchivoForm(forms.Form):
    file = forms.FileField(label='Archivo (txt, csv, json)', required=False)

class CorreoArchivoForm(forms.Form):
    file = forms.FileField(label='Archivo', required=False)

class GraficasForm(forms.Form):

    archivo = forms.CharField(label='Nombre de archivo', max_length=128)

    inicio = forms.DateTimeField(label='Fecha inicio',
                                 widget=forms.DateTimeInput(
                                     attrs={'class': 'datetimepicker'},
                                     format="%Y-%m-%d %H:%M"
                                 ),
                                 initial=timezone.localtime(timezone.now()) -
                                 timezone.timedelta(days=1))
    fin = forms.DateTimeField(label='Fecha fin',
                              widget=forms.DateTimeInput(
                                  attrs={'class': 'datetimepicker'},
                                  format="%Y-%m-%d %H:%M",
                              ),
                              initial=timezone.localtime(timezone.now()))
    sitios = forms.BooleanField(label='Sitios de phishing', required=False)
    top_sitios = forms.BooleanField(label='Top 5 sitios phishing vs tiempo de vida', required=False)
    sectores = forms.BooleanField(label='Sectores afectados', required=False)
    entidades = forms.BooleanField(label='Entidades afectadas', required=False)
    detecciones = forms.BooleanField(label='Número de detecciones', required=False)
    tiempo_reporte = forms.BooleanField(label='Tiempo promedio de reporte', required=False)
    top_paises = forms.BooleanField(label='Top 10 países que hospedan phishing', required=False)
    top_hosting = forms.BooleanField(label='Top 10 servicios de hosting', required=False)
    urls = forms.BooleanField(label='Adjuntar información sobre URLs', required=False)

class MensajeForm(forms.Form):
    
    urls = forms.ModelMultipleChoiceField(label='Direcciones URL a reportar',
                                          queryset=None, required=True,
                                          widget=forms.CheckboxSelectMultiple)
    de = forms.CharField(label='De')
    para = forms.CharField(label='Para', required=False)
    cc = forms.CharField(label='CC', required=False)
    cco = forms.CharField(label='CCO', required=False)
    asunto = forms.CharField(label='Asunto')
    mensaje = forms.CharField(label='Mensaje', widget=forms.Textarea)
    capturas = forms.ModelMultipleChoiceField(label='Selecciona las capturas a enviar',
                                              queryset=None, required=False,
                                              widget=forms.CheckboxSelectMultiple)
                                              
    def __init__(self, *args, **kwargs):
        urls = kwargs.pop('urls', Url.objects.none())
        super().__init__(*args, **kwargs)
        self.fields['capturas'].queryset = SitioInfo.objects.filter(pk__in=
            [x.sitio_info.pk for x in urls if x.sitio_info and x.sitio_info.captura]).distinct()
        self.fields['urls'].queryset = urls
        self.fields['urls'].error_messages['required'] = 'Seleccionar al menos una dirección URL'

    def actualiza(self):
        urls = [x.pk for x in self.fields['urls'].queryset]
        self.fields['urls'].queryset = Url.objects.filter(pk__in=urls)
