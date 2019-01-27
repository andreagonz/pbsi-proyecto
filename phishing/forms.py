from django import forms
from phishing.models import *
from django.forms.widgets import SelectDateWidget
from django.utils import timezone
from django.forms import ModelForm
from django.utils.translation import ugettext_lazy as _
from django.core.validators import MaxValueValidator, MinValueValidator
from django.conf import settings

class UrlsForm(forms.Form):
    urls = forms.CharField(label='URLs', widget=forms.Textarea)

class ProxyForm(forms.Form):
    http = forms.URLField(label='HTTP', required=False)
    https = forms.URLField(label='HTTPS', required=False)
    tor = forms.BooleanField(label='Tor', required=False)
    proxy = forms.ModelChoiceField(label='Proxies', queryset=Proxy.objects.all(),
                                   empty_label="Ninguno", required=False)
    user_agent = forms.CharField(max_length=256,required=True, initial=settings.USER_AGENT)
    
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
                                    validators=[MinValueValidator(1), MaxValueValidator(24)])

class CorreoForm(forms.Form):
    correo = forms.CharField(label='Correo', widget=forms.Textarea, required=False)
    
class ArchivoForm(forms.Form):
    file = forms.FileField(label='Archivo (txt, csv, json)', required=False)

class CorreoArchivoForm(forms.Form):
    file = forms.FileField(label='Archivo', required=False)

class GraficasForm(forms.Form):

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
    archivo = forms.CharField(label='Nombre de archivo', max_length=128)
    
    sitios = forms.BooleanField(
        label='Gráfica "Sitios de phishing"',
        required=False,
        widget=forms.CheckboxInput(
            attrs={'style':'float:left;margin-left:200px;margin-top:-22px;'}
        )
    )
    sitios_info = forms.CharField(
        label='Descripción',
        required=False,
        widget=forms.Textarea(attrs={'rows':2}),
        initial='Número de sitios phishing detectados, activos y reportados'
    )
    
    top_sitios = forms.BooleanField(
        label='Gráfica "Top 5 sitios phishing vs tiempo de vida"',
        required=False,
        widget=forms.CheckboxInput(
            attrs={'style':'float:left;margin-left:330px;margin-top:-22px;'}
        )
    )
    top_sitios_info = forms.CharField(
        label='Descripción',
        required=False,
        widget=forms.Textarea(attrs={'rows':2}),
        initial='Top 5 sitios phishing con mayor tiempo de vida desde su registro en el sistema'
    )
        
    sectores = forms.BooleanField(
        label='Gráfica "Sectores afectados"',
        required=False,
        widget=forms.CheckboxInput(
            attrs={'style':'float:left;margin-left:220px;margin-top:-22px;'}
        )
    )
    sectores_info = forms.CharField(
        label='Descripción',
        required=False,
        widget=forms.Textarea(attrs={'rows':2}),
        initial='Sectores que han sido afectados por sitios phishing'
    )
    
    entidades = forms.BooleanField(
        label='Gráfica "Entidades afectadas"',
        required=False,
        widget=forms.CheckboxInput(
            attrs={'style':'float:left;margin-left:230px;margin-top:-22px;'}
        )
    )
    entidades_info = forms.CharField(
        label='Descripción',
        required=False,
        widget=forms.Textarea(attrs={'rows':2}),
        initial='Entidades que han sido afectadas por sitios phishing'
    )
    
    detecciones = forms.BooleanField(
        label='Gráfica "Número de detecciones"',
        required=False,
        widget=forms.CheckboxInput(
            attrs={'style':'float:left;margin-left:245px;margin-top:-22px;'}
        )
    )
    detecciones_info = forms.CharField(
        label='Descripción',
        required=False,
        widget=forms.Textarea(attrs={'rows':2}),
        initial='Número de detecciones de sitios phishing por día'
    )
    
    tiempo_reporte = forms.BooleanField(
        label='Gráfica "Tiempo promedio de reporte"',
        required=False,
        widget=forms.CheckboxInput(
            attrs={'style':'float:left;margin-left:270px;margin-top:-22px;'}
        )
    )
    tiempo_reporte_info = forms.CharField(
        label='Descripción',
        required=False,
        widget=forms.Textarea(attrs={'rows':2}),
        initial='Tiempo promedio por día de reporte de sitio phishing desde su registro y tiempo promedio por día de vida de sitios phishing después de ser reportados'
    )
    
    top_paises = forms.BooleanField(
        label='Gráfica "Top 10 países que hospedan phishing"',
        required=False,
        widget=forms.CheckboxInput(
            attrs={'style':'float:left;margin-left:330px;margin-top:-22px;'}
        )
    )
    top_paises_info = forms.CharField(
        label='Descripción',
        required=False,
        widget=forms.Textarea(attrs={'rows':2}),
        initial='Top 10 países que hospedan sitios phishing'
    )
    
    top_hosting = forms.BooleanField(
        label='Gráfica "Top 10 servicios de hosting"',
        required=False,
        widget=forms.CheckboxInput(
            attrs={'style':'float:left;margin-left:260px;margin-top:-22px;'}
        )
    )
    top_hosting_info = forms.CharField(
        label='Descripción',
        required=False,
        widget=forms.Textarea(attrs={'rows':2}),
        initial='Top 10 servicios de hosting que hospedan sitios phishing'
    )
    
    urls = forms.BooleanField(
        label='Adjuntar información sobre URLs',
        required=False,
        widget=forms.CheckboxInput(
            attrs={'style':'float:left;margin-left:247px;margin-top:-22px;'}
        )
    )

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
        self.fields['capturas'].queryset = UrlActiva.objects.filter(
            pk__in=[x.obten_info.pk for x in urls if x.obten_info and x.obten_info.captura]).distinct()
        self.fields['urls'].queryset = urls
        self.fields['urls'].error_messages['required'] = 'Seleccionar al menos una dirección URL'

    def actualiza(self):
        urls = [x.pk for x in self.fields['urls'].queryset]
        qs = Url.objects.filter(pk__in=urls)
        self.fields['urls'].queryset = qs
        self.fields['capturas'].queryset = UrlActiva.objects.filter(
            pk__in=[x.obten_info.pk for x in qs if x.obten_info and x.obten_info.captura]).distinct()

class ActualizaURL(forms.Form):

    OPCIONES_DETECCION = (
        ('M', 'Sitio malicioso'),
        ('P', 'Sitio phishing'),
        ('I', 'Indefinido'),
        ('N', 'Sitio no malicioso'),
    )
    
    entidad = forms.ModelChoiceField(label='Entidad afectada', queryset=Entidad.objects.all(),
                                     required=False)
    deteccion = forms.ChoiceField(choices=OPCIONES_DETECCION, required=True)

    def __init__(self, *args, **kwargs):
        info = kwargs.pop('info', None)
        super().__init__(*args, **kwargs)
        self.fields['entidad'].initial = info.entidad_afectada
        self.fields['deteccion'].initial = info.deteccion
