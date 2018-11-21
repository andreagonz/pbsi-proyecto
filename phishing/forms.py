from django import forms
from .models import Proxy, Recurso, Url
from django.forms.widgets import SelectDateWidget
from django.utils import timezone
from django.forms import ModelForm
from django.utils.translation import ugettext_lazy as _

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
    inicio = forms.DateField(label='Fecha inicio', widget=SelectDateWidget(
        years=range(timezone.localtime(timezone.now()).year - 10,
                    timezone.localtime(timezone.now()).year + 1)),
                             initial=timezone.localtime(timezone.now()))
    fin = forms.DateField(label='Fecha fin',
                          widget=SelectDateWidget(
                              years=range(timezone.localtime(timezone.now()).year - 10,
                                          timezone.localtime(timezone.now()).year + 1)),
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
    frecuencia = forms.IntegerField(required=True)

class RecursoForm(ModelForm):
    class Meta:
        model = Recurso
        fields = ['es_phishtank', 'recurso', 'max_urls']
        labels = {
            "es_phistank": _("Es llave de API de phistank"),
            "recurso": _("Recurso o llade de API de phishtank"),
            "max_urls": _("Número máximo de URLs a extraer por consulta"),
        }

class CorreoForm(forms.Form):
    correo = forms.CharField(label='Correo', widget=forms.Textarea, required=False)
    
class ArchivoForm(forms.Form):
    file = forms.FileField(label='Archivo (txt, csv, json)', required=False)

class CorreoArchivoForm(forms.Form):
    file = forms.FileField(label='Archivo', required=False)

class GraficasForm(forms.Form):

    archivo = forms.CharField(label='Nombre de archivo', max_length=128)
    inicio = forms.DateField(label='Fecha inicio', widget=SelectDateWidget(
        years=range(timezone.localtime(timezone.now()).year - 10,
                    timezone.localtime(timezone.now()).year + 1)),
                             initial=timezone.localtime(timezone.now()))
    fin = forms.DateField(label='Fecha fin',
                          widget=SelectDateWidget(
                              years=range(timezone.localtime(timezone.now()).year - 10,
                                          timezone.localtime(timezone.now()).year + 1)),
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
    
    de = forms.CharField(label='De')
    para = forms.CharField(label='Para')
    cc = forms.CharField(label='CC', required=False)
    cco = forms.CharField(label='CCO', required=False)
    asunto = forms.CharField(label='Asunto')
    mensaje = forms.CharField(label='Mensaje', widget=forms.Textarea)
    capturas = forms.ModelMultipleChoiceField(label='Selecciona las capturas a enviar',
                                              queryset=None, required=False)

    def __init__(self, *args, **kwargs):
        urls = kwargs.pop('urls', Url.objects.none())
        super().__init__(*args, **kwargs)
        self.fields['capturas'].queryset = urls.exclude(captura=None)
