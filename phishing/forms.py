from django import forms
from .models import Proxy, Recurso
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
    
class MensajeForm(forms.Form):
    de = forms.CharField(label='De')
    para = forms.CharField(label='Para')
    cc = forms.CharField(label='CC', required=False)
    cco = forms.CharField(label='CCO', required=False)
    asunto = forms.CharField(label='Asunto')
    mensaje = forms.CharField(label='Mensaje', widget=forms.Textarea)

class Search(forms.Form):
    search=forms.CharField(max_length=500,required=True)

class HistoricoForm(forms.Form):
    inicio = forms.DateField(widget=SelectDateWidget
                                 (years=range(timezone.now().year - 10, timezone.now().year + 1)))
    fin = forms.DateField(widget=SelectDateWidget
                              (years=range(timezone.now().year - 10, timezone.now().year + 1)))

class CambiaAsuntoForm(forms.Form):
    asunto = forms.CharField(max_length=512, required=True)

class CambiaMensajeForm(forms.Form):
    mensaje = forms.CharField(required=True, widget=forms.Textarea)

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

class Doc(forms.Form):
    nombre = forms.CharField(max_length=100,required=True)
    inicio = forms.DateField(widget=SelectDateWidget(years=range(timezone.now().year - 10, timezone.now().year + 1)))
    fin = forms.DateField(widget=SelectDateWidget(years=range(timezone.now().year - 10, timezone.now().year + 1)))

class CorreoForm(forms.Form):
    correo = forms.CharField(label='Correo', widget=forms.Textarea, required=False)
    
class ArchivoForm(forms.Form):
    file = forms.FileField(label='Archivo (txt, csv, json)', required=False)

class CorreoArchivoForm(forms.Form):
    file = forms.FileField(label='Archivo', required=False)
