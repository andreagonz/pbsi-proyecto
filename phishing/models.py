from django.db import models
from django_countries.fields import CountryField
from django.contrib import admin
from .storage import OverwriteStorage
from django.utils.translation import ugettext_lazy as _
from django.core.exceptions import ValidationError

class Entidades(models.Model):
    
    nombre = models.CharField(max_length=128, unique=True)

    def __str__(self):
        return self.nombre

    def clean(self):
        super(Entidades, self).clean()
        try:
            e = Entidades.objects.get(nombre__iexact=self.nombre)
            if e.pk != self.pk:
                raise ValidationError('Ya existe una entidad con este nombre.')
        except Entidades.DoesNotExist:
            pass
                
class Ofuscacion(models.Model):

    regex = models.CharField(max_length=128)
    nombre = models.CharField(max_length=128)

    def __str__(self):
        return self.nombre

    class Meta:
        unique_together = ('regex', 'nombre',)
        
class Correo(models.Model):

    correo = models.CharField(max_length=512, unique=True)
        
    def __str__(self):
        return self.correo

class Dominio(models.Model):
    
    dominio = models.CharField(max_length=256, unique=True)
    captura = models.ImageField(storage=OverwriteStorage(),
                                upload_to='capturas', blank=True, null=True)

    @property
    def captura_url(self):
        if self.captura and hasattr(self.captura, 'url'):
            return self.captura.url
    
    def __str__(self):
        return self.dominio

class Url(models.Model):

    identificador = models.CharField(max_length=32, unique=True)
    url = models.URLField(max_length=512)
    timestamp = models.DateTimeField(auto_now_add=True)
    ip = models.CharField(max_length=15, blank=True)
    codigo = models.IntegerField(default=-1)
    titulo = models.CharField(max_length=512, null=True)
    captura = models.ImageField(storage=OverwriteStorage(),
                                upload_to='capturas', blank=True, null=True)
    ofuscacion = models.ManyToManyField(Ofuscacion)
    hash_archivo = models.CharField(max_length=32, null=True)
    entidades_afectadas = models.ManyToManyField(Entidades)
    reportado = models.BooleanField(default=False)
    pais = CountryField(null=True)
    correos = models.ManyToManyField(Correo)
    dominio = models.ForeignKey(Dominio, on_delete=models.PROTECT, null=True)
    netname = models.CharField(max_length=128, null=True)
    archivo = models.FileField(storage=OverwriteStorage(),
                               upload_to='archivos', blank=True, null=True)
    
    class Meta:
        unique_together = ('url', 'ip',)

    @property
    def captura_url(self):
        if self.captura and hasattr(self.captura, 'url'):
            return self.captura.url

    @property
    def archivo_url(self):
        if self.archivo and hasattr(self.archivo, 'url'):
            return self.archivo.url

    @property
    def entidades(self):
        if len(self.entidades_afectadas.all()) == 0:
            return 'No Identificada'
        s = []
        for x in self.entidades_afectadas.all():
            s.append(x.nombre.title())
        return ', '.join(s)

    @property
    def ofuscaciones(self):
        if len(self.ofuscacion.all()) == 0:
            return 'No Identificada'
        s = []
        for x in self.ofuscacion.all():
            s.append(x.nombre)
        return ', '.join(s)

    @property
    def correos_abuso(self):
        if len(self.correos.all()) == 0:
            return ''
        s = []
        for x in self.correos.all():
            s.append(x.correo)
        return ', '.join(s)

    @property
    def codigo_estado(self):
        if self.codigo >= 0:
            return str(self.codigo)
        return 'Sin respuesta'

    def __str__(self):
        return self.url
         
class Recurso(models.Model):

    es_phishtank = models.BooleanField(default=False,
                                       verbose_name= _('Es llave de API de phistank (No seleccionar si se trata de una URL)'))
    recurso = models.CharField(max_length=256, unique=True,
                               verbose_name=_("URL o llade de API de phishtank"))
    max_urls = models.IntegerField(default=-1,
                                   verbose_name=_("Número máximo de URLs a extraer por consulta (si es negativo se extraen todas)"))

    def __str__(self):
        return self.recurso
    
class Proxy(models.Model):

    http = models.URLField(max_length=256)
    https = models.URLField(max_length=256)

    class Meta:
        unique_together = ('http', 'https',)

    def __str__(self):
        s = []
        s.append('' if self.http is None else '%s' % self.http)
        s.append('' if self.https is None else '%s' % self.https)
        return ', '.join(s)
