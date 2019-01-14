from django.db import models
from django_countries.fields import CountryField
from django.contrib import admin
from .storage import OverwriteStorage
from django.utils.translation import ugettext_lazy as _
from django.core.exceptions import ValidationError

class Clasificacion_entidad(models.Model):

    nombre = models.CharField(max_length=128, unique=True)

    def __str__(self):
        return self.nombre
    
class Entidades(models.Model):
    
    nombre = models.CharField(max_length=128, unique=True)
    clasificacion = models.ForeignKey(Clasificacion_entidad, on_delete=models.SET_NULL, null=True)
    formularios = models.CharField(max_length=1024, null=True)
    
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

    @property
    def formularios_lst(self):
        if self.formularios:
            return [x.strip() for x in str(self.formularios).split('\n') if x.strip()]
        return []

    @property
    def formularios_coma(self):
        if self.formularios:
            return ', '.join(self.formularios_lst)
        return 'No asignados'
    
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

class RIR(models.Model):

    nombre = models.CharField(max_length=128, unique=True, null=False)
    
    def __str__(self):
        return self.nombre

class DNS(models.Model):
    
    nombre = models.CharField(max_length=128, unique=True)

    def __str__(self):
        return self.nombre
    
class Dominio(models.Model):
    
    dominio = models.CharField(max_length=256, unique=True)
    ip = models.CharField(max_length=128, blank=True)
    captura = models.ImageField(storage=OverwriteStorage(),
                                upload_to='capturas', blank=True, null=True)
    pais = CountryField(null=True)
    correos = models.ManyToManyField(Correo)
    servidor = models.CharField(max_length=128, null=True)
    asn = models.CharField(max_length=128, null=True)
    isp = models.CharField(max_length=128, null=True)
    dns = models.ManyToManyField(DNS)
    rir = models.ForeignKey(RIR, on_delete=models.PROTECT, null=True)
    
    @property
    def captura_url(self):
        if self.captura and hasattr(self.captura, 'url'):
            return self.captura.url
        return '/media/na.png'
    
    @property
    def urls_activas(self):
        urls = self.url_set.filter(reportado=False, ignorado=False, codigo__lt=400, codigo__gte=200)
        return urls.filter(pk__in=[x.pk for x in urls if x.activo_redirecciones])

    @property
    def activo(self):
        return len(self.urls_activas) > 0

    def __str__(self):
        return self.dominio
    
    @property
    def servidor_web(self):
        if self.servidor:
            return self.servidor
        return 'No identificado'

    @property
    def correos_abuso(self):
        if len(self.correos.all()) == 0:
            return ''
        s = []
        for x in self.correos.all():
            s.append(x.correo)
        return ', '.join(s)

    @property
    def servidores_dns(self):
        if len(self.dns.all()) == 0:
            return 'No identificados'
        s = []
        for x in self.dns.all():
            s.append(x.nombre)
        return ', '.join(s)

class Url(models.Model):

    OPCIONES_DETECCION = (
        ('M', 'Sitio malicioso'),
        ('P', 'Sitio phishing'),
        ('I', 'Indefinido'),
        ('N', 'Sitio no malicioso'),
    )
    identificador = models.CharField(max_length=32, unique=True)
    url = models.URLField(max_length=512, unique=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    timestamp_creacion = models.DateTimeField(auto_now_add=True)
    timestamp_deteccion = models.DateTimeField(null=True)
    timestamp_desactivado = models.DateTimeField(null=True)
    timestamp_reactivacion = models.DateTimeField()
    codigo = models.IntegerField(default=-1)
    codigo_anterior = models.IntegerField(default=-1)
    titulo = models.CharField(max_length=512, null=True)
    captura = models.ImageField(storage=OverwriteStorage(),
                                upload_to='capturas', blank=True, null=True)
    captura_anterior = models.ImageField(storage=OverwriteStorage(),
                                upload_to='capturas_anteriores', blank=True, null=True)
    ofuscacion = models.ManyToManyField(Ofuscacion)
    hash_archivo = models.CharField(max_length=32, null=True)
    entidades_afectadas = models.ManyToManyField(Entidades)
    ignorado = models.BooleanField(default=False)
    reportado = models.BooleanField(default=False)
    dominio = models.ForeignKey(Dominio, on_delete=models.PROTECT)
    archivo = models.FileField(storage=OverwriteStorage(),
                               upload_to='archivos', blank=True, null=True)
    redireccion = models.URLField(max_length=512, null=True)
    deteccion = models.CharField(max_length=1,
                                 choices=OPCIONES_DETECCION,
                                 default='I')

    @property
    def get_redireccion(self):
        if self.codigo < 300 or self.codigo >= 400:
            return None        
        r = self.redireccion
        url = None
        while r:
            try:
                url = Url.objects.get(url=r)
            except Url.DoesNotExist:
                return None
            r = url.redireccion
        return url
        
    @property
    def captura_url(self):
        url = self
        if self.codigo < 400 and self.codigo >= 300:
            url = self.get_redireccion
        if url and url.captura and hasattr(url.captura, 'url'):
            return url.captura.url
        return '/media/na.png'

    @property
    def captura_anterior_url(self):
        url = self
        if self.codigo < 400 and self.codigo >= 300:
            url = self.get_redireccion
        if url.captura_anterior and hasattr(url.captura_anterior, 'url'):
            return url.captura_anterior.url
        return '/media/na.png'
    
    @property
    def estado_deteccion(self):
        url = self
        if self.codigo >= 300 and self.codigo < 400:
            url = self.get_redireccion
        return 'Indefinido' if url is None else url.deteccion

    @property
    def archivo_url(self):
        if self.archivo and hasattr(self.archivo, 'url'):
            return self.archivo.url

    @property
    def entidades(self):
        if len(self.entidades_afectadas.all()) == 0:
            return 'No Identificadas'
        s = []
        for x in self.entidades_afectadas.all():
            s.append(x.nombre.title() + (' (%s)' % x.clasificacion) if x.clasificacion else '')
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
    def codigo_estado(self):
        if self.codigo >= 0:
            return str(self.codigo)
        return 'Sin respuesta'

    @property
    def codigo_anterior_estado(self):
        if self.codigo >= 0:
            return str(self.codigo_anterior)
        return 'Sin respuesta'

    @property
    def activo(self):
        return self.codigo >= 200 and self.codigo < 300
    
    @property
    def activo_redirecciones(self):
        if self.codigo >= 400 or self.codigo < 200:
            return False
        url = self
        if self.codigo >= 300:
            url = self.get_redireccion            
        return url and url.activo
        
    @property
    def estado(self):
        if self.activo:
            return 'Sitio activo'
        elif self.codigo >= 300 and self.codigo < 400:
            if self.activo_redirecciones:
                return 'Redirección activa'
            return 'Redirección inactiva'
        return 'Sitio inactivo'
    
    def __str__(self):
        return self.url
         
class Recurso(models.Model):

    es_phishtank = models.BooleanField(default=False,
                                       verbose_name= _('Es llave de API de phistank (No seleccionar si se trata de una URL)'))
    recurso = models.CharField(max_length=256, unique=True,
                               verbose_name=_("URL o llave de API de phishtank"))
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
    
class Mensaje(models.Model):

    ticket = models.CharField(max_length=25, unique=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return self.ticket

class MensajeURL(models.Model):

    url = models.ForeignKey(Url, on_delete=models.CASCADE)
    mensaje = models.ForeignKey(Mensaje, on_delete=models.CASCADE)
    timestamp_creacion_sitio = models.DateTimeField()
    timestamp_desactivado = models.DateTimeField(null=True)
    timestamp_deteccion = models.DateTimeField()
    entidades_afectadas = models.ManyToManyField(Entidades)
    pais = CountryField(null=True)
    asn = models.CharField(max_length=128, null=True)
    
    class Meta:
        get_latest_by = 'mensaje__timestamp'
        
