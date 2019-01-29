from django.db import models
from django_countries.fields import CountryField
from django.contrib import admin
from .storage import OverwriteStorage
from django.utils.translation import ugettext_lazy as _
from django.core.exceptions import ValidationError
import magic
from django.utils import timezone
import os

class Clasificacion_entidad(models.Model):

    nombre = models.CharField(max_length=128, unique=True)

    def __str__(self):
        return self.nombre
    
class Entidad(models.Model):
    
    nombre = models.CharField(max_length=128, unique=True)
    clasificacion = models.ForeignKey(Clasificacion_entidad, on_delete=models.SET_NULL, null=True,
                                      related_name='entidades')
    lista_blanca = models.CharField(max_length=2048, null=True)
    
    def __str__(self):        
        return self.nombre

    @property
    def clasificacion_str(self):
        return self.clasificacion if self.clasificacion else 'No asignada'

    @property
    def lista_blanca_lst(self):
        return [x.strip() for x in self.lista_blanca.split() if x.strip()] if self.lista_blanca else []
    
    def clean(self):
        super(Entidad, self).clean()
        try:
            e = Entidad.objects.get(nombre__iexact=self.nombre)
            if e.pk != self.pk:
                raise ValidationError('Ya existe una entidad con este nombre.')
        except Entidad.DoesNotExist:
            pass

class ASN(models.Model):

    asn = models.PositiveIntegerField(unique=True)
    nombre = models.CharField(max_length=128)
    formularios = models.CharField(max_length=2048, null=True)

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

    def __str__(self):
        return "AS%d %s" % (self.asn, self.nombre)
    
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
    asn = models.ForeignKey(ASN, on_delete=models.SET_NULL, null=True, related_name='dominios')
    isp = models.CharField(max_length=128, null=True)
    dns = models.ManyToManyField(DNS)
    rir = models.ForeignKey(RIR, on_delete=models.SET_NULL, null=True)
    
    @property
    def captura_url(self):
        if self.captura and hasattr(self.captura, 'url'):
            return self.captura.url
        return '/media/na.png'

    @property
    def urls_activas(self):
        return self.urls.order_by('url', '-timestamp_creacion').distinct('url').filter(
            pk__in=[x.pk for x in self.urls.all()
                    if x.activa and not x.reportado \
                    and not x.ignorado and not x.limpia])

    @property
    def activo(self):
        return self.urls_activas.count() > 0

    def __str__(self):
        return self.dominio
    
    @property
    def servidor_str(self):
        if self.servidor:
            return self.servidor
        return 'No identificado'

    @property
    def pais_str(self):
        return str(self.pais.name) if self.pais else 'No identificado'

    @property
    def ip_str(self):
        return self.ip if self.ip else 'No identificada'

    @property
    def isp_str(self):
        return self.isp if self.isp else 'No identificado'
    
    @property
    def rir_str(self):
        if self.rir:
            return self.rir.nombre
        return 'No identificado'

    @property
    def correos_mensaje_str(self):
        if self.correos.count() == 0:
            return ''
        s = []
        for x in self.correos.all():
            s.append(x.correo)
        return ', '.join(s)

    @property
    def correos_str(self):
        if self.correos.count() == 0:
            return 'No identificados'
        return self.correos_mensaje_str
    
    @property
    def dns_str(self):
        if self.dns.count() == 0:
            return 'No identificados'
        s = []
        for x in self.dns.all():
            s.append(x.nombre)
        return ', '.join(s)

    @property
    def dns_mensaje_str(self):
        if self.dns.count() == 0:
            return 'No identificados'
        s = []
        for x in self.dns.all():
            s.append(x.nombre.replace('.', '[.]', 1))
        return ', '.join(s)

    @property
    def asn_str(self):
        return str(self.asn) if self.asn else 'No identificado'

class Ticket(models.Model):

    ticket = models.CharField(max_length=25, unique=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return self.ticket

class Url(models.Model):
    
    url = models.URLField(max_length=512)
    dominio = models.ForeignKey(Dominio, on_delete=models.PROTECT, related_name='urls')    
    timestamp_creacion = models.DateTimeField(auto_now_add=True)
    timestamp_actualizacion = models.DateTimeField(auto_now_add=True)
    timestamp_desactivado = models.DateTimeField(null=True)
    codigo = models.IntegerField(default=-1)
    codigo_anterior = models.IntegerField(default=-1)
    ticket = models.ForeignKey(Ticket, on_delete=models.SET_NULL, null=True, related_name='sitios')
    ignorado = models.BooleanField(default=False)
    identificador = models.CharField(max_length=32, unique=True)
    
    @property
    def obten_info_activa(self):
        return self.urlactiva if hasattr(self, 'urlactiva') else None    

    @property
    def obten_info_redireccion(self):
        return self.urlredireccion if hasattr(self, 'urlredireccion') else None    

    @property
    def obten_info(self):
        url = self
        if self.es_redireccion:
            red = self.obten_info_redireccion
            url = red.redireccion_final if red else None
        return url.obten_info_activa if url else None

    @property
    def captura_url(self):
        ua = self.obten_info
        return ua.captura_url if ua and ua.activa else '/media/na.png'

    @property
    def captura_anterior_url(self):
        ua = self.obten_info
        return ua.captura_anterior_url if ua else '/media/na.png' 
    
    @property
    def es_redireccion(self):
        return self.codigo >= 300 and self.codigo < 400

    @property
    def activa(self):
        if self.codigo >= 200 and self.codigo < 300 and not self.timestamp_desactivado:
            return True
        if self.es_redireccion and not self.timestamp_desactivado:
            red = self.obten_info_redireccion
            red_rf = red.redireccion_final if red else None
            return red_rf.codigo >= 200 and red_rf.codigo < 300 and not red_rf.timestamp_desactivado \
                if red_rf else False
        return False

    @property
    def reportado(self):
        return not self.ticket is None

    @property
    def reportado_str(self):
        return 'Sí' if self.reportado else 'No'

    @property
    def ignorado_str(self):
        return 'Sí' if self.ignorado else 'No'

    @property
    def timestamp_reportado(self):
        return self.ticket.timestamp if self.ticket else None

    @property
    def codigo_str(self):
        if self.codigo >= 0:
            return str(self.codigo)
        return 'Sin respuesta'

    @property
    def codigo_anterior_str(self):
        if self.codigo_anterior >= 0:
            return str(self.codigo_anterior)
        return 'Sin respuesta'

    @property
    def estado(self):
        if self.activa:
            return 'Redirección activa' if self.es_redireccion else 'Sitio activo'
        return 'Redirección inactiva' if self.es_redireccion else 'Sitio inactivo'
            
    @property
    def limpia(self):
        ua = self.obten_info
        return ua.deteccion == 'N' if ua else True

    @property
    def entidad_afectada(self):
        ua = self.obten_info
        return ua.entidad_afectada if ua else None

    @property
    def entidad_afectada_str(self):
        entidad = self.entidad_afectada
        return entidad.nombre if entidad else 'No identificada'
    
    @property
    def deteccion_str(self):
        ua = self.obten_info
        return ua.get_deteccion_display() if ua else 'Indefinido'

    def __str__(self):
        return self.url

    class Meta:
        get_latest_by = 'timestamp_creacion'
        
class UrlActiva(Url):

    OPCIONES_DETECCION = (
        ('M', 'Sitio malicioso'),
        ('P', 'Sitio phishing'),
        ('I', 'Indefinido'),
        ('N', 'Sitio no malicioso'),
    )
    entidad_afectada = models.ForeignKey(Entidad, on_delete=models.SET_NULL, null=True)
    timestamp_deteccion = models.DateTimeField(null=True)
    captura = models.ImageField(storage=OverwriteStorage(),
                                upload_to='capturas', blank=True, null=True)
    captura_anterior = models.ImageField(storage=OverwriteStorage(),
                                upload_to='capturas_anteriores', blank=True, null=True)
    deteccion = models.CharField(max_length=1,
                                 choices=OPCIONES_DETECCION,
                                 default='I')
    titulo = models.CharField(max_length=512, null=True) 
    ofuscaciones = models.ManyToManyField(Ofuscacion)
    hash_archivo = models.CharField(max_length=32, null=True)
    archivo = models.FileField(storage=OverwriteStorage(), max_length=512,
                               upload_to='archivos', blank=True, null=True)
    
    @property
    def captura_url(self):
        if self.captura and hasattr(self.captura, 'url'):
            return self.captura.url
        return '/media/na.png'

    @property
    def captura_anterior_url(self):
        if self.captura_anterior and hasattr(self.captura_anterior, 'url'):
            return self.captura_anterior.url
        return '/media/na.png'

    @property
    def entidad_afectada_str(self):
        return self.entidad_afectada if self.entidad_afectada else 'No identificada'

    @property
    def titulo_str(self):
        return self.titulo if self.titulo else ''

    @property
    def archivo_url(self):
        if self.archivo and hasattr(self.archivo, 'url'):
            return self.archivo.url
        return None

    @property
    def hash_archivo_str(self):
        return self.hash_archivo if self.hash_archivo else 'No asignado'

    @property
    def archivo_es_texto(self):
        if self.archivo:
            try:
                magia = magic.Magic(mime=True, uncompress=True)
                mime = magia.from_file(self.archivo.path)
                return mime.startswith('text')
            except Exception as e:
                return False
        return False

    @property
    def filename(self):
        return os.path.basename(self.archivo.name)

    @property
    def ofuscaciones_str(self):
        if self.ofuscaciones.count() == 0:
            return 'No Identificada'
        s = []
        for x in self.ofuscaciones.all():
            s.append(x.nombre)
        return ', '.join(s)
    
class UrlRedireccion(Url):

    redireccion = models.ForeignKey(Url, on_delete=models.SET_NULL, null=True,
                                    related_name='redirecciones')
    redireccion_final = models.ForeignKey(Url, on_delete=models.SET_NULL, null=True,
                                          related_name='redirecciones_final')
    
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

def archivo_adjunto_path(instance, filename):
    fecha = timezone.localtime(timezone.now()).date()
    if instance.malicioso:
        return 'archivos_adjuntos/%s/maliciosos/%s' % (fecha, filename)
    else:
        return 'archivos_adjuntos/%s/indefinidos/%s' % (fecha, filename)

class ArchivoAdjunto(models.Model):

    malicioso = models.BooleanField(default=False)
    timestamp = models.DateTimeField(auto_now_add=True)
    archivo = models.FileField(
        storage=OverwriteStorage(),
        upload_to=archivo_adjunto_path,
        max_length=512,
        unique=True
    )

    @property
    def archivo_url(self):
        if self.archivo and hasattr(self.archivo, 'url'):
            return self.archivo.url
        return None

    @property
    def filename(self):
        return os.path.basename(self.archivo.name)
