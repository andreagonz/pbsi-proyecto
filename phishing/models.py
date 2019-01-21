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
    
class Entidad(models.Model):
    
    nombre = models.CharField(max_length=128, unique=True)
    clasificacion = models.ForeignKey(Clasificacion_entidad, on_delete=models.SET_NULL, null=True,
                                      related_name='entidades')
    
    def __str__(self):        
        return self.nombre

    @property
    def clasificacion_str(self):
        return self.clasificacion if self.clasificacion else 'No asignada'
    
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
    nombre = models.CharField(max_length=128, unique=True, null=True)
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
    asn = models.ForeignKey(ASN, on_delete=models.SET_NULL, null=True)
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
        return self.urls.filter(pk__in=[x.pk for x in self.urls.all()
                                        if x.sitio_activo and x.sitios.count() > 0])

    @property
    def urls_monitoreo(self):
        return self.urls.filter(pk__in=[x.pk for x in self.urls_activas
                                        if not x.reportado and not x.ignorado and not x.limpio])

    @property
    def activo(self):
        return self.urls_activas.count() > 0

    @property
    def activo_monitoreo(self):
        return self.urls_monitoreo.count() > 0

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
            return self.rir
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
    
class Url(models.Model):
    
    url = models.URLField(max_length=512, unique=True)
    dominio = models.ForeignKey(Dominio, on_delete=models.PROTECT, related_name='urls')
    timestamp_creacion = models.DateTimeField(auto_now_add=True)
    timestamp_actualizacion = models.DateTimeField(auto_now_add=True)
    codigo = models.IntegerField(default=-1)
    codigo_anterior = models.IntegerField(default=-1)    

    @property
    def tickets(self):
        tickets = []
        for x in self.sitios.select_related('ticket'):            
            if x.ticket:
                tickets.append(x.ticket)
        return tickets
        
    @property
    def es_redireccion(self):
        return self.codigo >= 300 and self.codigo < 400

    @property
    def mas_reciente(self):
        try:
            return self.sitios.latest()
        except:
            return None

    @property
    def redireccion(self):
        if not self.es_redireccion:
            return None
        s = self.mas_reciente
        return s.redireccion if s else None
        
    @property
    def redireccion_final(self):
        if not self.es_redireccion:
            return None
        s = self.mas_reciente
        r = s.redireccion if s else None
        while r:
            s = r.mas_reciente
            r = s.redireccion if s and s.url.es_redireccion else None
        return s.url if s else None

    @property
    def activo(self):
        return self.codigo >= 200 and self.codigo < 300

    @property
    def redireccion_activa(self):
        if not self.es_redireccion:
            return False
        url = self.redireccion_final        
        return False if url is None else url.activo

    @property
    def sitio_activo(self):
        return self.activo or self.redireccion_activa
    
    @property
    def sitio_info(self):
        url = self
        if self.es_redireccion:
            url = self.redireccion_final
        s = url.mas_reciente if url else None
        return s.sitioactivoinfo if s else None

    @property
    def ignorado(self):
        s = self.mas_reciente
        return s.ignorado if s else False

    @property
    def reportado(self):
        s = self.mas_reciente
        return not s.ticket is None if s else False

    @property
    def timestamp_reportado(self):
        s = self.mas_reciente
        return s.ticket.timestamp if s and s.ticket else None
    
    @property
    def captura_url(self):
        i = self.sitio_info
        return i.captura_url if i else '/media/na.png'

    @property
    def captura_anterior_url(self):
        i = self.sitio_info
        return i.captura_anterior_url if i else '/media/na.png'
    
    @property
    def deteccion(self):
        i = self.sitio_info
        return i.get_deteccion_display() if i else 'Indefinido'

    @property
    def archivo_url(self):
        i = self.sitio_info
        return i.archivo_url if i else None

    @property
    def archivo(self):
        i = self.sitio_info
        return i.archivo if i else None

    @property
    def entidad_afectada(self):
        i = self.sitio_info
        return i.entidad_afectada if i else None    

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
        if self.activo:
            return 'Sitio activo'
        elif self.es_redireccion:
            if self.redireccion_activa:
                return 'Redirección activa'
            return 'Redirección inactiva'
        return 'Sitio inactivo'
    
    @property
    def entidad_afectada_str(self):
        e = self.entidad_afectada
        return e if e else 'No identificada'

    @property
    def limpio(self):
        i = self.sitio_info
        return not i is None and i.deteccion == 'N'
    
    def __str__(self):
        return self.url
    
class Ticket(models.Model):

    ticket = models.CharField(max_length=25, unique=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return self.ticket
        
class SitioInfo(models.Model):

    timestamp_creacion = models.DateTimeField(auto_now_add=True)
    timestamp_desactivado = models.DateTimeField(null=True)
    url = models.ForeignKey(Url, on_delete=models.CASCADE, related_name='sitios')
    ticket = models.ForeignKey(Ticket, on_delete=models.SET_NULL, null=True, related_name='sitios')
    ignorado = models.BooleanField(default=False)
    redireccion = models.ForeignKey(Url, on_delete=models.SET_NULL, null=True,
                                    related_name='redirecciones')

    @property
    def captura_url(self):
        i = self.sitioactivoinfo
        if i and i.captura and hasattr(i.captura, 'url'):
            return i.captura.url
        return '/media/na.png'

    @property
    def captura_anterior_url(self):
        i = self.sitioactivoinfo
        if i and i.captura_anterior and hasattr(i.captura_anterior, 'url'):
            return i.captura_anterior.url
        return '/media/na.png'

    @property
    def mas_reciente(self):
        try:
            return self.sitios.latest()
        except:
            return None
        
    @property
    def redireccion_final(self):
        if not self.redireccion:
            return None
        r = self.redireccion
        while r and r.es_redireccion:
            s = r.mas_reciente
            r = s.redireccion if s and s.url.es_redireccion else None
        return r

    class Meta:
        get_latest_by = "timestamp_creacion"
    
class SitioActivoInfo(models.Model):

    OPCIONES_DETECCION = (
        ('M', 'Sitio malicioso'),
        ('P', 'Sitio phishing'),
        ('I', 'Indefinido'),
        ('N', 'Sitio no malicioso'),
    )
    identificador = models.CharField(max_length=32, unique=True)
    entidad_afectada = models.ForeignKey(Entidad, on_delete=models.SET_NULL, null=True)
    timestamp_deteccion = models.DateTimeField(null=True)
    captura = models.ImageField(storage=OverwriteStorage(),
                                upload_to='capturas', blank=True, null=True)
    captura_anterior = models.ImageField(storage=OverwriteStorage(),
                                upload_to='capturas_anteriores', blank=True, null=True)
    sitio = models.OneToOneField(SitioInfo, on_delete=models.CASCADE)
    deteccion = models.CharField(max_length=1,
                                 choices=OPCIONES_DETECCION,
                                 default='I')
    titulo = models.CharField(max_length=512, null=True) 
    ofuscaciones = models.ManyToManyField(Ofuscacion)
    hash_archivo = models.CharField(max_length=32, null=True)
    archivo = models.FileField(storage=OverwriteStorage(),
                               upload_to='archivos', blank=True, null=True)

    @property
    def captura_url(self):
        if self.sitio.url.activo and self.captura and hasattr(self.captura, 'url'):
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
    def ofuscaciones_str(self):
        if self.ofuscaciones.count() == 0:
            return 'No Identificada'
        s = []
        for x in self.ofuscaciones.all():
            s.append(x.nombre)
        return ', '.join(s)
    
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
