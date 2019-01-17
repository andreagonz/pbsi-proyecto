import os
from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from phishing.phishing import verifica_urls
from django.utils import timezone
from phishing.phishing import md5
from phishing.correo import *
from phishing.models import *

def log(mensaje):
    t = timezone.localtime(timezone.now())
    l = os.path.join(settings.DIR_LOG, 'reporte.log')
    with open(l, 'a') as w:
        w.write('[%s] %s\n' % (t, mensaje))

def url_reporta(url, ts):
    url.reportado = True
    if url.deteccion == 'I':
        url.timestamp_deteccion = ts
        url.deteccion = 'P'
    url.save()

class Command(BaseCommand):

    def handle(self, *args, **options):
        log("Inicia ejecucion de script de reporte")
        d = settings.DIR_CORREOS
        log("Directorio base de correos: %s" % d)
        p = os.path.join(d, "procesados")
        if not os.path.exists(p):
            os.mkdir(p)
        archivos = [f for f in os.listdir(d) if os.path.isfile(os.path.join(d, f))]
        for x in archivos:
            log("Leyendo archivo %s" % x)
            a = os.path.join(d, x)
            with open(a) as f:
                headers, urls, _, _, _ = parsecorreo(f.read())                
                sitios = verifica_urls(list(set(urls)), None, False)
                for u in urls:
                    log("Verificada URL %s" % u)
                if headers.get('Subject', '') == 'Reporte Phishing - TSU':
                    dominios = []
                    for s in sitios:
                        dominios.append(s.dominio)
                    dominios = list(set(dominios))
                    for d in dominios:
                        urls = d.urls_activas
                        if urls.count() == 0:
                            continue
                        hoy = timezone.localtime(timezone.now())
                        md = md5(d.dominio.encode('utf-8', 'backslashreplace'))
                        ticket = ('%d%02d%02d%s' % (hoy.year, hoy.month, hoy.day, md[:7])).upper()
                        de = settings.CORREO_DE
                        para = ['anduin.tovar@cert.unam.mx', 'victor.arteaga@cert.unam.mx']
                        cc = []
                        cco = ['andrea.gonzalez@bec.seguridad.unam.mx']
                        asunto = obten_asunto(d, ticket)
                        mensaje = obten_mensaje(d, ticket)
                        msg = genera_mensaje(d, de, para, cc, cco, asunto, mensaje, urls)
                        enviado = manda_correo(para, cc, cco, msg)
                        if not enviado:
                            log("Error al reportar dominio %s" % d.dominio)
                        try:
                            men = Mensaje.objects.get(ticket=ticket)
                        except:
                            men = Mensaje(ticket=ticket)
                            men.save()
                        men.timestamp = hoy
                        men.save()
                        for x in urls:
                            tsd = x.timestamp_deteccion if x.timestamp_deteccion else hoy
                            mu = MensajeURL(mensaje=men,
                                            timestamp_creacion_sitio=x.timestamp_reactivacion,
                                            url=x,
                                            timestamp_deteccion=tsd)
                            mu.pais = x.dominio.pais
                            mu.asn = x.dominio.asn
                            mu.save()
                            mu.entidades_afectadas.add(*x.entidades_afectadas.all())
                            url_reporta(x, hoy)
                        log("Dominio %s reportado" % d.dominio)
            os.rename(a, os.path.join(p, x))
        log("Termino ejecucion del script")
