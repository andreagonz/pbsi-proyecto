import os
from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone
from phishing.aux import phishing, correo, log
from phishing.models import *

def url_reporta(url, ticket):
    s = url.mas_reciente
    if s:
        s.ticket = ticket
        s.save()
        i = url.sitio_info
        if i and (i.deteccion != 'P' or i.deteccion != 'M'):
            i.deteccion = 'P'
            i.timestamp_deteccion = ticket.timestamp
            i.save()

class Command(BaseCommand):

    def handle(self, *args, **options):
        log.log("Inicia ejecucion de script de notificacion", "notificacion.log")
        d = settings.DIR_CORREOS
        log.log("Directorio base de correos: %s" % d, "notificacion.log")
        p = os.path.join(d, "procesados")
        if not os.path.exists(p):
            os.mkdir(p)
        archivos = [f for f in os.listdir(d) if os.path.isfile(os.path.join(d, f))]
        for archivo in archivos:
            log.log("Leyendo archivo %s" % archivo, "notificacion.log")
            a = os.path.join(d, archivo)
            with open(a) as f:
                headers, urls, _, _, _ = correo.parsecorreo(f.read())
                sitios = phishing.verifica_urls(list(set(urls)), None, False)
                for u in urls:
                    log.log("Verificada URL %s" % u, "notificacion.log")
                if headers.get('Subject', '') == 'Reporte Phishing - TSU':
                    dominios = []
                    for s in sitios:
                        dominios.append(s.dominio)
                    dominios = list(set(dominios))
                    for d in dominios:
                        urls0 = d.urls_monitoreo
                        urls = []
                        sitios = []
                        for u in urls0:
                            i = u.sitio_info
                            if i and (i.deteccion == 'P' or i.deteccion == 'P') and \
                               i.entidad_afectada:
                                sitios.append(i)
                                urls.append(u)
                        if len(urls) == 0:
                            continue
                        sitios = list(set(sitios))
                        hoy = timezone.localtime(timezone.now())
                        cadena_urls = ''.join([x.mas_reciente.identificador
                                               for x in urls if x.mas_reciente])
                        md = phishing.md5((d.dominio + cadena_urls).encode('utf-8', 'backslashreplace'))
                        ticket = ('%d%02d%02d%s' % (hoy.year, hoy.month, hoy.day, md[:7])).upper()
                        de = settings.CORREO_DE
                        para = ['anduin.tovar@cert.unam.mx', 'victor.arteaga@cert.unam.mx']
                        cc = []
                        cco = ['andrea.gonzalez@bec.seguridad.unam.mx'] #settings.CORREO_CCO.split()
                        asunto = correo.obten_asunto(d, ticket)
                        mensaje = correo.obten_mensaje(d, ticket)
                        msg = correo.genera_mensaje(d, de, para, cc, cco, asunto, mensaje, sitios)
                        enviado = correo.manda_correo(para, cc, cco, msg)
                        if not enviado:
                            log.log("Error al reportar dominio %s" % d.dominio, "notificacion.log")
                        else:
                            ts = timezone.localtime(timezone.now())
                            try:
                                ticketO = Ticket.objects.get(ticket=ticket)
                            except:
                                ticketO = Ticket(ticket=ticket, timestamp=ts)
                                ticketO.save()
                            for u in urls:
                                url_reporta(u, ticketO)
                                log.log("URL %s reportada" % u.url, "notificacion.log")
            os.rename(a, os.path.join(p, archivo))
        log.log("Termino ejecucion del script", "notificacion.log")
