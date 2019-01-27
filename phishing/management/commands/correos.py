import os
from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone
from phishing.aux import log, phishing, correo

class Command(BaseCommand):

    def handle(self, *args, **options):
        log.log("Inicia ejecucion de script de correos", "correo.log")
        d = settings.DIR_CORREOS
        log.log("Directorio base de correos: %s" % d, "correo.log")
        p = os.path.join(d, "procesados")
        if not os.path.exists(p):
            os.mkdir(p)
        archivos = [f for f in os.listdir(d) if os.path.isfile(os.path.join(d, f))]
        for x in archivos:
            log.log("Leyendo archivo %s" % x, "correo.log")
            a = os.path.join(d, x)
            with open(a) as f:
                _, urls, _, _, error = correo.parsecorreo(f.read(), x, False)
                if error:
                    log.log("Error al leer correo '%s'" % a, "correo.log")
                else:
                    urls = list(set(urls))
                    phishing.verifica_urls(urls, "correo.log")
                    for u in urls:
                        log.log("Verificada URL %s" % u, "correo.log")
            os.rename(a, os.path.join(p, x))
        log.log("Termino ejecucion del script", "correo.log")
