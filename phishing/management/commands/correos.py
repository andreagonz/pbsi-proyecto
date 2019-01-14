import os
from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
import phishing.correo as correo
from phishing.phishing import verifica_urls
from django.utils import timezone

def log(mensaje):
    t = timezone.localtime(timezone.now())
    l = os.path.join(settings.DIR_LOG, 'correo.log')
    with open(l, 'a') as w:
        w.write('[%s] %s\n' % (t, mensaje))

class Command(BaseCommand):

    def handle(self, *args, **options):
        #Fecha de inicio de la ejecucion del script
        log("Inicia ejecucion de script de correos")
        #Escanea las urls de los correos recibidos
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
                _, urls, _, _, _ = correo.parsecorreo(f.read())
                verifica_urls(list(set(urls)), None, False)
                for u in urls:
                    log("Verificada URL %s" % u)
            os.rename(a, os.path.join(p, x))
        log("Termino ejecucion del script")
