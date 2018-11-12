import os
from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
import phishing.correo as correo
from phishing.phishing import verifica_urls

class Command(BaseCommand):

    def handle(self, *args, **options):
        d = settings.DIR_CORREOS
        p = os.path.join(d, "procesados")
        if not os.path.exists(p):
            os.mkdir(p)
        archivos = [f for f in os.listdir(d) if os.path.isfile(os.path.join(d, f))]
        for x in archivos:
            a = os.path.join(d, x)
            with open(a) as f:
                _, urls = correo.parsecorreo(f.read())
                verifica_urls(list(set(urls)), None, False)
            os.rename(a, os.path.join(p, x))
