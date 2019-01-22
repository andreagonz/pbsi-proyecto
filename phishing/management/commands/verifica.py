from django.core.management.base import BaseCommand, CommandError
from phishing.aux import phishing, log
from django.utils import timezone
from django.conf import settings
import os
from phishing.models import Url

class Command(BaseCommand):
            
    def handle(self, *args, **options):
        log.log('Comieza verificación de URLs', 'monitoreo.log')
        urls = Url.objects.filter(codigo__lt=400, codigo__gte=200)
        sitios = phishing.verifica_urls(urls, None, True)
        for x in sitios:
            log.log("URL '%s' verificada" % str(x), 'monitoreo.log')
        log.log('Termina verificación de URLs', 'monitoreo.log')
