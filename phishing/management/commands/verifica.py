from django.core.management.base import BaseCommand, CommandError
from phishing.aux import phishing, log
from django.utils import timezone
from django.conf import settings
import os

class Command(BaseCommand):
            
    def handle(self, *args, **options):
        log.log('Comieza verificación de URLs', 'monitoreo.log')
        urls = [x.url for x in Url.objects.filter(codigo__lt=400, codigo__gte=200) if x.sitio_activo]
        phishing.verifica_urls(urls, None, True)
        log.log('URLs verificadas', 'monitoreo.log')
