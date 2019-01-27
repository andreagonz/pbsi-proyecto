from django.core.management.base import BaseCommand, CommandError
from phishing.aux import phishing, log
from django.utils import timezone
from django.conf import settings
import os
from phishing.models import Url

class Command(BaseCommand):
            
    def handle(self, *args, **options):
        log.log('Comieza verificación de URLs', 'monitoreo.log')
        urls = Url.objects.filter(timestamp_desactivado__isnull=True)
        sitios = phishing.verifica_urls_cron(urls)
        for x in sitios:
            log.log("URL '%s' verificada" % str(x), 'monitoreo.log')
        log.log('Termina verificación de URLs', 'monitoreo.log')
