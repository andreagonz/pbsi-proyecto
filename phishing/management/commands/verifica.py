from django.core.management.base import BaseCommand, CommandError
from phishing.phishing import verifica_urls
from phishing.models import Url
from django.utils import timezone
from django.conf import settings
import os

class Command(BaseCommand):

    def log(self, mensaje):
        t = timezone.localtime(timezone.now())
        l = os.path.join(settings.DIR_LOG, 'monitoreo.log')
        with open(l, 'a') as w:
            w.write('[%s] %s\n' % (t, mensaje))
            
    def handle(self, *args, **options):
        self.log('Comieza verificación de URLs')
        urls = [x.url for x in Url.objects.filter(codigo__lt=300, codigo__gte=200)]
        verifica_urls(urls, None, False)
        self.log('URLs verificadas')
