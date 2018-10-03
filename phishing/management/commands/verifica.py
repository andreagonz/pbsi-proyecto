from django.core.management.base import BaseCommand, CommandError
from phishing.phishing import verifica_urls
from phishing.models import Url

class Command(BaseCommand):

    def handle(self, *args, **options):
        urls = [x.url for x in
                Url.objects.filter(reportado=False, codigo__lt=300, codigo__gte=200)]
        verifica_urls(list(set(urls)), None, False)
