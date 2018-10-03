from django.core.management.base import BaseCommand, CommandError
from phishing.phishing import verifica_urls
from phishing.models import Recurso
import urllib.request
import gzip
import re

class Command(BaseCommand):

    def handle(self, *args, **options):
        recursos = Recurso.objects.filter(es_phishtank=True)
        if len(recursos) > 0:
            phistank = recursos[0]
            url = 'http://data.phishtank.com/data/%s/online-valid.csv.gz' % phistank.recurso
            urls = []
            try:
                with urllib.request.urlopen(url) as gz:
                    with gzip.GzipFile(mode='r', fileobj=gz) as f:
                        x = f.readline()
                        i = phistank.max_urls
                        while i != 0 and x:
                            s = x.decode().strip()
                            online = s.split(',')[-2]
                            if online == 'yes':
                                urls.append(s)
                                i -= 1
                            x = f.readline()
                verifica_urls(urls, None, True)
            except Exception as e:
                self.stdout.write(self.style.ERROR(str(e)))
        recursos = Recurso.objects.filter(es_phishtank=False)
        urls = []
        for r in recursos:
            url = r.recurso
            if not re.match("^https?://.+", url):
                url = 'http://' + url
            try:
                with urllib.request.urlopen(url) as f:
                    i = r.max_urls
                    x = f.readline()
                    while i != 0 and x:
                        s = x.decode().strip()
                        urls.append(s)
                        x = f.readline()
                        i -= 1
            except:
                self.stdout.write(self.style.ERROR(str(e)))
        verifica_urls(list(set(urls)), None, False)
