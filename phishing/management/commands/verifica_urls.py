import os
from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone
from phishing.aux import log, phishing, entrada
from phishing.views import aux
from phishing.models import Url
import magic

class Command(BaseCommand):

    help = 'Comando para verificar direcciones URL contenidas en un archivo (json, csv, txt)'
    
    def add_arguments(self, parser):
        parser.add_argument('archivo', nargs=1, type=str)
        parser.add_argument(
            '--mostrar-reporte',
            action='store_true',
            dest='reporte'
        )
        
    def handle(self, *args, **options):
        archivo = options['archivo'][0]
        if not os.path.exists(archivo):
            self.stderr.write(self.style.ERROR('El archivo "%s" no existe.' % archivo))
            return            
        if not magic.from_file(archivo, mime=True).startswith('text'):
            self.stderr.write(self.style.ERROR('El archivo "%s" no tiene un formato válido.' % archivo))
            return        
        with open(archivo, 'rb') as f:
            texto = f.read().decode('utf-8', errors='ignore')
        urls = []
        if archivo.endswith('.json'):
            urls = entrada.lee_json(texto)
        elif archivo.endswith('.csv'):
            urls = entrada.lee_csv(texto)
        else:
            urls = entrada.lee_txt(texto)
        urls = [x for x in list(set(urls)) if x]
        sitios = phishing.verifica_urls(urls, "verifica_urls.log")
        if options['verbosity'] > 1:
            for u in sitios:
                self.stdout.write("URL '%s' verificada" % u.url)
        self.stdout.write(self.style.SUCCESS('URLs verificadas exitósamente.'))
        if options['reporte']:
            urls = Url.objects.filter(pk__in=[x.pk for x in sitios]).distinct()
            context = aux.context_reporte(urls)
            self.stdout.write("# Sitios analizados: %d" % context['urls_total'])
            self.stdout.write("# Sitios activos: %d" % context['num_urls_activas'])
            self.stdout.write("# Sitios inactivos: %d" % context['num_urls_inactivas'])
            self.stdout.write("# Redirecciones: %d" % context['num_urls_redirecciones'])
            self.stdout.write("# Dominios afectados: %d\n" % len(context['dominios']))
            self.stdout.write("\nENTIDADES")
            for e in context['entidades']:
                self.stdout.write("	%s: %d" % (e[0], e[1]))
            self.stdout.write("\nTÍTULOS")
            for e in context['titulos']:
                self.stdout.write("	%s: %d" % (e[0], e[1]))
            self.stdout.write("\nDOMINIOS")
            for e in context['dominios']:
                self.stdout.write("	%s: %d" % (e[0], e[1]))
            self.stdout.write("\nPAÍSES")
            for e in context['paises']:
                self.stdout.write("	%s: %d" % (e[0], e[1]))
            for u in urls:
                self.stdout.write("\nURL: %s" % u.url)
                self.stdout.write("IP: %s" % u.dominio.ip_str)
                self.stdout.write("Código: %s" % u.codigo_str)
                self.stdout.write("Estado: %s" % u.estado)
                self.stdout.write("Correos de abuso: %s" % u.dominio.correos_str)
                self.stdout.write("ISP: %s" % u.dominio.isp_str)
                self.stdout.write("País: %s" % u.dominio.pais_str)
                self.stdout.write("ASN: %s" % u.dominio.asn_str)
                self.stdout.write("Servidor web: %s" % u.dominio.servidor_str)
                self.stdout.write("RIR: %s" % u.dominio.rir_str)
                self.stdout.write("Sevidores DNS: %s" % u.dominio.dns_str)
                self.stdout.write("Fecha de creción: %s" % u.timestamp_creacion)
                self.stdout.write("Ignorado: %s" % u.ignorado_str)
                self.stdout.write("Reportado: %s" % u.reportado_str)
                self.stdout.write("Detección: %s" % u.deteccion_str)
                self.stdout.write("Entidad afectada: %s" % u.entidad_afectada_str)
                ua = u.obten_info_activa
                if ua:
                    self.stdout.write("Título: %s" % ua.titulo_str)
                    self.stdout.write("Ofuscación: %s" % ua.ofuscaciones_str)
                    self.stdout.write("Hash MD5 de archivo: %s" % ua.hash_archivo_str)
        self.stdout.flush()
