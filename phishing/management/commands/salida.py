from django.core.management.base import BaseCommand, CommandError
from phishing.models import Url
from django.utils import timezone
from datetime import timedelta
from django.conf import settings
import os
from random import randint
from django.db.models import Q
import json
import time
from phishing.aux import log

class Command(BaseCommand):

    def json_urls(self, urls):
        data = {}
        data['sitios'] = []
        for u in urls:
            i = {
                'url': u.url,
                'codigo': u.codigo_str,
                'estado': u.estado,
                'deteccion': u.deteccion_str
            }
            info = u.obten_info
            if info:
                i['titulo'] = info.titulo_str
                i['metodo_ofuscacion'] = [x.nombre for x in info.ofuscaciones.all()]
                i['entidad_afectada'] = {}
                i['entidad_afectada']['nombre'] = str(info.entidad_afectada_str)
                i['entidad_afectada']['clasificacion'] = info.entidad_afectada.clasificacion.nombre if \
                                                            info.entidad_afectada else 'No identificada'
            if u.es_redireccion:
                red = u.obten_info_redireccion
                if red:
                    i['redireccion'] = red.redireccion.url if red.redireccion else 'No identificada'
                    i['redireccion_final'] = red.redireccion_final.url if red.redireccion_final else 'No identificada'
            d = u.dominio
            i['ip'] = d.ip_str
            i['pais'] = d.pais_str
            i['correos_abuso'] = [c.correo for c in d.correos.all()]
            i['servidor'] = d.servidor_str
            i['as'] = d.asn_str
            i['isp'] = d.isp_str
            i['dns_autoritativos'] = d.dns_str
            i['rir'] = d.rir_str
            data['sitios'].append(i)
        return data
        
    def handle(self, *args, **options):
        log.log('Comienza generación de reportes de salida', "salida.log")
        hoy = timezone.localtime(timezone.now()).date()
        urls_hoy = Url.objects.filter(timestamp_creacion__date=hoy).order_by('url', '-timestamp_creacion').distinct('url')
        urls_pk = []
        for x in urls_hoy:
            i = x.obten_info
            if i and (i.deteccion == 'P' or i.deteccion == 'M'):
                urls_pk.append(x.pk)
        urls = Url.objects.filter(pk__in=urls_pk)
        d = os.path.join(settings.DIR_SALIDA, str(hoy))
        if not os.path.exists(d):
            os.makedirs(d)
        with open(os.path.join(d, 'ips.txt'), 'a') as ips, \
             open(os.path.join(d, 'phishing.txt'), 'a') as phishing, \
             open(os.path.join(d, 'redirecciones.txt'), 'a') as red, \
             open(os.path.join(d, 'maliciosos.txt'), 'a') as mal, \
             open(os.path.join(d, 'firewall.txt'), 'a') as fire, \
             open(os.path.join(d, 'snort.txt'), 'a') as snort, \
             open(os.path.join(d, 'formato.txt'), 'a') as form, \
             open(os.path.join(d, 'sitios.json'), 'w') as sitios:
            for u in urls:
                if u.es_redireccion:
                    red.write('%s\n' % u.url)
                i = u.obten_info
                if i and i.deteccion == 'P':
                    phishing.write('%s\n' % u.url)
                elif i and i.deteccion == 'M':
                    mal.write('%s\n' % u.url)
                asn = '-'
                nom = '-'
                if u.dominio.asn:
                    a = u.dominio.asn
                    asn = a.asn
                    nom = a.nombre
                ip = '-'
                if u.dominio.ip:
                    ip = u.dominio.ip
                t = time.strftime('%Y-%m-%d %H:%M:%S')
                form.write('%s | %s | %s | %d saapm %d %s | %s\n' %
                           (asn, ip, t, u.pk, u.pk, u.url, nom))
            urls_dom = urls.distinct('dominio')
            for u in urls_dom:
                snort.write('Alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS '
                            '(msg:"Regla sitio malicioso"; flow:to_server,established; content:'
                            '"%s"; nocase; sid:%d; rev:1;)\n' % (u.dominio.dominio,
                                                                 randint(10000000,20000000)))
                if u.dominio.ip:
                    ips.write('%s\n' % u.dominio.ip)
                    fire.write('iptables -A INPUT -s %s -j DROP\n' % u.dominio.ip)
            json.dump(self.json_urls(urls), sitios, indent=4)
        log.log('Generados reportes de salida', "salida.log")
