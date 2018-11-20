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

class Command(BaseCommand):

    def json_urls(self, urls):
        data = {}
        data['sitios'] = []
        for u in urls:
            i = {
                'url': u.url,
                'codigo': u.codigo_estado,
                'estado': u.estado
            }
            if u.titulo:
                i['titulo'] = u.titulo
            if len(u.ofuscacion.all()) > 0:
                i['metodo_ofuscacion'] = [x.nombre for x in u.ofuscacion.all()]
            if len(u.entidades_afectadas.all()) > 0:
                i['entidades_afectadas'] = []
                for x in u.entidades_afectadas.all():
                    e = {'nombre': x.nombre}
                    if x.clasificacion:
                        e['clasificacion'] = x.clasificacion.nombre
                    i['entidades_afectadas'].append(e)
            if u.redireccion:
                i['redireccion'] = u.redireccion
            if u.dominio:
                d = u.dominio
                if d.ip:
                    i['ip'] = d.ip
                if d.pais:
                    i['pais'] = d.pais.code
                if len(d.correos.all()) > 0:
                    i['correos_abuso'] = [x.correo for x in d.correos.all()]
                if d.servidor:
                    i['servidor'] = d.servidor
                if d.asn:
                    i['as'] = d.asn
                if d.isp:
                    i['isp'] = d.isp
                if len(d.dns.all()) > 0:
                    i['dns_autoritativos'] = [x.nombre for x in d.dns.all()]
                if d.rir:
                    i['rir'] = d.rir.nombre
            data['sitios'].append(i)
        return data
        
    def handle(self, *args, **options):
        hoy = timezone.localtime(timezone.now())
        urls_hoy = Url.objects.filter(timestamp_creacion__gt=hoy - timedelta(days=1))
        d = os.path.join(settings.DIR_SALIDA, str(hoy.date()))
        if not os.path.exists(d):
            os.makedirs(d)
        with open(os.path.join(d, 'ips.txt'), 'a') as ips, \
             open(os.path.join(d, 'urls.txt'), 'a') as urls, \
             open(os.path.join(d, 'redirecciones.txt'), 'a') as red, \
             open(os.path.join(d, 'firewall.txt'), 'a') as fire, \
             open(os.path.join(d, 'snort.txt'), 'a') as snort, \
             open(os.path.join(d, 'formato.txt'), 'a') as form, \
             open(os.path.join(d, 'sitios.json'), 'w') as sitios: 
            for u in urls_hoy:
                urls.write('%s\n' % u.url)
                if u.codigo < 400 and u.codigo >= 300:
                    red.write('%s\n' % u.url)
                asn = '-'
                nom = '-'
                if u.dominio and u.dominio.asn:
                    a = u.dominio.asn
                    i = a.find(' ')
                    if i > 0:
                        asn = a[2:i]
                        nom = a[i + 1:]
                ip = '-'
                if u.dominio and u.dominio.ip:
                    ip = u.dominio.ip
                t = time.strftime('%Y-%m-%d %H:%M:%S')
                form.write('%s | %s | %s | | %s\n' % (asn, ip, t, nom))
            urls_dom = urls_hoy.filter(~Q(dominio=None)).distinct('dominio')
            for u in urls_dom:
                snort.write('Alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS '
                            '(msg:"Regla sitio phishing"; flow:to_server,established; content:'
                            '"%s"; nocase; sid:%d; rev:1;)\n' % (u.dominio.dominio,
                                                                 randint(10000000,20000000)))
                if u.dominio.ip:
                    ips.write('%s\n' % u.dominio.ip)
                    fire.write('iptables -A INPUT -s %s -j DROP\n' % u.dominio.ip)
            json.dump(self.json_urls(urls_hoy), sitios, indent=4)
            
