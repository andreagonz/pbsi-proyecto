import os
import sys
import json
import re
import smtplib
import requests
from subprocess import Popen, PIPE
from urllib.parse import urlparse, urljoin
from requests.exceptions import ConnectionError
from lxml import html
import hashlib
from bs4 import BeautifulSoup, Comment
from django.conf import settings
from phishing.models import *
from django.utils import timezone
from django.core.files import File
from virus_total_apis import PublicApi as VirusTotalPublicApi
import magic
from phishing.aux import log
import gzip
import urllib.parse
import random

def md5(x):
    return hashlib.md5(x).hexdigest()

def md5_content(c):
    h = hashlib.md5()
    h.update(c)
    return h.hexdigest()

def lineas_md5(texto):
    hashes = []
    for x in texto.split('\n'):
        if len(x) == 0:
            hashes.append(md5(x.encode('utf-8')))
        else:
            hashes.append(md5(x.encode('utf-8') if x[-1] != '\n' else x[:-1].encode('utf-8')))
    return hashes

def obten_entidad_afectada(entidades, texto):
    if not texto:
        return None
    try:
        texto = bytes(bytearray(texto, encoding='utf-8', errors='ignore'))
        tree = html.fromstring(texto)
    except Exception as e:
        log.log("Error al buscar entidades en texto: %s" % str(e), "phishing.log")
        return None
    texto = []
    for x in tree.xpath("//text()"):
        texto.append(x.lower())
    t = '\n'.join(texto)
    ent = {}
    for x in t.split():
        e = entidades.get(x, None)
        if e:
            ent[e] = 1 if not ent.get(e, None) else ent[e] + 1
    if len(ent) > 0:
        k, _ = max(ent.items(), key=lambda x: x[1])
        return k
    return None

def archivo_texto(sitio):
    try:
        if sitio.archivo is None:
            return ''
        with gzip.open(sitio.archivo.path, "rb") as f:
            return f.read().decode(encoding="utf-8", errors="ignore")
    except Exception as e:
        log.log('Error: %s' % str(e), "phishing.log")
        return ''

def archivo_hashes(sitio):
    return lineas_md5(archivo_texto(sitio))
    
def encuentra_ofuscacion(ofuscaciones, texto):
    of = []
    for x in ofuscaciones:        
        if len(re.findall(x.regex, texto)) > 0:
            of.append(x)
    return of

def lee_comentarios_html(texto):
    soup = BeautifulSoup(texto,'lxml')
    comments = [x.strip() for x in soup.findAll(text=lambda text:isinstance(text, Comment))]
    match = re.findall('(?:^[\s]*//| //)(.+)', texto)
    match += re.findall('/[*](.*\n?.*)[*]/', texto)
    for m in match:
        comments.append(m.strip())
    return comments

def recursos_externos(texto):    
    soup = BeautifulSoup(texto, 'lxml')
    links = soup.findAll("a")
    l = []
    for link in links:
        if not link.get("href", None) is None:
            if urlparse(link['href']).scheme != "" \
               and urlparse(sitio.url).netloc != urlparse(link['href']).netloc:
                l.append(link["href"])
    return '\n'.join(l)

def genera_id(url):
    ts = str(timezone.localtime(timezone.now()))
    return md5((url + ts + random.choice("abcde012345")).encode('utf-8', 'backslashreplace'))

def hacer_peticion(sitios, sesion, sitio, entidades, ofuscaciones,
                   dominios_inactivos, max_redir, existe=False, cron=False, monitoreo=False):
    """
    Se hace una peticion a la url y se obtiene el codigo de respuesta junto con
    el titulo de la pagina
    """
    codigo = -1
    texto = ''
    content = None
    redireccion = None
    try:
        headers = {'User-Agent': settings.USER_AGENT}
        req = sesion.get(sitio.url, headers=headers, allow_redirects=False)
        codigo = req.status_code
        nuevo_sitio = False
        if existe and (sitio.codigo_anterior >= 400 or sitio.codigo_anterior < 200) and \
           (codigo >= 200 or codigo < 400):
            nuevo_sitio = True
        if (not existe and codigo >= 200 and codigo < 400) or nuevo_sitio:
            s = None
            try:
                s = SitioInfo(url=sitio, identificador=genera_id(sitio.url))
                s.save()
            except Exception as e:
                log.log("Error al crear sitio para url %s: %s" % (sitio.url, str(e)), "phishing.log")
            if s and codigo >= 200:
                try:
                    sa = SitioActivoInfo(sitio=s)
                    sa.save()
                except Exception as e:
                    log.log("Error al crear sitio para sitio activo %s: %s" %
                            (sitio.url, str(e)), "phishing.log")
        if codigo < 400 and codigo >= 300:
            redireccion = urljoin(sitio.url, req.headers['location'])
            if (not cron and redireccion != sitio.url and max_redir > 0) or \
               (cron and redireccion != sitio.url and max_redir > 0 and \
                sitio.redireccion and redireccion != sitio.redireccion.url):
                redireccion = redireccion[:-1] if redireccion.endswith('#') else redireccion
                verifica_url(sitios, redireccion, entidades, ofuscaciones, dominios_inactivos,
                             sesion, max_redir - 1, monitoreo=monitoreo)
        elif codigo < 300 and codigo >= 200:
            texto = req.text
            tree = html.fromstring(req.text)
            t = tree.xpath("//title")
            titulo = t[0].text if len(t) > 0 else ''
            content = req.content
            i = sitio.mas_reciente
            a = i.sitioactivoinfo if i else None
            if a:
                a.titulo = None if titulo is None else titulo.strip().replace('\n', ' ')
                a.save()
    except Exception as e:
        log.log('Error: %s' % str(e), "phishing.log")
    finally:
        return codigo, texto, content, existe, redireccion

def get_correo(correo):
    try:
        c = Correo.objects.get(correo=correo)
    except Correo.DoesNotExist:
        c = Correo(correo=correo)
        c.save()
    return c

def mkdir(d):
    if not os.path.exists(d):
        os.makedirs(d)

def obten_sesion(proxy):
    """
    Regresa una sesión para realizar peticiones.
    Recibe:
        tor (bool) - De ser True se crea una sesión para usar TOR
        verboso (bool) - De ser True se utiliza el modo verboso
    Regresa:
        sesión
    """
    if proxy is None:
        return requests
    sesion = requests.session()
    sesion.proxies = proxy
    return sesion

def guarda_captura(url, out, proxy=None):
    """
    Se genera la captura de pantalla de la url especificada,
    se guarda el resultado en out
    """
    url = urllib.parse.quote_plus(url, safe=';/?:@&=+$,_-')
    if proxy and proxy.startswith('socks5://'):
        process = Popen("proxychains xvfb-run -a --server-args='-screen 0, 1280x1200x24' cutycapt --url='%s' --out='%s' --min-width=800 --min-height=600 --max-wait=25000" % (url, out), shell=True, stdout=PIPE, stderr=PIPE)
    elif proxy:
        o = urlparse(proxy)
        proxy = "%s://%s" % (o.scheme, o.netloc) if o.scheme and o.netloc else ''
        proxy = urllib.parse.quote_plus(proxy, safe='/:')
        process = Popen("xvfb-run -a --server-args='-screen 0, 1280x1200x24' cutycapt --url='%s' --out='%s' --min-width=800 --min-height=600 --max-wait=25000 --http-proxy='%s'" % (url, out, proxy), shell=True, stdout=PIPE, stderr=PIPE)
    else:
        process = Popen("xvfb-run -a --server-args='-screen 0, 1280x1200x24' cutycapt --url='%s' --out='%s' --min-width=800 --min-height=600 --max-wait=25000" % (url, out), shell=True, stdout=PIPE, stderr=PIPE)
    stdout, stderr = process.communicate()
    return not stderr is None

def genera_captura(url, nombre, proxy=None):
    captura = os.path.join(settings.MEDIA_ROOT, nombre)
    guarda_captura(url, captura, proxy)
    return captura

def guarda_archivo(content, nombre):
    archivo = os.path.join(settings.MEDIA_ROOT, nombre)
    with gzip.open(archivo, 'wb') as w:
        w.write(content)
    return archivo
    
def get_proxy(sesion):
    proxy = None
    if not getattr(sesion, 'proxies', None) is None:
        proxy = sesion.proxies.get('http', None)
        proxy = sesion.proxies.get('https', None) if proxy is None else proxy
    return proxy

def es_phishing(url):
    params = {'apikey': settings.VIRUSTOTAL_API_KEY, 'resource': url, 'scan': 0}
    headers = {"Accept-Encoding": "gzip, deflate"}
    try:
        r = requests.post('https://www.virustotal.com/vtapi/v2/url/report',
                          params=params, headers=headers)
        if r.status_code != 200:
            return False
        j = r.json()
        if j.get('response_code', 0) != 1:
            return False
        if j.get('positives', 0) > 0:
            return True
        return False
    except Exception as e:
        log_phishing('Error: %s' % str(e))
        return False

def escanear_archivo(h):        
    try:
        vt = VirusTotalPublicApi(settings.VIRUSTOTAL_API_KEY)
        response = vt.get_file_report(h)
        resultado = json.loads(json.dumps(response, ))
        return resultado['results']['positives']
    except Exception as e:
        return -1
    
def desactiva_redirecciones(url, ts):
    s = url.mas_reciente
    if not s or s.timestamp_desactivado:
        return
    s.timestamp_desactivado = ts
    s.save()
    si = SitioInfo.objects.filter(redireccion__pk=url.pk)
    for i in si:
        i.timestamp_desactivado = ts
        i.save()
    for i in si:
        desactiva_redirecciones(i.url, ts)
    
def verifica_url_aux(sitios, url, existe, entidades, ofuscaciones, dominios_inactivos,
                     sesion, max_redir, monitoreo=False, cron=False):
    texto = ''
    dominio = url.dominio.dominio
    url.codigo_anterior = url.codigo
    url.timestamp_actualizacion = timezone.localtime(timezone.now())
    if dominios_inactivos.get(dominio, None) is None:
        url.codigo, texto, content, existe, redireccion = hacer_peticion(
            sitios, sesion, url, entidades, ofuscaciones, dominios_inactivos,
            max_redir, existe, monitoreo=monitoreo
        )
        if url.codigo_anterior >= 200 and url.codigo_anterior < 400 and \
           (url.codigo >= 400 or url.codigo < 200):
            desactiva_redirecciones(url, timezone.localtime(timezone.now()))
        sitio_info = url.mas_reciente
        if not sitio_info:
            url.save()
            log.log("Error al crear sitio para url '%s'" % url.url, "phishing.log")
            return False
        if redireccion:
            try:
                u = Url.objects.get(url=redireccion)                
                sitio_info.redireccion = u
                sitio_info.save()
            except Exception as e:
                log.log("Error al asignar redireccion %s a url %s: %s"
                        % (redireccion, url.url, str(e)), "phishing.log")
        mime = ''
        sitio_activo_info = sitio_info.sitioactivoinfo
        if url.activo and content and sitio_activo_info:
            nombre = 'archivos/%s.gz' % sitio_activo_info.sitio.identificador
            archivo = guarda_archivo(content, nombre)
            if os.path.exists(archivo):
                with open(archivo, 'rb') as f:
                    sitio_activo_info.archivo.save(os.path.basename(archivo), File(f), True)
                sitio_activo_info.hash_archivo = md5_content(content)
                magia = magic.Magic(mime=True, uncompress=True)
                mime = magia.from_file(archivo)
        malicioso = False
        if not existe and url.activo and sitio_activo_info and sitio_activo_info.hash_archivo:
            if escanear_archivo(sitio_activo_info.hash_archivo) > 0:
                sitio_activo_info.deteccion = 'M'
                sitio_activo_info.timestamp_deteccion = timezone.localtime(timezone.now())
                malicioso = True
        if (sitio_activo_info.deteccion == 'I' or malicioso) and url.activo and not \
           (malicioso and not mime.startswith('text')):
            if es_phishing(url.url):
                sitio_activo_info.deteccion = 'P'
                sitio_activo_info.timestamp_deteccion = timezone.localtime(timezone.now())
        if url.activo:
            if not sitio_activo_info.entidad_afectada:
                entidad = obten_entidad_afectada(entidades, texto)
                if entidad:
                    sitio_activo_info.entidad_afectada = entidad
            if sitio_activo_info.ofuscaciones.count() == 0:
                ofuscaciones = encuentra_ofuscacion(ofuscaciones, texto)
                for o in ofuscaciones:
                    sitio_activo_info.ofuscaciones.add(o)
        # if sitio.activo and sitio.deteccion == 'I':
        # heuristica_phishing(sitio)
        if url.codigo < 0:
            dominios_inactivos[dominio] = 1
        if (monitoreo or not existe) and url.activo and sitio_activo_info:
            proxy = get_proxy(sesion)
            nombre = 'capturas/%s.jpg' % sitio_activo_info.sitio.identificador
            if sitio_activo_info.captura and os.path.exists(sitio_activo_info.captura.path):
                with open(sitio_activo_info.captura.path, 'rb') as f:
                    sitio_activo_info.captura_anterior.save(
                        os.path.basename(sitio_activo_info.captura.path), File(f), True
                    )
            captura = genera_captura(url.url, nombre, proxy)
            if os.path.exists(captura):
                with open(captura, 'rb') as f:
                    sitio_activo_info.captura.save(os.path.basename(captura), File(f), True)
        sitio_activo_info.save()
    else:
        url.codigo = -1
        desactiva_redirecciones(url, timezone.localtime(timezone.now()))
    url.save()
    return True

def correos_whois(w):
    correos = []
    remail = r"([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)"
    for x in w.splitlines():
        f = re.findall(remail, x)
        if len(f) > 0 and 'abuse' in f[0].lower():
            correos.append(f[0])
        if 'ORGABUSEEMAIL' in x.upper() and len(f) > 0:
            correos.append(f[0])
    return list(set(correos))

def whois(ip):
    if ip is None:
        return ''
    process = Popen(['whois', ip], stdout=PIPE, stderr=PIPE)
    stdout, stderr = process.communicate()
    return stdout.decode('utf-8', errors='ignore')

def dig_ns(dominio):
    if dominio is None:
        return ''
    process = Popen(['dig', '+short', 'NS', dominio], stdout=PIPE, stderr=PIPE)
    stdout, stderr = process.communicate()
    return stdout.decode('utf-8', errors='ignore')

def get_dns(dominio):
    if len(dominio.dns.all()) > 0:
        return
    dig = dig_ns(dominio.dominio)
    if dig:
        for x in dig.split('\n'):
            x = x.strip()
            if x:
                try:
                    dns = DNS.objects.get(nombre=x)
                except:
                    dns = DNS(nombre=x)
                    dns.save()
                dominio.dns.add(dns)
        dominio.save()
    
def get_head(dominio, schema, w, sesion):
    if not dominio.ip:
        return
    if not dominio.servidor:
        r = sesion.head('%s://%s' % (schema, dominio.dominio))
        dominio.servidor = r.headers.get('Server', None)
    if dominio.rir:
        return
    rir = None
    if w:           
        if 'LACNIC' in w:
            rir = 'Latin American and Caribbean IP address Regional Registry'
        elif 'RIPE' in w:
            rir = 'RIPE Network Coordination Centre'
        elif 'AFRINIC' in w or 'AfriNIC' in w:
            rir = 'African Network Information Centre'
        elif 'APNIC' in w:
            rir = 'Asia-Pacific Network Information Centre'
        elif 'ARIN' in w:
            rir = 'American Registry for Internet Numbers'
        if rir:
            try:
                rirdb = RIR.objects.get(nombre=rir)
            except:
                rirdb = RIR(nombre=rir)
                rirdb.save()
            dominio.rir = rirdb
            dominio.save()

def get_info(dominio, sesion):
    if dominio.pais and dominio.isp and dominio.asn and dominio.ip:
        return
    r = sesion.get("http://ip-api.com/json/%s?fields=status,countryCode,isp,as,query" % dominio.dominio)
    j = json.loads(r.text)
    if j['status'] == 'success':
        dominio.pais = j['countryCode'] if j.get('countryCode', None) else None
        dominio.isp = j['isp'] if j.get('isp', None) else None        
        dominio.ip = j['query'] if j.get('query', None) else None
        if j.get('as', None):
            asn = j['as'].strip().split(" ", 1)
            if len(asn) > 1:
                sn = asn[0][2:]
                nombre = asn[1]
                n = -1
                try:
                    n = int(sn)
                except Exception as e:
                    log.log("Error al leer ASN para dominio '%s': %s" %
                            (dominio.dominio, str(e)), "phishing.log")
                if n > 0:
                    asnO = None
                    try:
                        asnO = ASN.objects.get(asn=n)
                    except:
                        log.log("ASN %d no encontrado en base de datos" % n, "phishing.log")
                    if not asnO:
                        try:
                            asnO = ASN(asn=n, nombre=nombre)
                            asnO.save()
                        except Exception as e:
                            log.log("Error al crear ASN 'AS%d %s': %s" %
                                    (n, nombre, str(e)), "phishing.log")
                            asnO = None
                    if asnO:
                        dominio.asn = asnO
        dominio.save()
        
def actualiza_dominio(dominio, scheme, sesion):
    get_info(dominio, sesion)
    get_dns(dominio)
    if dominio.ip:
        w = whois(dominio.ip)
        get_head(dominio, scheme, w, sesion)
        if len(dominio.correos.all()) == 0:
            correos = correos_whois(w)
            for x in correos:                
                dominio.correos.add(get_correo(x))
    nombre = 'capturas/%s.jpg' % genera_id(dominio.dominio)
    proxy = get_proxy(sesion)
    captura = genera_captura(dominio.dominio, nombre, proxy)
    if os.path.exists(captura):
        with open(captura, 'rb') as f:
            dominio.captura.save(os.path.basename(captura), File(f), True)
    dominio.save()    

def obten_dominio(dominio, scheme, sesion, monitoreo=False, proxy=None):
    d = None
    try:
        d = Dominio.objects.get(dominio=dominio)
    except:
        log.log("No se encontró dominio '%s' en base de datos" % dominio, "phishing.log")
    if not d:
        try:
            d = Dominio(dominio=dominio)
            d.save()
            monitoreo = True
        except Exception as e:
            log.log("Error al crear dominio '%s': %s" % (dominio, str(e)), "phishing.log")
            return None
    if monitoreo:
        actualiza_dominio(d, scheme, sesion)
    return d

def obten_sitio(url, sesion, proxy=None, dominio=None):
    u = urlparse(url)
    dom = u.netloc
    existe = False
    sitio = None
    try:
        sitio = Url.objects.get(url=url)
        existe = True
    except:
        log.log("No se encontró la url '%s' en la base de datos" % url, "phishing.log")
    if not existe:
        d = dominio 
        if not dominio:
            d = obten_dominio(dom, u.scheme, sesion, proxy=proxy, monitoreo=False)
        if d:
            try:
                sitio = Url(url=url, dominio=d)
                sitio.save()            
            except Exception as e:
                log.log("Error al crear sitio para url '%s': %s" % (url, str(e)), "phishing.log")
    return sitio, existe

def verifica_url(sitios, url, entidades, ofuscaciones, dominios_inactivos,
                 sesion, max_redir, monitoreo=False):
    if not re.match("^https?://.+", url):
        url = 'http://' + url
    sitio, existe = obten_sitio(url, sesion)
    if sitio:
        verifica_url_aux(sitios, sitio, existe, entidades, Ofuscacion.objects.all(),
                         dominios_inactivos, sesion, max_redir, monitoreo=monitoreo)
        sitios.append(sitio)

def mi_ip(sesion):
    try:
        r = sesion.get('https://api.ipify.org')
        log.log("IP de salida: %s" % r.text, "ip.log")
        # print("\033[92mIP: %s\033[0m" % r.text)
    except Exception as e:
        log.log("Error al obtener IP de salida: %s" % str(e), "phishing.log")

def monitorea_dominio(dominio, urls, proxy):
    scheme = 'http'
    for u in urls:
        url = urlparse(u.url)
        if url.scheme == 'https':
            scheme = 'https'
    sesion = obten_sesion(proxy)
    if settings.DEBUG:
        mi_ip(sesion)
    actualiza_dominio(dominio, scheme, sesion)
    entidades = {}
    dominios_inactivos = {}
    for x in Entidad.objects.all():
        entidades[x.nombre.lower()] = x    
    for u in urls:
        verifica_url_aux([], u, True, entidades, Ofuscacion.objects.all(),
                         dominios_inactivos, sesion, settings.MAX_REDIRECCIONES, monitoreo=True)
    
def verifica_urls(urls, proxy, cron=False):
    sesion = obten_sesion(proxy)
    if settings.DEBUG:
        mi_ip(sesion)
    mkdir(os.path.join(settings.MEDIA_ROOT, 'capturas'))
    mkdir(os.path.join(settings.MEDIA_ROOT, 'archivos'))
    entidades = {}
    for x in Entidad.objects.all():
        entidades[x.nombre.lower()] = x
    ofuscaciones = Ofuscacion.objects.all()
    dominios_inactivos = {}
    sitios = []
    for url in urls:
        if cron:
            verifica_url_aux(sitios, url, True, entidades, ofuscaciones, dominios_inactivos,
                             sesion, settings.MAX_REDIRECCIONES, cron=True)
        else:
            verifica_url(sitios, url, entidades, ofuscaciones,
                         dominios_inactivos, sesion, settings.MAX_REDIRECCIONES)
    return sitios

def cambia_frecuencia(funcion, n):
    n = 1 if n < 1 or n > 24 else n
    comando = "/bin/bash -c 'source %s/bin/activate && python %s/manage.py %s'" % \
              (settings.DIR_ENV, settings.BASE_DIR, funcion)
    process = Popen('crontab -l | egrep -v "%s"  | crontab -'
                    % (comando), shell=True, stdout=PIPE, stderr=PIPE)
    out, err = process.communicate()
    if err:
        log.log("Error: %s" % err.decode('utf-8', errors='ignore'), "ajustes.log")
    if out:
        log.log(out.decode('utf-8', errors='ignore'), "ajustes.log")
    i = "*/%d" % n if n < 24 else '0'
    process = Popen('(crontab -l ; echo "0 %s * * * %s") | sort - | uniq - | crontab -'
                    % (i, comando), shell=True, stdout=PIPE, stderr=PIPE)
    out, err = process.communicate()
    if err:
        log.log("Error: %s" % err.decode('utf-8', errors='ignore'), "ajustes.log")
    if out:
        log.log(out.decode('utf-8', errors='ignore'), "ajustes.log")
