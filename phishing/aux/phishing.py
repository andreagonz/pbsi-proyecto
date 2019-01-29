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
    for k, v in entidades.items():
        cuenta = t.count(k)
        if cuenta > 0:
            ent[v] = cuenta
    if len(ent) > 0:
        k, _ = max(ent.items(), key=lambda x: x[1])
        return k
    return None

def archivo_texto(sitio):
    try:
        ua = sitio.obten_info_activa
        if ua and ua.archivo is None:
            return ''
        with gzip.open(ua.archivo.path, "rb") as f:
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
    return comments

def comentarios_sitio(sitio):
    return lee_comentarios_html(archivo_texto(sitio))

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
    rand = ''.join([random.choice("abcde012345") for x in range(5)])
    return md5((url + ts + rand).encode('utf-8', 'backslashreplace'))

def valida_url(url):
    if not re.match("^https?://.+", url):
        url = 'http://%s' % url
    return url

def hacer_peticion(url, lista_info, entidades, ofuscaciones, dominios_inactivos, sesion,
                   max_redir, info_completa, seguir_redirecciones, bitacora, user_agent):
    """
    Se hace una peticion a la url y se obtiene el codigo de respuesta junto con
    el titulo de la pagina
    """
    codigo = -1
    texto = None
    content = None
    titulo = None
    redireccion = None
    try:
        headers = {'User-Agent': user_agent}
        req = sesion.get(url, headers=headers, allow_redirects=False)
        codigo = req.status_code
        if codigo < 400 and codigo >= 300:
            redireccion = urljoin(url, req.headers['location'])
            redireccion = redireccion[:-1] if redireccion.endswith('#') else redireccion
            redireccion = valida_url(redireccion)
            if seguir_redirecciones and redireccion != url and max_redir > 0:
                if not info_completa:
                    urls_orig = Url.objects.filter(url=url)
                    if urls_orig.count() > 0:
                        url_orig = urls_orig.latest()
                        if url_orig.es_redireccion:
                            url_orig_r = url_orig.obten_info_redireccion
                            url_redir = url_orig_r.redireccion
                            if url_redir and url_redir.url != redireccion:
                                info_completa = True
                obten_info_sitio(redireccion, lista_info, entidades, ofuscaciones, dominios_inactivos,
                                 sesion, max_redir - 1, info_completa, True, bitacora, user_agent)
        elif codigo < 300 and codigo >= 200:
            texto = req.text
            tree = html.fromstring(req.text)
            t = tree.xpath("//title")
            titulo = t[0].text.strip().replace('\n', ' ') if len(t) > 0 else None
            content = req.content
    except Exception as e:
        log.log('Error: %s' % str(e), bitacora)
    finally:
        return codigo, texto, content, titulo, redireccion

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

def guarda_captura(url, out, proxy, user_agent, bitacora):
    """
    Se genera la captura de pantalla de la url especificada,
    se guarda el resultado en out
    """
    user_agent = re.sub('[^a-zA-Z0-9/(.;)_ ]', '', user_agent)
    url = urllib.parse.quote_plus(url, safe=';/?:@&=+$,_-')
    if proxy and proxy.startswith('socks5://'):
        process = Popen("proxychains xvfb-run -a --server-args='-screen 0, 1280x1200x24' cutycapt --url='%s' --out='%s' --min-width=800 --min-height=600 --max-wait=25000 --user-agent='%s'" % (url, out, user_agent), shell=True, stdout=PIPE, stderr=PIPE)
    elif proxy:
        o = urlparse(proxy)
        proxy = "%s://%s" % (o.scheme, o.netloc) if o.scheme and o.netloc else ''
        proxy = urllib.parse.quote_plus(proxy, safe='/:')
        process = Popen("xvfb-run -a --server-args='-screen 0, 1280x1200x24' cutycapt --url='%s' --out='%s' --min-width=800 --min-height=600 --max-wait=25000 --http-proxy='%s' --user-agent='%s'" % (url, out, proxy, user_agent), shell=True, stdout=PIPE, stderr=PIPE)
    else:
        process = Popen("xvfb-run -a --server-args='-screen 0, 1280x1200x24' cutycapt --url='%s' --out='%s' --min-width=800 --min-height=600 --max-wait=25000 --user-agent='%s'" % (url, out, user_agent), shell=True, stdout=PIPE, stderr=PIPE)
    stdout, stderr = process.communicate()
    if stderr:
        log.log("Error al tomar captura de url '%s': %s"
              % (url, stderr.decode('utf-8', errors='ignore')), bitacora)
    return not stderr is None

def genera_captura(url, nombre, proxy, user_agent, bitacora):
    captura = os.path.join(settings.MEDIA_ROOT, "capturas", nombre)
    try:
        guarda_captura(url, captura, proxy, user_agent, bitacora)
    except Exception as e:
        log.log("Error al tomar captura de url '%s': %s" % (url, str(e)), bitacora)
    return captura if os.path.exists(captura) else None

def guarda_archivo(content, nombre, bitacora):
    archivo = os.path.join(settings.MEDIA_ROOT, "archivos", nombre)
    try:
        with gzip.open(archivo, 'wb') as w:
            w.write(content)
    except Exception as e:
        log.log("Error al guardar archivo: %s" % str(e), bitacora)
        return None
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
        log.log('Error: %s' % str(e), "phishing.log")
        return False

def escanear_archivo(h):        
    try:
        vt = VirusTotalPublicApi(settings.VIRUSTOTAL_API_KEY)
        response = vt.get_file_report(h)
        resultado = json.loads(json.dumps(response, ))
        return resultado['results']['positives']
    except Exception as e:
        return -1

def obten_sitio_dicc(url):
    return {
        'url': None,
        'entidad': None,
        'captura': None,
        'deteccion': 'I',
        'titulo': None,
        'ofuscaciones': [],
        'hash_archivo': None,
        'archivo': None,
        'codigo': -1,
        'redireccion': None
    }

def deteccion_url(url, hash_archivo, content):
    mime = ''
    deteccion = 'I'
    if hash_archivo and escanear_archivo(hash_archivo) > 0:
        deteccion = 'M'
        mime = magic.from_buffer(content, mime=True)
    if not (deteccion == 'M' and not mime.startswith('text')):
        if es_phishing(url):
            deteccion = 'P'
    return deteccion
            
def obten_info_sitio(url, lista_info, entidades, ofuscaciones, dominios_inactivos, sesion,
                     max_redir, info_completa, seguir_redirecciones, bitacora, user_agent):
    u = urlparse(url)
    dominio_s = u.netloc
    sitio_dicc = obten_sitio_dicc(url)
    sitio_dicc['url'] = url
    if not dominios_inactivos.get(dominio_s, False):
        codigo, texto, content, titulo, redireccion = hacer_peticion(
            url, lista_info, entidades, ofuscaciones, dominios_inactivos,
            sesion, max_redir, info_completa, seguir_redirecciones, bitacora, user_agent
        )
        sitio_dicc['codigo'] = codigo
        sitio_dicc['redireccion'] = redireccion
        if codigo < 0:
            dominios_inactivos[dominio_s] = True
        else:
            sitio_dicc['titulo'] = titulo
            if codigo >= 200 and codigo < 300:
                identificador = genera_id(url)
                arc_nombre = '%s.gz' % identificador
                sitio_dicc['archivo'] = guarda_archivo(content, arc_nombre, bitacora)
                sitio_dicc['hash_archivo'] = md5(content)
                sitio_dicc['titulo'] = titulo
                if info_completa:
                    sitio_dicc['entidad'] = obten_entidad_afectada(entidades, texto)
                    img_proxy = get_proxy(sesion)
                    img_nombre = '%s.jpg' % identificador
                    sitio_dicc['captura'] = genera_captura(url, img_nombre, img_proxy, user_agent, bitacora)
                    sitio_dicc['ofuscaciones'] = encuentra_ofuscacion(ofuscaciones, texto)
                    sitio_dicc['deteccion'] = deteccion_url(url, sitio_dicc['hash_archivo'], content)
    else:
        sitio_dicc['codigo'] = -1
    lista_info.append(sitio_dicc)

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
        
def actualiza_dominio(dominio, scheme, sesion, user_agent, bitacora):
    get_info(dominio, sesion)
    get_dns(dominio)
    if dominio.ip:
        w = whois(dominio.ip)
        get_head(dominio, scheme, w, sesion)
        if len(dominio.correos.all()) == 0:
            correos = correos_whois(w)
            for x in correos:                
                dominio.correos.add(get_correo(x))
    nombre = '%s.jpg' % genera_id(dominio.dominio)
    proxy = get_proxy(sesion)
    captura = genera_captura(dominio.dominio, nombre, proxy, user_agent, bitacora)
    if captura:
        with open(captura, 'rb') as f:
            dominio.captura.save(os.path.basename(captura), File(f), True)
    dominio.save()    

def obten_dominio(dominio, scheme, sesion, bitacora, proxy, user_agent):
    d = None
    try:
        d = Dominio.objects.get(dominio=dominio)
    except:
        log.log("No se encontró dominio '%s' en base de datos" % dominio, bitacora)
    if not d:
        try:
            d = Dominio(dominio=dominio)
            d.save()
            actualiza_dominio(d, scheme, sesion, user_agent, bitacora)
        except Exception as e:
            log.log("Error al crear dominio '%s': %s" % (dominio, str(e)), bitacora)
            return None        
    return d

def crea_url(url, codigo, sesion, bitacora, proxy, user_agent):
    u = urlparse(url)
    dominio_s = u.netloc
    dominio = obten_dominio(dominio_s, u.scheme, sesion, bitacora, proxy, user_agent)
    if not dominio:
        return None
    try:
        identificador = genera_id(url)
        if codigo >= 200 and codigo < 300:
            nuevo = UrlActiva(url=url, dominio=dominio, codigo=codigo, identificador=identificador)
        elif codigo >= 300 and codigo < 400:
            nuevo = UrlRedireccion(url=url, dominio=dominio, codigo=codigo, identificador=identificador)
        else:
            nuevo = Url(url=url, dominio=dominio, codigo=codigo, identificador=identificador)
        nuevo.save()
        return nuevo
    except Exception as e:
        log.log("Error al crear la url '%s': %s" % (url, str(e)), bitacora)
    return None

def obten_url(url):
    sitios = Url.objects.filter(url=url)
    if sitios.count() > 0:
        return sitios.latest()
    return None

def mi_ip(sesion):
    try:
        r = sesion.get('https://api.ipify.org')
        log.log("IP de salida: %s" % r.text, "monitoreo.log")
    except Exception as e:
        log.log("Error al obtener IP de salida: %s" % str(e), "monitoreo.log")

def dicc_entidades():
    entidades = {}
    for x in Entidad.objects.all():
        entidades[x.nombre.lower()] = x
    return entidades

def url_300_a_200(codigo, url_anterior):
    return (url_anterior.codigo >= 300 and url_anterior.codigo < 400) and \
        (codigo >= 200 and codigo < 300)

def url_vivo_a_muerto(codigo, url_anterior):
    if url_anterior.timestamp_desactivado:
        return False
    return (url_anterior.codigo >= 200 and url_anterior.codigo < 400) and \
        (codigo < 200 or codigo >= 400)

def url_200_a_300(codigo, url_anterior):
    return (url_anterior.codigo >= 200 and url_anterior.codigo < 300) and \
        (codigo >= 300 and codigo < 400)

def url_muerto_a_vivo(codigo, url_anterior):
    return (url_anterior.codigo < 200 or url_anterior.codigo >= 400 or \
            url_anterior.timestamp_desactivado) and \
            (codigo >= 200 and codigo < 400)

def url_cambio_redireccion(url, redireccion):
    if not url.es_redireccion:
        return False
    red = url.obten_info_redireccion
    red_r = red.redireccion if red else None
    return red_r and red_r.url != redireccion

def desactiva_redirecciones(url, ts):
    if url.timestamp_desactivado:
        return 
    url.timestamp_desactivado = ts
    url.timestamp_actualizacion = ts
    url.save()
    for u in url.redirecciones.all():
        desactiva_redirecciones(u, ts)
    
def actualiza_redirecciones(url, url_anterior, ts):
    for r in url_anterior.redirecciones.all():
        r.redireccion = url
        r.timestamp_actualizacion = ts
        r.save()
    for r in url_anterior.redirecciones_final.all():
        r.redireccion_final = url
        r.timestamp_actualizacion = ts
        r.save()
            
def detecta_desactivacion_sitio(url, codigo, redireccion, sesion, bitacora, proxy, user_agent):
    url.codigo_anterior = url.codigo
    url.save()
    if url_300_a_200(codigo, url) or url_200_a_300(codigo, url) or \
       url_vivo_a_muerto(codigo, url) or url_cambio_redireccion(url, redireccion):
        if url_vivo_a_muerto(codigo, url):
            url.codigo = codigo
            url.save()
        ts = timezone.localtime(timezone.now())
        desactiva_redirecciones(url, ts)
    if url_300_a_200(codigo, url) or url_200_a_300(codigo, url) or \
       url_muerto_a_vivo(codigo, url) or url_cambio_redireccion(url, redireccion):
        url_anterior = url
        url = crea_url(url.url, codigo, sesion, bitacora, proxy, user_agent)
        if url:
            url.codigo_anterior = url_anterior.codigo
            url.save()
            actualiza_redirecciones(url, url_anterior, timezone.localtime(timezone.now()))
    return url

def actualiza_sitio(url, info, existe, sesion, bitacora, proxy, user_agent):
    codigo = info['codigo']
    if not existe:
        url.codigo_anterior = codigo
        url.codigo = codigo
        if codigo < 200 or codigo >= 400:
            url.timestamp_desactivado = url.timestamp_creacion
        url.save()
    else:
        url.timestamp_actualizacion = timezone.localtime(timezone.now())
        url.save()
        url = detecta_desactivacion_sitio(url, codigo, info['redireccion'], sesion, bitacora, proxy, user_agent)
    if not url:
        return None
    if url.codigo >= 200 and url.codigo < 300:
        ua = url.obten_info_activa
        if ua:
            ua.titulo = info['titulo']
            for o in info['ofuscaciones']:
                ua.ofuscaciones.add(o)            
            ua.hash_archivo = info['hash_archivo']
            if not ua.entidad_afectada:
                ua.entidad_afectada = info['entidad']
            if ua.deteccion == 'I':
                ua.deteccion = info['deteccion']
            if ua.entidad_afectada:
                for dominio in ua.entidad_afectada.lista_blanca_lst:
                    if dominio == url.dominio.dominio:
                        ua.deteccion = 'N'
            if info['captura']:
                if ua.captura and os.path.exists(ua.captura.path):
                    with open(ua.captura.path, 'rb') as f:
                        ua.captura_anterior.save(
                            os.path.basename(ua.captura.path), File(f), True
                        )
                if os.path.exists(info['captura']):
                     with open(info['captura'], 'rb') as f:
                         ua.captura.save(os.path.basename(info['captura']), File(f), True)
            if info['archivo'] and os.path.exists(info['archivo']):
                    with open(info['archivo'], 'rb') as f:
                        ua.archivo.save(os.path.basename(info['archivo']), File(f), True)
            ua.save()
    return url
    
def actualiza_lista_info(url, lista_info, sesion, bitacora, proxy, user_agent):
    urls = []
    lista = lista_info[::-1][1:] if url else lista_info[::-1]
    if url:
        url = actualiza_sitio(url, lista_info[-1], True, sesion, bitacora, proxy, user_agent)
        urls.append(url)
    for info in lista:
        url_o = obten_url(info['url'])
        existe = True
        if not url_o:
            existe = False
            url_o = crea_url(info['url'], info['codigo'], sesion, bitacora, proxy, user_agent)
        if url_o:
            url_o = actualiza_sitio(url_o, info, existe, sesion, bitacora, proxy, user_agent)
        urls.append(url_o)
    for x in range(len(urls)):
        if x < len(urls) - 1 and urls[x]:
            red = urls[x].obten_info_redireccion
            if red:
                red.redireccion = urls[x + 1]
                red.redireccion_final = urls[-1]
                red.save()
    uf = urls[-1] if len(urls) > 0 else None
    if uf and uf.timestamp_desactivado:
        for u in urls[:-1]:
            if u and not u.timestamp_desactivado:
                u.timestamp_desactivado = uf.timestamp_desactivado        
    return [u for u in urls if u]

def verifica_urls(urls, bitacora):
    mkdir(os.path.join(settings.MEDIA_ROOT, 'capturas'))
    mkdir(os.path.join(settings.MEDIA_ROOT, 'archivos'))
    sesion = obten_sesion(None)
    entidades = dicc_entidades()
    ofuscaciones = Ofuscacion.objects.all()
    dominios_inactivos = {}
    sitios = []
    for url in urls:
        url = valida_url(url)
        urls_obj = Url.objects.filter(url=url)
        no_existe = True
        if urls_obj.count() > 0:
            no_existe = False
        lista_info = []
        obten_info_sitio(
            url, lista_info, entidades, ofuscaciones, dominios_inactivos, sesion,
            settings.MAX_REDIRECCIONES, no_existe, True, bitacora, settings.USER_AGENT
        )
        sitios += actualiza_lista_info(None, lista_info, sesion, bitacora, None, settings.USER_AGENT)
    return [x for x in sitios if x]
        
def verifica_urls_cron(urls):
    sesion = obten_sesion(None)
    entidades = dicc_entidades()
    ofuscaciones = Ofuscacion.objects.all()
    dominios_inactivos = {}
    sitios = []
    for url in urls:
        lista_info = []
        obten_info_sitio(
            url.url, lista_info, entidades, ofuscaciones, dominios_inactivos, sesion,
            settings.MAX_REDIRECCIONES, False, False, "monitoreo.log", settings.USER_AGENT
        )
        sitios += actualiza_lista_info(url, lista_info, sesion, "monitoreo.log", None, settings.USER_AGENT)
    return [x for x in sitios if x]
    
def monitoreo(dominio, urls, proxy, user_agent):
    scheme = 'http'
    for u in urls:
        url = urlparse(u.url)
        if url.scheme == 'https':
            scheme = 'https'
    entidades = dicc_entidades()
    sesion = obten_sesion(proxy)
    ofuscaciones = Ofuscacion.objects.all()
    dominios_inactivos = {}
    sitios = []
    if settings.DEBUG:
        mi_ip(sesion)
    actualiza_dominio(dominio, scheme, sesion, user_agent, "monitoreo.log")
    for url in urls:
        lista_info = []
        obten_info_sitio(
            url.url, lista_info, entidades, ofuscaciones, dominios_inactivos, sesion,
            settings.MAX_REDIRECCIONES, True, True, "monitoreo.log", user_agent
        )
        sitios += actualiza_lista_info(url, lista_info, sesion, "monitoreo.log", proxy, user_agent)
    return [x for x in sitios if x]
