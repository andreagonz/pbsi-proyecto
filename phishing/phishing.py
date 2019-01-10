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
from .models import Url, Entidades, Correo, Dominio, Ofuscacion, DNS, RIR
from django.utils import timezone
from django.core.files import File
from virus_total_apis import PublicApi as VirusTotalPublicApi

def log_phishing(mensaje):
    t = timezone.localtime(timezone.now())
    l = os.path.join(settings.DIR_LOG, 'phishing.log')
    with open(l, 'a') as w:
        w.write('[%s] %s\n' % (t, mensaje))

def error(msg, exit=False):
    """
    Manda un error y de especificarse, se sale del programa
    """
    sys.stderr.write('%s\n' % msg)
    if exit:
        sys.exit(1)

def md5(x):
    return hashlib.md5(x).hexdigest()

def md5_archivo(fname):
    h = hashlib.md5()
    with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            h.update(chunk)
    return h.hexdigest()

def lineas_md5(texto):
    hashes = []
    for x in texto.split('\n'):
        if len(x) == 0:
            hashes.append(md5(x.encode('utf-8')))
        else:
            hashes.append(md5(x.encode('utf-8') if x[-1] != '\n' else x[:-1].encode('utf-8')))
    return hashes

def obten_entidades_afectadas(entidades, texto):
    if not texto:
        return []
    tree = html.fromstring(texto)
    texto = []
    for x in tree.xpath("//text()"):
        texto.append(x)
    t = '\n'.join(texto)
    ent = []
    for x in t.split():
        e = entidades.get(x.lower(), None)
        if not e is None:
            ent.append(e)
    return ent

def archivo_texto(sitio):
    try:
        if sitio.archivo is None:
            return ''
        with sitio.archivo.open() as f:
            return f.read().decode()
    except Exception as e:
        log_phishing('Error: %s' % str(e))
        return ''

def archivo_hashes(sitio):
    return lineas_md5(archivo_texto(sitio))
    
def encuentra_ofuscacion(ofuscaciones, texto):
    of = []
    for x in ofuscaciones:        
        if len(re.findall(x.regex, texto)) > 0:
            of.append(x)
    return of

def leeComentariosHTML(texto):
    soup = BeautifulSoup(texto,'lxml')
    comments = [x.strip() for x in soup.findAll(text=lambda text:isinstance(text, Comment))]
    match = re.findall('(?:^[\s]*//| //)(.+)', texto)
    match += re.findall('/[*](.*\n?.*)[*]/', texto)
    for m in match:
        comments.append(m.strip())
    return comments

def archivo_comentarios(sitio):
    return leeComentariosHTML(archivo_texto(sitio))

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

def hacer_peticion(sitios, sesion, sitio, entidades, ofuscaciones, dominios_inactivos,
                   max_redir, entidades_afectadas=None, existe=False):
    """
    Se hace una peticion a la url y se obtiene el codigo de respuesta junto con
    el titulo de la pagina
    """
    codigo = -1
    titulo = None
    texto = ''
    content = None
    try:
        headers = {'User-Agent': settings.USER_AGENT}
        req = sesion.get(sitio.url, headers=headers, allow_redirects=False)
        codigo = req.status_code
        if existe and codigo < 400 and sitio.timestamp_desactivado:
            sitio.timestamp_desactivado = None
            sitio.timestamp_reportado = None
            sitio.ignorado = False
            existe = False
            sitio.deteccion = 'I'
        if codigo < 400 and codigo >= 300:
            redireccion = urljoin(sitio.url, req.headers['location'])
            if redireccion != sitio.url and max_redir > 0:
                sitio.redireccion = redireccion[:-1] if redireccion.endswith('#') else redireccion
                verifica_url(sitios, sitio.redireccion, entidades, ofuscaciones, dominios_inactivos,
                             sesion, max_redir - 1, entidades_afectadas)
        elif codigo < 300 and codigo >= 200:
            texto = req.text
            tree = html.fromstring(req.text)
            t = tree.xpath("//title")
            titulo = t[0].text if len(t) > 0 else ''
            content = req.content
        titulo = '' if titulo is None else titulo.strip().replace('\n', ' ')
    except Exception as e:
        log_phishing('Error: %s' % str(e))
    finally:
        return codigo, texto, titulo, content, existe

def get_correo(correo):
    try:
        c = Correo.objects.get(correo=correo)
    except Correo.DoesNotExist:
        c = Correo()
        c.correo = correo
        c.save()
    return c

def genera_id(url):
    return md5(url.encode('utf-8', 'backslashreplace'))[::2]

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
    if proxy is None:
        process = Popen('xvfb-run -a --server-args="-screen 0, 1280x1200x24" cutycapt --url="%s" --out="%s" --min-width=400 --min-height=300 --max-wait=25000' % (url, out), shell=True, stdout=PIPE, stderr=PIPE)
    else:
        process = Popen('xvfb-run -a --server-args="-screen 0, 1280x1200x24" cutycapt --url="%s" --out="%s" --min-width=400 --min-height=300 --max-wait=25000 --http-proxy="%s"' % (url, out, proxy), shell=True, stdout=PIPE, stderr=PIPE)
    stdout, stderr = process.communicate()
    return not stderr is None

def genera_captura(url, nombre, proxy=None):
    captura = os.path.join(settings.MEDIA_ROOT, nombre)
    guarda_captura(url, captura, proxy)
    return captura

def guarda_archivo(content, nombre):
    archivo = os.path.join(settings.MEDIA_ROOT, nombre)
    with open(archivo, 'wb') as w:
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

def deteccion_redirecciones(url, estado, ts):
    if url.deteccion == estado:
        return
    url.deteccion = estado
    url.timestamp_deteccion = ts
    url.save()
    for p in Url.objects.filter(redireccion=url.url):
        deteccion_redirecciones(p, estado, ts)

def desactiva_redirecciones(url, ts):
    if url.timestamp_desactivado:
        return
    url.timestamp_desactivado = ts
    url.save()
    for p in Url.objects.filter(redireccion=url.url):
        desactiva_redirecciones(p, ts)

def verifica_url_aux(sitios, sitio, existe, entidades, ofuscaciones,
                     dominios_inactivos, sesion, max_redir, entidades_afectadas, monitoreo=False):
    texto = ''
    dominio = urlparse(sitio.url).netloc
    sitio.codigo_anterior = sitio.codigo
    sitio.timestamp = timezone.localtime(timezone.now())    
    if dominios_inactivos.get(dominio, None) is None:
        sitio.codigo, texto, sitio.titulo, content, existe = hacer_peticion(sitios, sesion, sitio, entidades, ofuscaciones,
                                                                            dominios_inactivos, max_redir, entidades_afectadas, existe)
        if sitio.codigo_anterior >= 200 and sitio.codigo_anterior < 400 and sitio.codigo >= 400:
            desactiva_redirecciones(sitio, timezone.localtime(timezone.now()))        
        if sitio.activo and content:
            nombre = 'archivos/%s.txt' % sitio.identificador
            archivo = guarda_archivo(content, nombre)
            if os.path.exists(archivo):
                with open(archivo, 'rb') as f:
                    sitio.archivo.save(os.path.basename(archivo), File(f), True)
                sitio.hash_archivo = md5_archivo(archivo)
        if not existe and sitio.activo and sitio.hash_archivo:
            if escanear_archivo(sitio.hash_archivo) > 0:
                deteccion_redirecciones(sitio, 'M', timezone.localtime(timezone.now()))
        if sitio.activo and sitio.deteccion == 'I':
            if es_phishing(sitio.url):
                deteccion_redirecciones(sitio, 'P', timezone.localtime(timezone.now()))
                for x in encuentra_ofuscacion(ofuscaciones, texto):
                    sitio.ofuscacion.add(x)
        if entidades_afectadas is None and sitio.activo and sitio.deteccion != 'M':
            for x in obten_entidades_afectadas(entidades, texto):
                sitio.entidades_afectadas.add(x)
        # if sitio.activo and sitio.deteccion == 'I':
        # heuristica_phishing(sitio)
        if sitio.codigo < 0:
            dominios_inactivos[dominio] = 1
        if (monitoreo or not existe) and sitio.codigo > 0:
            proxy = get_proxy(sesion)
            nombre = 'capturas/%s.png' % sitio.identificador
            if sitio.captura and os.path.exists(sitio.captura.path):
                with open(sitio.captura.path, 'rb') as f:
                    sitio.captura_anterior.save(os.path.basename(sitio.captura.path), File(f), True)
            captura = genera_captura(sitio.url, nombre, proxy)
            if os.path.exists(captura):
                with open(captura, 'rb') as f:
                    sitio.captura.save(os.path.basename(captura), File(f), True)
    else:
        sitio.codigo = -1
    sitio.save()

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
        dominio.pais = j['countryCode'] if j['countryCode'] else None
        dominio.isp = j['isp'] if j['isp'] else None
        dominio.asn = j['as'] if j['as'] else None
        dominio.ip = j['query'] if j['query'] else None
        dominio.save()
        
def obten_dominio(dominio, scheme, sesion, monitoreo=False, proxy=None):
    try:
        d = Dominio.objects.get(dominio=dominio)
    except:
        d = Dominio(dominio=dominio)
        if d:
            d.save()
        else:
            return None
        monitoreo = True
    if monitoreo:
        get_info(d, sesion)
        get_dns(d)
        if d.ip:
            w = whois(d.ip)
            get_head(d, scheme, w, sesion)
            if len(d.correos.all()) == 0:
                correos = correos_whois(w)
                for x in correos:                
                    d.correos.add(get_correo(x))
        nombre = 'capturas/%s.png' % genera_id(dominio)
        captura = genera_captura(dominio, nombre, proxy)
        if os.path.exists(captura):
            with open(captura, 'rb') as f:
                d.captura.save(os.path.basename(captura), File(f), True)
        d.save()
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
        d = dominio
        if not dominio:
            d = obten_dominio(dom, u.scheme, sesion, proxy=proxy, monitoreo=False)
        if d:
            sitio = Url(url=url, identificador=genera_id(url), dominio=d)
    finally:
        if sitio:
            sitio.save()
        return sitio, existe

def verifica_url(sitios, url, entidades, ofuscaciones, dominios_inactivos,
                 sesion, max_redir, entidades_afectadas=None):
    if not re.match("^https?://.+", url):
        url = 'http://' + url
    sitio, existe = obten_sitio(url, sesion)
    if not sitio:
        return
    verifica_url_aux(sitios, sitio, existe, entidades, Ofuscacion.objects.all(),
                     dominios_inactivos, sesion, max_redir, entidades_afectadas)
    sitios.append(sitio)

def monitorea_dominio(dominio, urls, proxy):
    schema = 'http'
    for u in urls:
        url = urlparse(u.url)
        if url.scheme == 'https':
            schema = 'https'
    sesion = obten_sesion(proxy)
    dominio = obten_dominio(dominio, schema, sesion, proxy=proxy, monitoreo=True)
    if not dominio:
        return
    entidades = {}
    for x in Entidades.objects.all():
        entidades[x.nombre.lower()] = x    
    for u in urls:
        sitio, existe = obten_sitio(u.url, sesion, dominio)
        verifica_url_aux([], sitio, False, entidades, Ofuscacion.objects.all(),
                         {}, sesion, settings.MAX_REDIRECCIONES, None)

def verifica_urls(urls, proxy, phistank):
    sesion = obten_sesion(proxy)
    mkdir(os.path.join(settings.MEDIA_ROOT, 'capturas'))
    mkdir(os.path.join(settings.MEDIA_ROOT, 'archivos'))
    entidades = {}
    for x in Entidades.objects.all():
        entidades[x.nombre.lower()] = x
    dominios_inactivos = {}
    sitios = []
    if phistank:
        for sitio in urls:
            campos = sitio.split(',')
            url = campos[1]
            entidad = None if campos[-1] == 'Other' else [campos[-1]]
            verifica_url(sitios, campos[1], entidades, Ofuscacion.objects.all(),
                                       dominios_inactivos, sesion, settings.MAX_REDIRECCIONES,
                                       entidad)
    else:
        for url in urls:
            verifica_url(sitios, url, entidades, Ofuscacion.objects.all(),
                                       dominios_inactivos, sesion, settings.MAX_REDIRECCIONES)
    return sitios

def cambia_frecuencia(funcion, n):
    process = Popen(['which', 'python3'], stdout=PIPE, stderr=PIPE)
    p, s = process.communicate()
    python3 = p.decode('utf-8', errors='ignore').strip()
    process = Popen("crontab -l | egrep -v '%s %s/manage.py %s'  | crontab -"
                    % (python3, settings.BASE_DIR, funcion),
                    shell=True, stdout=PIPE, stderr=PIPE)
    process.communicate()
    process = Popen(
        '(crontab -l ; echo "%d * * * * %s %s/manage.py %s") | sort - | uniq - | crontab -' % (n, python3, settings.BASE_DIR, funcion),
        shell=True, stdout=PIPE, stderr=PIPE)
    process.communicate()
