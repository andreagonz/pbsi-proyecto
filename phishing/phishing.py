import os
import sys
import re
import smtplib
import requests
from subprocess import Popen, PIPE
from urllib.parse import urlparse
from requests.exceptions import ConnectionError
from lxml import html
import hashlib
from bs4 import BeautifulSoup, Comment
from django.conf import settings
from .models import Url, Entidades, Correo, Dominio, Ofuscacion
from django.conf import settings
from django.utils import timezone
from django.core.files import File

def error(msg, exit=False):
    """
    Manda un error y de especificarse, se sale del programa
    """
    sys.stderr.write('%s\n' % msg)
    if exit:
        sys.exit(1)

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
    except:
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
    # match += re.findall(r'\*(([^*]|[\r\n]|(\*+([^*/]|[\r\n])))*)\*+',texto)
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
                   max_redir, entidades_afectadas=None):
    """
    Se hace una peticion a la url y se obtiene el codigo de respuesta junto con
    el titulo de la pagina
    """
    codigo = -1
    titulo = None
    texto = ''
    try:
        headers = {'User-Agent': settings.USER_AGENT}
        req = sesion.get(sitio.url, headers=headers, allow_redirects=False)
        codigo = req.status_code
        if codigo < 400 and codigo >= 300:
            redireccion = req.headers['location']
            if redireccion != sitio.url and max_redir > 0:
                verifica_url(sitios, redireccion, entidades, ofuscaciones, dominios_inactivos,
                             sesion, max_redir - 1, entidades_afectadas)
        elif codigo < 300 and codigo >= 200:
            texto = req.text
            tree = html.fromstring(req.text)
            t = tree.xpath("//title")
            titulo = t[0].text if len(t) > 0 else ''
        titulo = '' if titulo is None else titulo.strip().replace('\n', ' ')
    except Exception as e:
        error(str(e))
    finally:
        return codigo, texto, titulo

def nslookup(dominio):
    """
    Se realiza la resolucion de la direccion IP para el dominio
    """
    if re.match("[0-9]{1,3}(.[0-9]{1,3}){3}", dominio):
        return dominio
    process = Popen(['nslookup', dominio], stdout=PIPE, stderr=PIPE)
    stdout, stderr = process.communicate()
    if stderr:
        return ''
    for x in stdout.decode('utf-8').split('\n')[2:]:
        if 'Address' in x:
            return x.split(' ')[1]
    return ''

def get_correo(correo):
    try:
        c = Correo.objects.get(correo=correo)
    except Correo.DoesNotExist:
        c = Correo()
        c.correo = correo
        c.save()
    return c

def procesa_whois(w):
    correos, netname, country = [], None, None
    remail = r"([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)"
    for x in w.splitlines():
        f = re.findall(remail, x)
        if len(f) > 0 and 'abuse' in f[0].lower():
            correos.append(f[0])
        elif netname is None and 'netname' in x.lower():
            netname = x.strip().split(' ')[-1]
        elif country is None and 'country' in x.lower():
            country = x.strip().split(' ')[-1].upper()
        elif 'ORGABUSEEMAIL' in x.upper() and len(f) > 0:
            correos.append(f[0])
    return correos, netname, country

def whois(nombre):
    if nombre is None:
        return ''
    process = Popen(['whois', nombre], stdout=PIPE, stderr=PIPE)
    stdout, stderr = process.communicate()
    return stdout.decode('utf-8')
        
def genera_id(url, ip):
    if ip is None:
        ip = ''
    return md5(('%s%s' % (url, ip)).encode('utf-8'))[::2]

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
    # print(sesion.proxies)
    return sesion

def guarda_captura(url, out, proxy=None):
    """
    Se genera la captura de pantalla de la url especificada,
    se guarda el resultado en out
    """
    if proxy is None:
        process = Popen('xvfb-run --server-args="-screen 0, 1280x1200x24" cutycapt --url="%s" --out="%s"' % (url, out), shell=True, stdout=PIPE, stderr=PIPE)
    else:
        process = Popen('xvfb-run --server-args="-screen 0, 1280x1200x24" cutycapt --url="%s" --out="%s" --http-proxy="%s"' % (url, out, proxy), shell=True, stdout=PIPE, stderr=PIPE)
    stdout, stderr = process.communicate()
    return not stderr is None

def genera_captura(url, nombre, proxy=None):
    captura = os.path.join(settings.MEDIA_ROOT, nombre)
    guarda_captura(url, captura, proxy)
    return captura

def guarda_archivo(texto, nombre):
    archivo = os.path.join(settings.MEDIA_ROOT, nombre)
    with open(archivo, 'w') as w:
        w.write(texto)
    return archivo
    
def get_proxy(sesion):
    proxy = None
    if not getattr(sesion, 'proxies', None) is None:
        proxy = sesion.proxies.get('http', None)
        proxy = sesion.proxies.get('https', None) if proxy is None else proxy
    return proxy

def verifica_url_aux(sitios, sitio, existe, entidades, ofuscaciones,
                     dominios_inactivos, sesion, max_redir, entidades_afectadas, monitoreo=False):
    texto = ''
    dominio = urlparse(sitio.url).netloc
    if dominios_inactivos.get(dominio, None) is None:
        sitio.codigo, texto, titulo = hacer_peticion(sitios, sesion, sitio, entidades, ofuscaciones,
                                             dominios_inactivos, max_redir, entidades_afectadas)
        sitio.titulo = titulo
        if (not existe and (sitio.codigo >= 200 and sitio.codigo < 300)) or monitoreo:
            proxy = get_proxy(sesion)
            nombre = 'capturas/%s.png' % sitio.identificador
            captura = genera_captura(sitio.url, nombre, proxy)
            with open(captura, 'rb') as f:
                sitio.captura.save(os.path.basename(captura), File(f), True)
            nombre = 'archivos/%s.txt' % sitio.identificador
            archivo = guarda_archivo(texto, nombre)
            with open(archivo, 'rb') as f:
                sitio.archivo.save(os.path.basename(archivo), File(f), True)
            sitio.hash_archivo = md5(texto.encode('utf-8'))
            if entidades_afectadas is None:
                for x in obten_entidades_afectadas(entidades, texto):
                    sitio.entidades_afectadas.add(x)
            else:
                for x in entidades_afectadas:
                    e = entidades.get(x.lower(), None)
                    if e is None:
                        e = Entidades(nombre=x)
                        e.save()
                    sitio.entidades_afectadas.add(e)
            for x in encuentra_ofuscacion(ofuscaciones, texto):
                sitio.ofuscacion.add(x)
        elif sitio.codigo < 0:
            dominios_inactivos[dominio] = 1
    else:
        sitio.codigo = -1
    if not existe:
        correos, sitio.netname, sitio.pais = procesa_whois(whois(sitio.ip))
        for x in correos:
            sitio.correos.add(get_correo(x))
    sitio.save()

def obten_dominio(dominio, captura=False, proxy=None):
    try:
        d = Dominio.objects.get(dominio=dominio)
    except:
        d = Dominio(dominio=dominio)
        captura = True
    if captura:
        nombre = 'capturas/%s.png' % genera_id(dominio, None)
        captura = genera_captura(dominio, nombre, proxy)
        with open(captura, 'rb') as f:
            d.captura.save(os.path.basename(captura), File(f), True)
        d.save()
    return d

def obten_sitio(url, proxy=None):
    dominio = urlparse(url).netloc
    ip = nslookup(dominio)
    existe = False
    try:
        sitio = Url.objects.get(url=url, ip=ip)
        sitio.timestamp = timezone.now()
        existe = True
    except:
        sitio = Url(ip=ip, url=url, identificador=genera_id(url, ip))
        sitio.save()
        sitio.dominio = obten_dominio(dominio, proxy=proxy)
        sitio.save()
    finally:
        return sitio, existe

def verifica_url(sitios, url, entidades, ofuscaciones, dominios_inactivos,
                 sesion, max_redir, entidades_afectadas=None):
    if not re.match("^https?://.+", url):
        url = 'http://' + url
    sitio, existe = obten_sitio(url)
    verifica_url_aux(sitios, sitio, existe, entidades, Ofuscacion.objects.all(),
                     dominios_inactivos, sesion, max_redir, entidades_afectadas)
    sitios.append(sitio)

def monitorea_url(sitio, proxy):
    sesion = obten_sesion(proxy)
    dominio = urlparse(sitio.url).netloc
    obten_dominio(dominio, True, get_proxy(sesion))
    entidades = {}
    for x in Entidades.objects.all():
        entidades[x.nombre.lower()] = x
    sitio2, existe = obten_sitio(sitio.url)
    verifica_url_aux([], sitio2, False, entidades, Ofuscacion.objects.all(),
                     {}, sesion, settings.MAX_REDIRECCIONES, None)
    return sitio2

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
    python3 = p.decode('utf-8').strip()
    print(python3)
    process = Popen("crontab -l | egrep -v '%s %s/manage.py %s'  | crontab -"
                    % (python3, settings.BASE_DIR, funcion),
                    shell=True, stdout=PIPE, stderr=PIPE)
    process.communicate()
    process = Popen(
        '(crontab -l ; echo "%d * * * * %s %s/manage.py %s") | sort - | uniq - | crontab -' % (n, python3, settings.BASE_DIR, funcion),
        shell=True, stdout=PIPE, stderr=PIPE)
    process.communicate()
