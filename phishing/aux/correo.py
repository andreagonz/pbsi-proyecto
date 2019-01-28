# -*- coding: utf-8 -*-
import os
import smtplib
from urllib.parse import urlparse
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from email.mime.text import MIMEText
from email.mime.image import MIMEImage
from django.conf import settings
import datetime
import email
import re
import hashlib
import json
from virus_total_apis import PublicApi as VirusTotalPublicApi
import zipfile
from django.utils import timezone
from phishing.aux import log
import gzip
from email.message import EmailMessage
import magic
import humanize
from bs4 import BeautifulSoup
from django.core.files.base import ContentFile
from phishing.models import ArchivoAdjunto
from django.db import IntegrityError

def obten_texto(mensaje, archivo):
    if not os.path.exists(archivo):
        return ''
    with open(archivo) as f:
        if mensaje:
            return f.read()
        else:
            return f.readline()
    
def crea_diccionario(dominio):
    urls = dominio.urls_activas
    es_unam = dominio.dominio.endswith('unam.mx')
    entidades = list(set([x['urlactiva__entidad_afectada__nombre'] for x in urls.exclude(
        urlactiva__entidad_afectada__isnull=True).values(
            'urlactiva__entidad_afectada__nombre'
        )]))
    pais = 'País' if es_unam else 'Country'
    servidor = 'Servidor Web' if es_unam else 'Web Server'
    dns = 'Servidores DNS' if es_unam else 'DNS Servers'
    urlss = 'URLs: \n' if urls.count() > 1 else 'URL: '
    dom = 'Dominio' if es_unam else 'Domain'
    regex = re.compile(r'^htt')
    dicc = {
        'urls': '%s%s\n' % (urlss, '\n'.join([regex.sub('hxx', str(x)).replace('.', '[.]', 1) for x in urls])),
        'ip': ('IP: %s\n' % dominio.ip_str) if dominio.ip else '',
        'pais': ('%s: %s\n' % (pais, dominio.pais.code)) if dominio.pais else '',
        'dominio': '%s: %s\n' % (dom, dominio.dominio.replace('.', '[.]', 1)),
        'asn': ('ASN: %s\n' % dominio.asn_str) if dominio.asn else '',
        'isp': ('ISP: %s\n' % dominio.isp_str) if dominio.isp else '',
        'rir': ('RIR: %s\n' % dominio.rir_str) if dominio.rir else '',
        'servidor': ('%s: %s\n' % (servidor, dominio.servidor_str)) if dominio.servidor else '',
        'dns': ('%s: %s\n' % (dns, dominio.dns_mensaje_str)) if dominio.dns.count() > 0 else '',
        'entidades': ', '.join(entidades) if len(entidades) > 0 else '?'
    }
    return dicc

def obten_plantilla(mensaje, sitio, ticket=''):
    dicc = crea_diccionario(sitio)
    dicc['ticket'] = ticket
    try:
        plantilla = settings.PLANTILLA_CORREO_ASUNTO
        if mensaje:
            plantilla = settings.PLANTILLA_CORREO_MENSAJE
        if (sitio.ip and (sitio.ip.startswith('132.248') or sitio.ip.startswith('132.247'))) \
           or sitio.dominio.endswith('unam.mx'):
            plantilla = settings.PLANTILLA_UNAM_ASUNTO
            if mensaje:
                plantilla = settings.PLANTILLA_UNAM_MENSAJE
        s = obten_texto(mensaje, plantilla).format_map(dicc)
        return s
    except Exception as e:
        log.log('Error: %s' % str(e), "correo.log")
        return 'Error en formato de texto'

def obten_mensaje(sitio, ticket=''):
    return obten_plantilla(True, sitio)

def obten_asunto(sitio, ticket=''):
    return obten_plantilla(False, sitio, ticket=ticket)

def lee_archivo(archivo):
    with open(archivo) as f:
        return f.read()

def modifica_archivo(archivo, s):
    with open(archivo, 'w') as w:
        return w.write(s)
    
def lee_plantilla_asunto():
    return lee_archivo(settings.PLANTILLA_CORREO_ASUNTO)

def lee_plantilla_mensaje():
    return lee_archivo(settings.PLANTILLA_CORREO_MENSAJE)

def lee_plantilla_unam_asunto():
    return lee_archivo(settings.PLANTILLA_UNAM_ASUNTO)

def lee_plantilla_unam_mensaje():
    return lee_archivo(settings.PLANTILLA_UNAM_MENSAJE)

def cambia_asunto(s):
    modifica_archivo(settings.PLANTILLA_CORREO_ASUNTO, s)

def cambia_mensaje(s):
    modifica_archivo(settings.PLANTILLA_CORREO_MENSAJE, s)

def cambia_unam_asunto(s):
    modifica_archivo(settings.PLANTILLA_UNAM_ASUNTO, s)

def cambia_unam_mensaje(s):
    modifica_archivo(settings.PLANTILLA_UNAM_MENSAJE, s)

def adjunta_imagen(msg, sitio):
    """
    Se ajunta un archivo al mensaje msg
    """
    try:
        with sitio.captura.open(mode='rb') as a_file:
            basename = os.path.basename(sitio.captura_url)
            part = MIMEApplication(a_file.read(), Name=basename)
            part['Content-Disposition'] = 'attachment; filename="%s"' % basename
            msg.attach(part)
    except Exception as e:
        log.log('Error: %s' % str(e), "correo.log")
        
def genera_mensaje(sitio, fromadd, toadd, cc, bcc, asunto, mensaje, capturas):
    """
    Se genera el mensaje destinado para la cuenta de abuso
    """
    dicc = crea_diccionario(sitio)
    msg = MIMEMultipart()
    msg['Subject'] = asunto
    msg['From'] = fromadd
    msg['To'] = ', '.join(toadd)
    msg['Cc'] = ', '.join(cc)
    msg['Bcc'] = ', '.join(bcc)
    msg['Reply-To'] = settings.CORREO_RESPONDER_A
    mensaje = mensaje.replace('\n', '<br/>').replace(' ', '&nbsp;')
    msg.attach(MIMEText(mensaje, 'html'))
    for x in capturas:
        if x.captura:
            adjunta_imagen(msg, x)
    return msg.as_string()

def manda_correo(para, cc, cco, msg):
    """
    Se envia un correo con el mensaje especificado
    """
    server = None
    b = True
    try:
        if settings.CORREO_SSL:
            server = smtplib.SMTP_SSL(settings.CORREO_SERVIDOR, settings.CORREO_PUERTO)
        else:
            server = smtplib.SMTP(settings.CORREO_SERVIDOR, settings.CORREO_PUERTO)
            server.starttls()
        usr = settings.CORREO_USR
        passw = settings.CORREO_PASS
        if usr and passw:
            server.login(usr, passw)
        server.sendmail(usr, para + cc + cco, msg)
        log.log('Correo enviado. To:%s, Cc:%s, Bcc:%s' % (', '.join(para if para else []),
                                                      ', '.join(cc if cc else []),
                                                          ', '.join(cco if cco else [])), "correo.log")
    except Exception as e:
        log.log('Error: %s' % str(e), "correo.log")
        b = False
    finally:
        if server:
            server.quit()
        return b

def es_malicioso(HASH_sha256):
    resultado = None
    try:
        vt = VirusTotalPublicApi(settings.VIRUSTOTAL_API_KEY)
        response = vt.get_file_report(HASH_sha256)
        resultado = json.loads(json.dumps(response))
    except Exception as e:
        log.log('Error: %s' % str(e), "correo.log")
        return False
    resultados = resultado.get('results', None) if resultado else None
    return resultados and resultados.get('positives', 0) > 0

def sha256(fname):
    hash_sha256 = hashlib.sha256()
    hash_sha256.update(fname)
    return hash_sha256.hexdigest()

def mkdir(d):
    if not os.path.exists(d):
        os.makedirs(d)

def guarda_payload(nombre, payload, malicioso):
    adjunto = None
    try:
        adjunto = ArchivoAdjunto(malicioso=malicioso)
        z_payload = gzip.compress(payload)
        adjunto.archivo.save(nombre, ContentFile(z_payload))
        adjunto.save()
    except IntegrityError:
        hoy = timezone.localtime(timezone.now())
        adjuntos = ArchivoAdjunto.objects.filter(timestamp__date=hoy.date())
        for archivo in adjuntos:
            if archivo.filename == nombre:
                return archivo
        return None
    except Exception as e:
        log.log("Error al guardar archivo adjunto '%s': %s" % (archivo, str(e)), "correo.log")
        return None
    return adjunto
        
def analisis_archivo(attachment, usuario_autenticado):
    """
    Esta funcion analiza los archivos contenidos en los correos
    """
    datos = {}
    try:
        datos['Tipo'] = attachment.get_content_type()
        payload = attachment.get_payload(decode=True)
        datos['Tamaño'] = humanize.naturalsize(0)
        if payload:
            datos['Tipo'] = magic.from_buffer(payload, mime=True)
            sha256_h = sha256(payload)
            archivo = "%s.gz" % sha256_h
            malicioso = es_malicioso(sha256_h)
            guarda = guarda_payload(archivo, payload, malicioso)
            if guarda and usuario_autenticado:
                datos['Archivo'] = guarda
            datos['Tamaño'] = humanize.naturalsize(len(payload))
            datos['Es malicioso'] = 'Sí' if malicioso else 'No'
            datos['Referencia'] = "https://www.virustotal.com/#/search/%s" % sha256_h
        content_disposition = attachment.get("Content-Disposition", None)
        if content_disposition:
            dispositions = content_disposition.strip().split(";")
            for param in dispositions[1:]:
                param = param.strip()
                k, v = param.split("=")
                k = k.lower()
                if k == "filename":
                    datos['Nombre'] = v
                elif k == "create-date":
                    datos['Fecha de creación'] = v
                elif k == "modification-date":
                    datos['Fecha de modificación'] = v
                elif k == "read-date":
                    datos['Fecha de lectura'] = v
    except Exception as e:
        log.log('Error: %s' % str(e), "correo.log")
        return None
    return datos

def obten_urls(body, html=False):
    textos = [body]
    if html:
        try:
            soup = BeautifulSoup(body, 'html.parser')
            textos = []
            for x in soup.findAll(text=True):
                x = x.strip()
                if x:
                    textos.append(x)            
            for link in soup.find_all('a'):
                textos.append(link.get('href', ''))
        except Exception as e:
            log.log("Error al leer HTML: %s" % str(e), "correo.log")
    regex1 = re.compile(r"hxxp://")
    regex2 = re.compile(r"hxxps://")
    regex3 = re.compile(r" ?[(\[][.][)\]] ?")
    regex4 = re.compile(r" ?[(\[]dot[)\]] ?")
    urls = []
    for t in textos:
        try:
            t = regex1.sub('http://', t)
            t = regex2.sub('https://', t)
            t = regex3.sub('.', t)
            t = regex3.sub('.', t)
            urls += re.findall('http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', t)
        except Exception as e:
            log.log("Error al extraer urls de correo: %s" % str(e), "correo.log")
    return urls

def es_adjunto(parte):
    content_disposition = parte.get("Content-Disposition", None)
    if content_disposition:
        dispositions = content_disposition.strip().split(";")
        if content_disposition and dispositions[0].lower() == "attachment":
            return True
    return False

def analiza_correo(mensaje, archivos, urls, usuario_autenticado):
    for parte in mensaje.walk():
        if es_adjunto(parte):
            analisis = analisis_archivo(parte, usuario_autenticado)
            if analisis:
                archivos.append(analisis)
                tipo = archivos[-1].get('Tipo', '')
                if tipo == 'text/plain' or tipo.startswith('message'):
                    payload = parte.get_payload(decode=True)
                    if payload:
                        payload = payload.decode('utf-8', errors='ignore')
                        parsecorreo_aux(payload, archivos[-1].get('Nombre', '-'),
                                        archivos, urls, usuario_autenticado)
        elif parte.get_content_type().startswith('text'):
            html = parte.get_content_type() == 'text/html'
            urls += obten_urls(parte.get_payload(decode=True).decode('utf-8', errors='ignore'), html)
            
def parsecorreo_aux(texto, nombre, archivos, urls, usuario_autenticado):
    try:
        mensaje = email.message_from_string(texto)
    except Exception as e:
        log.log("Error al leer correo %s: %s" % (nombre, str(e)), "correo.log")
        return None
    analiza_correo(mensaje, archivos, urls, usuario_autenticado)
    return mensaje    

def parsecorreo(texto, nombre, usuario_autenticado):
    urls = []
    archivos = []
    mensaje = parsecorreo_aux(texto, nombre, archivos, urls, usuario_autenticado)
    if not mensaje:
        return {}, urls, '', archivos, True    
    headers = str(mensaje).split('\n\n')
    raw_headers = headers[0] if len(headers) > 0 else ''    
    lista = [
        'From','To','Cc','Bcc','Subject','X-Virus-Scanned','X-Spam-Flag', 'X-Spam-Score',
        'X-Spam-Status','X-Spam-Level','Received', 'authentication-results', 'X-Received',
        'Received-SPF', 'Date', 'Delivered-To', 'In-Reply-To', 'Return-Path', 'Content-Type',
        'received-spf', 'x-originating-ip', 'Return-Path', 'Authentication-Results'
    ]
    cabeceras = {k.title(): mensaje.get(k) for k in lista if mensaje.get(k, None)}
    return cabeceras, list(set(urls)), raw_headers, archivos, False
