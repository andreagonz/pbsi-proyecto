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

def log(mensaje):
    t = timezone.localtime(timezone.now())
    l = os.path.join(settings.DIR_LOG, 'correo.log')
    with open(l, 'a') as w:
        w.write('[%s] %s\n' % (t, mensaje))
        
def obten_texto(mensaje, archivo):
    if not os.path.exists(archivo):
        return ''
    with open(archivo) as f:
        if mensaje:
            return f.read()
        else:
            return f.readline()
    
def crea_diccionario(dominio):
    entidades = {}
    for x in dominio.urls_activas:
        for e in x.entidades_afectadas.all():
            entidades[e] = str(e)
    regex = re.compile(r'^htt')
    dicc = {
        'urls': '\n'.join([regex.sub('hxx', str(x)) for x in dominio.urls_activas]).replace('.', '(.)'),
        'ip': dominio.ip,
        'pais': dominio.pais,
        'dominio': dominio.dominio.replace('.', '(.)'),
        'asn': dominio.asn,
        'isp': dominio.isp,
        'rir': dominio.rir,
        'servidor': dominio.servidor_web,
        'dns': dominio.servidores_dns.replace('.', '(.)'),
        'entidades': ', '.join(entidades.values()) if len(entidades) > 0 else 'No identificadas',
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
        log('Error: %s' % str(e))
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
        log('Error: %s' % str(e))
        
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
    mensaje = mensaje.replace('\n', '<br/>').replace(' ', '&nbsp;')
    msg.attach(MIMEText(mensaje, 'html'))
    for x in capturas:
        if x.captura_url:
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
        recipientes = [para]
        if cc[0]:
            recipientes.append(cc)
        if cco[0]:
            recipientes.append(cco)
        server.sendmail(usr, recipientes, msg)
        log('Correo enviado. To:%s, Cc:%s, Bcc:%s' % (', '.join(para if para else []),
                                                      ', '.join(cc if cc else []),
                                                      ', '.join(cco if cco else [])))
    except Exception as e:
        log('Error: %s' % str(e))
        b = False
    finally:
        if server:
            server.quit()
        return b


"""
===========================================
"""
def virustotal(HASH_sha256):    
    vt = VirusTotalPublicApi(settings.VIRUSTOTAL_API_KEY)
    response = vt.get_file_report(HASH_sha256)
    #print(json.dumps(response, sort_keys=False, indent=4))
    resultado = json.loads(json.dumps(response, sort_keys=False, indent=4))
    #print(str(json))
    try:
        if resultado['results']['positives']>0:
            num= resultado['results']['positives']
            return "Si"
            #print(resultado['results']['positives'])
	    ###### Condicion si es mayor a 0 que se guarde en el directorio, si no que no se guarde
        return "No"
    except Exception as e:
        log('Error: %s' % str(e))
        return "No encontro coincidencias"

def erroremail(dicc, palabra, mensaje):
    """
    Imprime los campos de los headers de cada correo
    """
    if mensaje.get(palabra, None):        
        dicc[palabra] = mensaje[palabra]
        return True
    return False

def sha256(fname):
    hash_sha256 = hashlib.sha256()
    hash_sha256.update(fname)
    return hash_sha256.hexdigest()

def mkdir(d):
    if not os.path.exists(d):
        os.makedirs(d)

def analisisarchivos(attachment):
    """
    Esta funcion analiza los archivos contenidos en los correos
    """
    try:
        tipo = attachment.get_content_type()
        payload = attachment.get_payload(decode=True)
        if not payload:
            return "Ninguno", "Ninguno", "Ninguno"
        nombre = sha256(payload)
        noentidades=virustotal(nombre)
        fecha = str(timezone.localtime(timezone.now()).date())
        path = os.path.join(settings.MEDIA_ROOT, 'archivos', fecha)
        mkdir(path)
        if noentidades=='No':
            open(os.path.join(path, nombre), 'wb').write(
                attachment.get_payload(decode=True))
        else:
            if noentidades=='Si':
                mkdir(os.path.join(path, 'maliciosos'))
                open(os.path.join(path, 'maliciosos', nombre), 'wb').write(
                    attachment.get_payload(decode=True))
            else:
                mkdir(os.path.join(path, 'no_clasificado'))
                open(os.path.join(path, 'no_clasificado', nombre), 'wb').write(
                    attachment.get_payload(decode=True))
    except Exception as e:
        log('Error: %s' % str(e))
        return "1", "1", "1"
    return nombre, noentidades,tipo
#resultados.append("Nombre de archivo: " + nombre+"\n")
#resultados.append("\tArchivo malicioso: " +noentidades+"\n")
#resultados.append("Mas informacion: https://www.virustotal.com/#/file/"+nombre)

def parsecorreo(texto):
    """
    Realiza el parseo del archivo email
    """
    resultados = {}
    url = []
    archivos = {}
    mensaje = email.message_from_string(texto)
    h = str(mensaje).split('\n\n')
    headers = h[0] if len(h) > 0 else ''
    if not erroremail(resultados, "To", mensaje):
        return {}, url, headers, {}, True
    else:        
        lista = ['From','To','Cc','Bcc','Subject','X-Virus-Scanned','X-Spam-Flag',
                 'X-Spam-Score','X-Spam-Status','X-Spam-Level','Received']
        for head in lista:
            erroremail(resultados, head, mensaje)
        if mensaje.is_multipart():
            for part in mensaje.walk():
                ctype = part.get_content_type()
                cdispo = str(part.get('Content-Disposition'))
                if ctype == 'text/plain' and 'attachment' not in cdispo:
                    body = part.get_payload(decode=True)
                    url = re.findall('http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+',body.decode('utf-8', errors='ignore'))
                    break
        else:
            body = mensaje.get_payload(decode=True)
            url = re.findall('http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+',body.decode('utf-8', errors='ignore'))
        mensaje = email.message_from_string(texto)
        tamanio = len(mensaje.get_payload())
        if tamanio < 20:
            for x in range(0,tamanio):
                if(x!=0):
                    attachment = mensaje.get_payload()[x]
                    nombre, noentidades, tipo = analisisarchivos(attachment)
                    if noentidades == "1":
                       return {}, url, headers, {}, True
                    else:
                        archivos['tipo'] = tipo
                        archivos['nombre'] = nombre
                        archivos['malicioso'] = noentidades
                        archivos['info'] = "https://www.virustotal.com/#/file/" + nombre
    return resultados, url, headers, archivos, False
