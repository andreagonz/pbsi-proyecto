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

def obten_texto(mensaje, archivo):
    if not os.path.exists(archivo):
        print(archivo)
        return ''
    with open(archivo) as f:
        if mensaje:
            return f.read()
        else:
            return f.readline()
    
def crea_diccionario(sitio):
    dicc = {
        'id': sitio.identificador,
        'url': sitio.url.replace('.', '(dot)'),
        'timestamp': sitio.timestamp,
        'ip': 'Unknown' if sitio.ip is None else sitio.ip,
        'codigo': 'Unresponsive' if sitio.codigo is None else sitio.codigo,
        'titulo': 'Unknown' if sitio.titulo is None else sitio.titulo,
        'ofuscacion': ', '.join([o.nombre for o in sitio.ofuscacion.all()]),
        'hash': sitio.hash_archivo,
        'pais': sitio.pais,
        'dominio': urlparse(sitio.url).netloc,
        'netname': 'Unknown' if sitio.netname is None else sitio.netname,
        'entidades': 'Unknown' if len(sitio.entidades_afectadas.all()) == 0 \
        else ', '.join([e.nombre.title() for e in sitio.entidades_afectadas.all()]),
    }
    return dicc

def obten_plantilla(mensaje, sitio):
    dicc = crea_diccionario(sitio)
    try:
        plantilla = settings.PLANTILLA_CORREO_ASUNTO
        if mensaje:
            plantilla = settings.PLANTILLA_CORREO_MENSAJE
        s = obten_texto(mensaje, plantilla).format_map(dicc)
        return s
    except Exception as e:
        print(str(e))
        return 'Error en formato de texto'

def obten_mensaje(sitio):
    return obten_plantilla(True, sitio)

def obten_asunto(sitio):
    return obten_plantilla(False, sitio)

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

def cambia_asunto(s):
    modifica_archivo(settings.PLANTILLA_CORREO_ASUNTO, s)

def cambia_mensaje(s):
    modifica_archivo(settings.PLANTILLA_CORREO_MENSAJE, s)
    
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
    except:
        return
        
def genera_mensaje(sitio, fromadd, toadd, asunto, mensaje):
    """
    Se genera el mensaje destinado para la cuenta de abuso
    """
    dicc = crea_diccionario(sitio)
    msg = MIMEMultipart()
    msg['Subject'] = asunto
    msg['From'] = fromadd
    msg['To'] = toadd
    mensaje = mensaje.replace('\n', '<br/>').replace(' ', '&nbsp;')
    msg.attach(MIMEText(mensaje, 'html'))
    adjunta_imagen(msg, sitio)
    return msg.as_string()

def manda_correo(correos, msg):
    """
    Se envia un correo con el mensaje especificado
    """
    try:
        server = smtplib.SMTP(settings.CORREO_SERVIDOR, settings.CORREO_PUERTO)
        server.ehlo()
        if settings.CORREO_TLS:
            server.starttls()
            server.ehlo()
        usr = settings.CORREO_USR
        passw = settings.CORREO_PASS
        if usr and passw:
            server.login(usr, passw)
        emails = [x.strip() for x in correos.split(',')]
        server.sendmail(usr, emails, msg)
    finally:
        server.quit()


"""
===========================================
"""

def erroremail(palabra,mensaje):
    """
    Imprime los campos de los headers de cada correo
    """
    try:
        return (palabra+": "+mensaje[palabra])
    except Exception as e:
        return (palabra+": No hay informacion de "+palabra)

def md5(fname):
    hash_md5 = hashlib.md5()
    hash_md5.update(fname)
    return hash_md5.hexdigest()

def parsecorreo(texto):
    """
    Realiza el parseo del archivo email
    """
    mensaje = email.message_from_string(texto)
    lista = ['From','To','Cc','Bcc','Subject','X-Virus-Scanned','X-Spam-Flag','X-Spam-Score','X-Spam-Status','X-Spam-Level','Received']
    resultados = []
    for head in lista:
        resultados.append(erroremail(head,mensaje))
    b = email.message_from_string(texto)
    if b.is_multipart():
        for part in b.walk():
            ctype = part.get_content_type()
            cdispo = str(part.get('Content-Disposition'))
            if ctype == 'text/plain' and 'attachment' not in cdispo:
                body = part.get_payload(decode=True)  # decode
                url=re.findall('http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\), ]|(?:%[0-9a-fA-F][0-9a-fA-F]))+',body.decode('latin-1'));
                break
    else:
        body=b.get_payload(decode=True)
        url=re.findall('http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\), ]|(?:%[0-9a-fA-F][0-9a-fA-F]))+',body.decode('utf-8'));
        for urls in url:
            resultados.append("URL: "+urls+"\n")
#Obtener archivo adjunto
    msg = email.message_from_string(texto)
    tamanio=len(msg.get_payload())
    #attachment = msg.get_payload()[1]
    if tamanio < 20:
        for x in range(0,tamanio):
           #print (x)
            if(x!=0):
                attachment = msg.get_payload()[x]
                resultados.append("Tipo de archivo: " + attachment.get_content_type()+"\n")
                nombre = md5(attachment.get_payload(decode=True))
                open('%s/archivos/%s'% (settings.MEDIA_ROOT, nombre), 'wb').write(attachment.get_payload(decode=True))
                resultados.append("Nombre de archivo: " + nombre)
    return resultados, url
