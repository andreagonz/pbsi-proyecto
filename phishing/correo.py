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
# from virus_total_apis import PublicApi as VirusTotalPublicApi
import zipfile


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
    """
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
    """
    dicc = {
        'id': "",
        'url': '\n'.join([str(x) for x in sitio.urls_activas]),
        'timestamp': '',
        'ip': 'Unknown',
        'codigo': 'Unresponsive',
        'titulo': 'Unknown',
        'ofuscacion': ', ',
        'hash': '',
        'pais': '',
        'dominio': str(sitio),
        'netname': 'Unknown',
        'entidades': 'Unknown',
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
"""
def virustotal(HASH_sha256):
    API_KEY = 'ea825868bdd93b5a0cea2159c1786ebbedd35a088ab7db4e96b4e2bcd9fafb66'
    vt = VirusTotalPublicApi(API_KEY)
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
    except:
        return "No encontro coincidencias"
"""
def erroremail(palabra,mensaje):
    """
    Imprime los campos de los headers de cada correo
    """
    try:
        return (palabra+": "+mensaje[palabra])
    except Exception as e:
        return (palabra+": No hay informacion de "+palabra)

def sha256(fname):
    hash_sha256 = hashlib.sha256()
    print(fname)
    hash_sha256.update(fname)
    return hash_sha256.hexdigest()

def analisisarchivos(attachment):
    """
    Esta funcion analiza los archivos contenidos en los correos
    """
    tipo= attachment.get_content_type()
    payload = attachment.get_payload(decode=True)
    if not payload:
        return "Ninguno", "Ninguno", "Ninguno"
    nombre = sha256(payload)
    # noentidades=virustotal(nombre)
    noentidades=""
    if noentidades=='No':
        open('%s/archivos/%s'% (settings.MEDIA_ROOT, nombre), 'wb').write(attachment.get_payload(decode=True))
    else:
        if noentidades=='Si':
            open('%s/archivos/maliciosos/%s'% (settings.MEDIA_ROOT, nombre), 'wb').write(attachment.get_payload(decode=True))
        else:
            open('%s/archivos/noclasificado/%s'% (settings.MEDIA_ROOT, nombre), 'wb').write(attachment.get_payload(decode=True))
    return nombre, noentidades,tipo
            #resultados.append("Nombre de archivo: " + nombre+"\n")
            #resultados.append("\tArchivo malicioso: " +noentidades+"\n")
            #resultados.append("Mas informacion: https://www.virustotal.com/#/file/"+nombre)

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
                url=re.findall('http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+',body.decode('utf-8', errors='ignore'));
                break
    else:
        body=b.get_payload(decode=True)
        url=re.findall('http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+',body.decode('utf-8', errors='ignore'));
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
                nombre,noentidades,tipo=analisisarchivos(attachment)
                resultados.append("Tipo de archivo: " +tipo+"\n") #+ attachment.get_content_type()+"\n")
                resultados.append("Nombre de archivo: " + nombre+"\n")
                resultados.append("\tArchivo malicioso: " +noentidades+"\n")
                resultados.append("Mas informacion: https://www.virustotal.com/#/file/"+nombre)
    return resultados, url
