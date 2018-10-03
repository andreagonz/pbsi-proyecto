import re
import email
from email.Utils import parseaddr
from email.Header import decode_header

direccion_re = re.compile('^'+addr_spec+'$')

def lee_txt(archivo):
    with open(archivo) as f:
        return [x.strip() for x in f.readlines()]

def lee_csv(archivo):
    return lee_txt(csv)

def get_cabecera(header, default="ascii"):
    try:
        headers = decode_header(header)
    except email.Errors.HeaderParseError:
        return header.encode('ascii', 'replace').decode('ascii')
    else:
        for i, (text, charset) in enumerate(headers):
            try:
                headers[i] = unicode(text, charset or default, errors='replace')
            except LookupError:
                headers[i] = unicode(text, default, errors='replace')
        return u"".join(headers)
    
def get_direcciones(msg, nombre):
    addrs = email.utils.getaddresses(msg.get_all(nombre, []))
    for i, (nombre, addr) in enumerate(addrs):
        if not nombre and addr:
            nombre = addr            
        try:
            addr = addr.encode('ascii')
        except UnicodeError:
            addr = ''
        else:
            if not direccion_re.match(addr):
                addr = ''
        addrs[i] = (get_cabecera(nombre), addr)
    return addrs

def lee_correo(correo):
    dicc = {}
    msg = email.message_from_string(correo)
    de = get_direcciones(msg, 'from')
    dicc['remitente'] = ('', '') if not de else de[0]
    dicc['destinatarios'] = get_direcciones(msg, 'to')
    dicc['cc'] = get_direcciones(msg, 'cc')
    dicc['asunto'] = get_cabecera(msg.get('Subject', ''))
    dicc['adjuntos'] = msg.get_payload()
    
