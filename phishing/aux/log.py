from django.utils import timezone
from django.conf import settings
import os

def log(mensaje, bitacora):
    t = timezone.localtime(timezone.now())
    l = os.path.join(settings.DIR_LOG, bitacora)
    with open(l, 'a') as w:
        w.write('[%s] %s\n' % (t, mensaje))
