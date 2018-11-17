import os
from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
import phishing.correo as correo
from phishing.phishing import verifica_urls

class Command(BaseCommand):

    def handle(self, *args, **options):
        #Fecha de inicio de la ejecucion del script
        bitacora = open("/opt/pbsi-proyecto/phishing/logs/correo.log","a")
        salida = os.popen('date')
        procesado = salida.read()
        bitacora.write("Inicia ejecucion del script: " + str(procesado))
        #Escanea las urls de los correos recibidos
        d = settings.DIR_CORREOS
        p = os.path.join(d, "procesados")
        if not os.path.exists(p):
            os.mkdir(p)
        archivos = [f for f in os.listdir(d) if os.path.isfile(os.path.join(d, f))]
        try:
            for x in archivos:
                a = os.path.join(d, x)
                with open(a) as f:
                    try:
                        _, urls = correo.parsecorreo(f.read())
                        verifica_urls(list(set(urls)), None, False)
                    except ValueError:
                        print("Error URL")
                    try:
                        bitacora.write("\n" + str(urls))
                    except ValueError:
                        print("No se puede imprimir las urls en el archivo\n")
                os.rename(a, os.path.join(p, x))
                try:
                    bitacora.write("\n" + str(a))
                except ValueError:
                    print("No se puede imprimr las lineas en el archivo\n")

        except ValueError: 
            print("Error en la lectura del correo")
        
        try:
            salida = os.popen('date')
            procesado = salida.read()
            bitacora.write("\nTermina ejecucion del script: " + str(procesado))
            salida.close()
            bitacora.close()
        except ValueError:
            print("No se puede terminar la ejecucion del script\n")
