from django.urls import path
from phishing.views import (
    monitoreo, valida_urls, detalle, historico, ajustes, reporte, procesa_correo, detalle
)

urlpatterns = [
    path('monitoreo', monitoreo.monitoreo, name='monitoreo'),
    path('monitoreo/<int:pk>', monitoreo.monitoreo_id, name='monitoreo-id'),
    path('valida-urls', valida_urls.valida_urls, name='valida-urls'),
    path('url/<int:pk>', detalle.url_detalle, name='url-detalle'),
    path('historico', historico.historico, name='historico'),
    path('ajustes', ajustes.ajustes, name='ajustes'),
    path('crea-proxy', ajustes.NuevoProxy.as_view(), name='crea-proxy'),
    path('actualiza-proxy/<int:pk>', ajustes.ActualizaProxy.as_view(), name='actualiza-proxy'),
    path('elimina-proxy/<int:pk>', ajustes.elimina_proxy, name='elimina-proxy'),
    path('ofuscaciones', ajustes.ofuscaciones_view, name='ofuscaciones'),
    path('crea-ofuscacion', ajustes.NuevaOfuscacion.as_view(), name='crea-ofuscacion'),
    path('actualiza-ofuscacion/<int:pk>', ajustes.ActualizaOfuscacion.as_view(), name='actualiza-ofuscacion'),
    path('elimina-ofuscacion/<int:pk>', ajustes.elimina_ofuscacion, name='elimina-ofuscacion'),
    path('entidades', ajustes.entidades_view, name='entidades'),
    path('crea-entidad', ajustes.NuevaEntidad.as_view(), name='crea-entidad'),
    path('actualiza-entidad/<int:pk>', ajustes.ActualizaEntidad.as_view(), name='actualiza-entidad'),
    path('crea-clasificacion', ajustes.NuevaClasificacionEntidad.as_view(), name='crea-clasificacion'),
    path('actualiza-clasificacion/<int:pk>', ajustes.ActualizaClasificacionEntidad.as_view(), name='actualiza-clasificacion'),
    path('elimina-entidad/<int:pk>', ajustes.elimina_entidad, name='elimina-entidad'),
    path('elimina-clasificacion/<int:pk>', ajustes.elimina_clasificacion, name='elimina-clasificacion'),
    path('reporte/', reporte.DocumentView.as_view(), name='reporte'),
    path('doc/', reporte.crear_doc, name='doc'),
    path('procesa-correo/', procesa_correo.procesa_correo, name='procesa-correo'),
    path('ticket/<int:pk>', detalle.TicketView.as_view(), name='ticket'),
    path('asns', ajustes.asn_view, name='asns'),
    path('crea-asn', ajustes.NuevoASN.as_view(), name='crea-asn'),
    path('actualiza-asn/<int:pk>', ajustes.ActualizaASN.as_view(), name='actualiza-asn'),
    path('asn/<int:pk>', detalle.ASNView.as_view(), name='asn'),
    path('dominio/<int:pk>', detalle.DominioView.as_view(), name='dominio'),
]
