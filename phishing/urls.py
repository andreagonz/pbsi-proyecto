from django.urls import path
from .views import (
    monitoreo, valida_urls, busca, monitoreo_id, url_detalle, historico,
    ajustes, ActualizaProxy, NuevoProxy, elimina_proxy,
    ActualizaRecurso, NuevoRecurso, elimina_recurso,
    ofuscaciones_view, entidades_view,
    ActualizaEntidad, NuevaEntidad, elimina_entidad,
    ActualizaOfuscacion, NuevaOfuscacion, elimina_ofuscacion, createDoc, DocumentView,
    entrada
)

urlpatterns = [
    path('monitoreo', monitoreo, name='monitoreo'),
    path('monitoreo/<int:pk>', monitoreo_id, name='monitoreo-id'),
    path('valida-urls', valida_urls, name='valida-urls'),
    path('url/<int:pk>', url_detalle, name='url-detalle'),
    path('historico', historico, name='historico'),
    path('ajustes', ajustes, name='ajustes'),
    path('crea-proxy', NuevoProxy.as_view(), name='crea-proxy'),
    path('actualiza-proxy/<int:pk>', ActualizaProxy.as_view(), name='actualiza-proxy'),
    path('elimina-proxy/<int:pk>', elimina_proxy, name='elimina-proxy'),
    path('crea-recurso', NuevoRecurso.as_view(), name='crea-recurso'),
    path('actualiza-recurso/<int:pk>', ActualizaRecurso.as_view(), name='actualiza-recurso'),
    path('elimina-recurso/<int:pk>', elimina_recurso, name='elimina-recurso'),
    path('ofuscaciones', ofuscaciones_view, name='ofuscaciones'),
    path('crea-ofuscacion', NuevaOfuscacion.as_view(), name='crea-ofuscacion'),
    path('actualiza-ofuscacion/<int:pk>', ActualizaOfuscacion.as_view(), name='actualiza-ofuscacion'),
    path('elimina-ofuscacion/<int:pk>', elimina_ofuscacion, name='elimina-ofuscacion'),
    path('entidades', entidades_view, name='entidades'),
    path('crea-entidad', NuevaEntidad.as_view(), name='crea-entidad'),
    path('actualiza-entidad/<int:pk>', ActualizaEntidad.as_view(), name='actualiza-entidad'),
    path('elimina-entidad/<int:pk>', elimina_entidad, name='elimina-entidad'),
    path('doc/', DocumentView.as_view(), name='doc'),
    path('creaDoc/',createDoc, name='creadoc'),

    path('entrada/', entrada, name='entrada'),
]
