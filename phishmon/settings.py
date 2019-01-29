"""
Django settings for phishmon project.

Generated by 'django-admin startproject' using Django 2.0.5.

For more information on this file, see
https://docs.djangoproject.com/en/2.0/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/2.0/ref/settings/
"""

import os
from django.urls import reverse_lazy

# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/2.0/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = '!+v7eriae)k^si!7phn=!x08mch!yxryd50i2=$e=ht93ps69k'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = False

#Servername
ALLOWED_HOSTS = ['pocs.seguridad.unam.mx','127.0.0.1', 'localhost', '192.168.100.35']


# Application definition

INSTALLED_APPS = [
    'phishing',
    'rest_framework',
    'django_countries',
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'phishmon.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [os.path.join(BASE_DIR, 'templates')],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
            'libraries': {
                'filtros': 'templatetags.filtros',
            },
        },
    },
]

WSGI_APPLICATION = 'phishmon.wsgi.application'


# Database
# https://docs.djangoproject.com/en/2.0/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'phishdb',
        'USER': 'phishuser',
        'PASSWORD': 'phishmonpass',
        'HOST': 'localhost',
        'PORT': '5432',
    }
}


# Password validation
# https://docs.djangoproject.com/en/2.0/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


# Internationalization
# https://docs.djangoproject.com/en/2.0/topics/i18n/

LOCALE_NAME = 'es_MX'

LANGUAGE_CODE = 'es-mx'

TIME_ZONE = 'America/Mexico_City'

USE_I18N = True

USE_L10N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/2.0/howto/static-files/

STATIC_ROOT = os.path.join(BASE_DIR, 'static')

STATIC_URL = '/static/'

MEDIA_ROOT = os.path.join(BASE_DIR, 'media')

MEDIA_URL = '/media/'

LOGIN_URL= reverse_lazy('login')

LOGIN_REDIRECT_URL = reverse_lazy('home')


# Variables especiales de la aplicación

USER_AGENT = 'SAAPM'

MAX_REDIRECCIONES = 25

PLANTILLA_CORREO_ASUNTO = os.path.join(MEDIA_ROOT, 'plantillas', 'correo_asunto.txt')

PLANTILLA_CORREO_MENSAJE = os.path.join(MEDIA_ROOT, 'plantillas', 'correo_mensaje.txt')

PLANTILLA_UNAM_MENSAJE = os.path.join(MEDIA_ROOT, 'plantillas', 'unam_mensaje.txt')

PLANTILLA_UNAM_ASUNTO = os.path.join(MEDIA_ROOT, 'plantillas', 'unam_asunto.txt')

CORREO_USR = ''

CORREO_PASS = ''

CORREO_DE = 'phishing@pocs.seguridad.unam.mx'

CORREO_SERVIDOR = '127.0.0.1'

CORREO_PUERTO = 587

CORREO_CCO = 'roberto.sanchez@cert.unam.mx, anduin.tovar@cert.unam.mx'

CORREO_RESPONDER_A = 'anduin.tovar@cert.unam.mx'

CORREO_SSL = False

DIR_CORREOS = '/directorio/de/correos'

DIR_SALIDA = os.path.join(BASE_DIR, 'salida')

DIR_LOG = os.path.join(BASE_DIR, 'log')

VIRUSTOTAL_API_KEY = 'LLAVE_API_VIRUS_TOTAL'

DIR_ENV = '/opt/env'
