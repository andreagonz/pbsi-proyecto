from django.shortcuts import render
from django.urls import reverse_lazy
from django.views.generic import TemplateView,View
from django.template import loader,RequestContext
from django.http import HttpResponse
from django.contrib.postgres.search import SearchQuery, SearchRank, SearchVector
from phishing.models import Url,Correo,Dominio##,Comentario,Hash
from phishing.forms import *
from django.core.exceptions import MultipleObjectsReturned
from django.http import JsonResponse
from django.db.models import Count, Q,F
from django.db.models.functions import Extract
import json
from rest_framework.views import APIView
from rest_framework.response import Response
#from django.contrib.auth import get_user_model
import randomcolor
import datetime
from phishing.phishing import lineas_md5,md5,archivo_hashes
from django.contrib.auth.decorators import login_required
from django.contrib.auth.mixins import LoginRequiredMixin

