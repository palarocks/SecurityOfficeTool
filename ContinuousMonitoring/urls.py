"""ContinuousMonitoring URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/1.10/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  url(r'^$', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  url(r'^$', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.conf.urls import url, include
    2. Add a URL to urlpatterns:  url(r'^blog/', include('blog.urls'))
"""
from django.conf.urls import url
from django.contrib import admin
from SoftwareMonitoring import views

urlpatterns = [
    url(r'^admin/', admin.site.urls),
    url(r'^$', views.principal_view),
    url(r'^soft/', views.sacar_software),
    url(r'^spam/', views.spam),
    url(r'^software/', views.software),
    url(r'^csv/', views.do_csv),
    url(r'^xls/', views.do_xls),
    url(r'^sacar_software/', views.sacar_software),
    url(r'^resultados_spam/', views.resultados_spam),
    url(r'^software_detail/(?P<ip>((2[0-5]|1[0-9]|[0-9])?[0-9]\.){3}((2[0-5]|1[0-9]|[0-9])?[0-9]))/$', views.software_detail),
    url(r'^software_detail/(?P<ip>[\w|\W]+)/$', views.software_detail),
    url(r'^software_host_detail/(?P<soft>[\w|\W]+)/$', views.software_host_detail),
    url(r'^insertar_maquinas/', views.insertar_maquinas),
    url(r'^datatable/', views.datatable),

]
