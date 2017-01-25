from __future__ import unicode_literals

from django.db import models

# Software instalado en las maquinas
class Software(models.Model):
    name = models.CharField(max_length=100)
    version = models.CharField(max_length=100)
    publisher = models.CharField(max_length=100)

    def __str__(self):
        return self.name

# Maquinas que tenemos en el inventario
class Machine(models.Model):
    ip = models.CharField(max_length=100)
    hostname = models.CharField(max_length=100)
    software_installed = models.ManyToManyField(Software)

    def __str__(self):
        return self.hostname

class Adminlocal(models.Model):
    user = models.CharField(max_length=100)
    passwd = models.CharField(max_length=100)

    def __str__(self):
        return self.user