from django.db import models

# Create your models here.


class Ipaddress(models.Model):
    ipaddress = models.GenericIPAddressField()

    def __str__(self):
        return self.ipaddress
