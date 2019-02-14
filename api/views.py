from django.shortcuts import render
from .forms import IpForm
from django.http import HttpResponse
import json
import traceback

# Create your views here


def search(request):
    result = {}
    form = IpForm(request.GET or None)
    if request.method == 'GET':
        if form.is_valid():
            virusscan = form.scan()
            virustotal = form.reports()
            return HttpResponse(json.dumps({'VIRUS SCAN': virusscan, 'VIRUS TOTAL': virustotal}), content_type="application/json")
        else:
            form = IpForm()
    return render(request, 'ipaddress.html', {'form': form, 'result': result})