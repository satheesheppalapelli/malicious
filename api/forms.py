import requests
from django import forms
import json
import urllib
import traceback
from .models import Ipaddress


class IpForm(forms.ModelForm):
    #ipaddress = forms.GenericIPAddressField()
    class Meta:
        model = Ipaddress
        fields = ('ipaddress',)

    def scan(self):
        # this code for url or ip scan
        response_scan = {}
        try:
            ipaddress = self.cleaned_data['ipaddress']
            url = 'https://www.virustotal.com/vtapi/v2/url/scan'
            params = {'apikey': 'api_key', 'resource': ipaddress}
            response = requests.post(url, data=params)
            response_scan = response.json()
        except Exception as error:
            traceback.print_exc("Exception as Error {}".format(error))
        # just return a JsonResponse
        # return JsonResponse(response_scan, safe=False)
        return response_scan

    # this code is for the gettings reports
    def reports(self):
        response = {}
        ipaddress = self.cleaned_data['ipaddress']
        url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
        parameters = {'apikey': 'api_key', 'ip': ipaddress}
        response = urllib.request.urlopen('%s?%s' % (url, urllib.parse.urlencode(parameters))).read().decode('utf-8')
        # response_scan = json.loads(response)
        response = json.dumps(response)

        # response = requests.post('https://www.virustotal.com/vtapi/v2/url/report', params=params, headers=headers)
        # response_dict = response.json
        # harvest important info from JSON response
        positiveresults = 0
        totalresults = 0
        try:
            for x in response.get("detected_referrer_samples"):
                positiveresults = positiveresults + x.get("positives")
                totalresults = totalresults + x.get("total")
        except Exception as error:
            # if no results found program throws a TypeError
            print("No results {}".format(error))

        # convert results to string for output formatting
        positiveresults = str(positiveresults)
        totalresults = str(totalresults)
        result = positiveresults + '/' + totalresults + ' total AV detection ratio'
        # print results
        # return result
        return result, response