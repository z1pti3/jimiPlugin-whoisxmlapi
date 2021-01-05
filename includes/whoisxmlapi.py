import requests
import json
import time
from pathlib import Path

class _whoisxmlapi():
    def __init__(self, apiToken, ca=None, requestTimeout=30):
        self.requestTimeout = requestTimeout
        self.apiToken = apiToken
        if ca:
            self.ca = Path(ca)
        else:
            self.ca = None

    def apiCall(self,url,urlArgs=[],methord="GET",data=None,jsonResponse=True):
        urlArgs.append("apiKey={0}".format(self.apiToken))
        kwargs={}
        kwargs["timeout"] = self.requestTimeout
        if self.ca:
            kwargs["verify"] = self.ca
        try:
            url = "{0}/?{1}".format(url,"&".join(urlArgs))
            if methord == "GET":
                response = requests.get(url, **kwargs)
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError):
            return 0, "Connection Timeout"
        if not jsonResponse:
            return response.text, response.status_code
        if response.status_code == 200 or response.status_code == 202:
            return json.loads(response.text), response.status_code
        return None, response.status_code

    def whois(self,domainName,thinWhois=1,ignoreRawTexts=1):
        url = "https://www.whoisxmlapi.com/whoisserver/WhoisService"
        response, statusCode = self.apiCall(url,["outputFormat=JSON","domainName={0}".format(domainName),"thinWhois={0}".format(thinWhois),"ignoreRawTexts={0}".format(thinWhois)])
        return response

    def whoisHistory(self,domainName):
        url = "https://whois-history.whoisxmlapi.com/api/v1"
        response, statusCode = self.apiCall(url,["outputFormat=JSON","domainName={0}".format(domainName),"mode=purchase"])
        return response

    def subdomains(self,domainName):
        url = "https://subdomains.whoisxmlapi.com/api/v1"
        response, statusCode = self.apiCall(url,["outputFormat=JSON","domainName={0}".format(domainName)])
        return response

    def reverseIPLookup(self,ip):
        url = "https://reverse-ip.whoisxmlapi.com/api/v1"
        response, statusCode = self.apiCall(url,["outputFormat=JSON","ip={0}".format(ip)])
        return response

    def reverseMXLookup(self,mailServerFQDN):
        url = "https://reverse-mx.whoisxmlapi.com/api/v1"
        response, statusCode = self.apiCall(url,["outputFormat=JSON","mx={0}".format(mailServerFQDN)])
        return response

    def websiteScreenshot(self,url):
        url = "https://website-screenshot.whoisxmlapi.com/api/v1"
        response, statusCode = self.apiCall(url,["outputFormat=JSON","url={0}".format(url),"imageOutputFormat=base64"],jsonResponse=False)
        return response

    def verifyEmail(self,email):
        url = "https://emailverification.whoisxmlapi.com/api/v1"
        response, statusCode = self.apiCall(url,["outputFormat=JSON","emailAddress={0}".format(email)])
        return response

    def ipGeolocation(self,ip):
        url = "https://ip-geolocation.whoisxmlapi.com/api/v1"
        response, statusCode = self.apiCall(url,["outputFormat=JSON","ipAddress={0}".format(ip)])
        return response
    
    def dnsLookup(self,domainName,lookupType="A"):
        url = "https://www.whoisxmlapi.com/whoisserver/DNSService"
        response, statusCode = self.apiCall(url,["outputFormat=JSON","domainName={0}".format(domainName),"type={0}".format(lookupType)])
        return response

    def netblock(self,ip=None,mask=None,asn=None):
        url = "https://ip-netblocks.whoisxmlapi.com/api/v2"
        urlArgs = []
        if ip:
            urlArgs.append("ip={0}".format(ip))
        elif asn:
            urlArgs.append("asn={0}".format(asn))
        if ip and mask:
            urlArgs.append("mask={0}".format(ip))
        urlArgs.append("outputFormat=JSON")
        response, statusCode = self.apiCall(url,urlArgs)
        return response

    def domainReputation(self,domainName):
        url = "https://domain-reputation.whoisxmlapi.com/api/v1"
        response, statusCode = self.apiCall(url,["outputFormat=JSON","domainName={0}".format(domainName)])
        return response

    def domainCategorization(self,domainName):
        url = "https://website-categorization.whoisxmlapi.com/api/v1"
        response, statusCode = self.apiCall(url,["outputFormat=JSON","domainName={0}".format(domainName)])
        return response

    def websiteContacts(self,domainName):
        url = "https://website-contacts.whoisxmlapi.com/api/v1"
        response, statusCode = self.apiCall(url,["outputFormat=JSON","domainName={0}".format(domainName)])
        return response

    def domainAvailabilityCheck(self,domainName):
        url = "https://domain-availability.whoisxmlapi.com/api/v1"
        response, statusCode = self.apiCall(url,["outputFormat=JSON","domainName={0}".format(domainName)])
        return response
