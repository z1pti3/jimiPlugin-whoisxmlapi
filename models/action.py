from core.models import action
from core import auth, db, helpers

from plugins.whoisxmlapi.includes import whoisxmlapi

class _whoisxmlapiWhois(action._action):
    apiToken = str()
    domainName = str()

    def run(self,data,persistentData,actionResult):
        domainName = helpers.evalString(self.domainName,{"data" : data})
        apiToken = auth.getPasswordFromENC(self.apiToken)

        result = whoisxmlapi._whoisxmlapi(apiToken).whois(domainName)

        if result:
            actionResult["result"] = True
            actionResult["rc"] = 0
            actionResult["whois"] = result
        else:
            actionResult["result"] = False
            actionResult["rc"] = 404
            actionResult["msg"] = "Failed to get a valid response from whoisxmlapi API"
        return actionResult 

    def setAttribute(self,attr,value,sessionData=None):
        if attr == "apiToken" and not value.startswith("ENC "):
            if db.fieldACLAccess(sessionData,self.acl,attr,accessType="write"):
                self.apiToken = "ENC {0}".format(auth.getENCFromPassword(value))
                return True
            return False
        return super(_whoisxmlapiWhois,self).setAttribute(attr,value,sessionData=sessionData)

class _whoisxmlapiWhoisHistory(action._action):
    apiToken = str()
    domainName = str()

    def run(self,data,persistentData,actionResult):
        domainName = helpers.evalString(self.domainName,{"data" : data})
        apiToken = auth.getPasswordFromENC(self.apiToken)

        result = whoisxmlapi._whoisxmlapi(apiToken).whoisHistory(domainName)

        if result:
            actionResult["result"] = True
            actionResult["rc"] = 0
            actionResult["whois"] = result
        else:
            actionResult["result"] = False
            actionResult["rc"] = 404
            actionResult["msg"] = "Failed to get a valid response from whoisxmlapi API"
        return actionResult 

    def setAttribute(self,attr,value,sessionData=None):
        if attr == "apiToken" and not value.startswith("ENC "):
            if db.fieldACLAccess(sessionData,self.acl,attr,accessType="write"):
                self.apiToken = "ENC {0}".format(auth.getENCFromPassword(value))
                return True
            return False
        return super(_whoisxmlapiWhoisHistory,self).setAttribute(attr,value,sessionData=sessionData)

class _whoisxmlapiGetSubdomains(action._action):
    apiToken = str()
    domainName = str()

    def run(self,data,persistentData,actionResult):
        domainName = helpers.evalString(self.domainName,{"data" : data})
        apiToken = auth.getPasswordFromENC(self.apiToken)

        result = whoisxmlapi._whoisxmlapi(apiToken).subdomains(domainName)

        if result:
            actionResult["result"] = True
            actionResult["rc"] = 0
            actionResult["apiResult"] = result
        else:
            actionResult["result"] = False
            actionResult["rc"] = 404
            actionResult["msg"] = "Failed to get a valid response from whoisxmlapi API"
        return actionResult 

    def setAttribute(self,attr,value,sessionData=None):
        if attr == "apiToken" and not value.startswith("ENC "):
            if db.fieldACLAccess(sessionData,self.acl,attr,accessType="write"):
                self.apiToken = "ENC {0}".format(auth.getENCFromPassword(value))
                return True
            return False
        return super(_whoisxmlapiGetSubdomains,self).setAttribute(attr,value,sessionData=sessionData)

class _whoisxmlapiReverseIPLookup(action._action):
    apiToken = str()
    ip = str()

    def run(self,data,persistentData,actionResult):
        ip = helpers.evalString(self.ip,{"data" : data})
        apiToken = auth.getPasswordFromENC(self.apiToken)

        result = whoisxmlapi._whoisxmlapi(apiToken).reverseIPLookup(ip)

        if result:
            actionResult["result"] = True
            actionResult["rc"] = 0
            actionResult["apiResult"] = result
        else:
            actionResult["result"] = False
            actionResult["rc"] = 404
            actionResult["msg"] = "Failed to get a valid response from whoisxmlapi API"
        return actionResult 

    def setAttribute(self,attr,value,sessionData=None):
        if attr == "apiToken" and not value.startswith("ENC "):
            if db.fieldACLAccess(sessionData,self.acl,attr,accessType="write"):
                self.apiToken = "ENC {0}".format(auth.getENCFromPassword(value))
                return True
            return False
        return super(_whoisxmlapiReverseIPLookup,self).setAttribute(attr,value,sessionData=sessionData)

class _whoisxmlapiReverseMXLookup(action._action):
    apiToken = str()
    mailServerFQDN = str()

    def run(self,data,persistentData,actionResult):
        mailServerFQDN = helpers.evalString(self.mailServerFQDN,{"data" : data})
        apiToken = auth.getPasswordFromENC(self.apiToken)

        result = whoisxmlapi._whoisxmlapi(apiToken).reverseMXLookup(mailServerFQDN)

        if result:
            actionResult["result"] = True
            actionResult["rc"] = 0
            actionResult["apiResult"] = result
        else:
            actionResult["result"] = False
            actionResult["rc"] = 404
            actionResult["msg"] = "Failed to get a valid response from whoisxmlapi API"
        return actionResult 

    def setAttribute(self,attr,value,sessionData=None):
        if attr == "apiToken" and not value.startswith("ENC "):
            if db.fieldACLAccess(sessionData,self.acl,attr,accessType="write"):
                self.apiToken = "ENC {0}".format(auth.getENCFromPassword(value))
                return True
            return False
        return super(_whoisxmlapiReverseMXLookup,self).setAttribute(attr,value,sessionData=sessionData)

class _whoisxmlapiWebsiteScreenshot(action._action):
    apiToken = str()
    domainName = str()

    def run(self,data,persistentData,actionResult):
        domainName = helpers.evalString(self.domainName,{"data" : data})
        apiToken = auth.getPasswordFromENC(self.apiToken)

        result = whoisxmlapi._whoisxmlapi(apiToken).websiteScreenshot(domainName)

        if result:
            actionResult["result"] = True
            actionResult["rc"] = 0
            actionResult["base64Image"] = result
        else:
            actionResult["result"] = False
            actionResult["rc"] = 404
            actionResult["msg"] = "Failed to get a valid response from whoisxmlapi API"
        return actionResult 

    def setAttribute(self,attr,value,sessionData=None):
        if attr == "apiToken" and not value.startswith("ENC "):
            if db.fieldACLAccess(sessionData,self.acl,attr,accessType="write"):
                self.apiToken = "ENC {0}".format(auth.getENCFromPassword(value))
                return True
            return False
        return super(_whoisxmlapiWebsiteScreenshot,self).setAttribute(attr,value,sessionData=sessionData)

class _whoisxmlapiVerifyEmail(action._action):
    apiToken = str()
    emailAddress = str()

    def run(self,data,persistentData,actionResult):
        emailAddress = helpers.evalString(self.emailAddress,{"data" : data})
        apiToken = auth.getPasswordFromENC(self.apiToken)

        result = whoisxmlapi._whoisxmlapi(apiToken).verifyEmail(emailAddress)

        if result:
            actionResult["result"] = True
            actionResult["rc"] = 0
            actionResult["apiResult"] = result
        else:
            actionResult["result"] = False
            actionResult["rc"] = 404
            actionResult["msg"] = "Failed to get a valid response from whoisxmlapi API"
        return actionResult 

    def setAttribute(self,attr,value,sessionData=None):
        if attr == "apiToken" and not value.startswith("ENC "):
            if db.fieldACLAccess(sessionData,self.acl,attr,accessType="write"):
                self.apiToken = "ENC {0}".format(auth.getENCFromPassword(value))
                return True
            return False
        return super(_whoisxmlapiVerifyEmail,self).setAttribute(attr,value,sessionData=sessionData)

class _whoisxmlapiIPGeolocation(action._action):
    apiToken = str()
    ip = str()

    def run(self,data,persistentData,actionResult):
        ip = helpers.evalString(self.ip,{"data" : data})
        apiToken = auth.getPasswordFromENC(self.apiToken)

        result = whoisxmlapi._whoisxmlapi(apiToken).ipGeolocation(ip)

        if result:
            actionResult["result"] = True
            actionResult["rc"] = 0
            actionResult["apiResult"] = result
        else:
            actionResult["result"] = False
            actionResult["rc"] = 404
            actionResult["msg"] = "Failed to get a valid response from whoisxmlapi API"
        return actionResult 

    def setAttribute(self,attr,value,sessionData=None):
        if attr == "apiToken" and not value.startswith("ENC "):
            if db.fieldACLAccess(sessionData,self.acl,attr,accessType="write"):
                self.apiToken = "ENC {0}".format(auth.getENCFromPassword(value))
                return True
            return False
        return super(_whoisxmlapiIPGeolocation,self).setAttribute(attr,value,sessionData=sessionData)

class _whoisxmlapiDNSLookup(action._action):
    apiToken = str()
    domainName = str()
    lookupType = "A"

    def run(self,data,persistentData,actionResult):
        domainName = helpers.evalString(self.domainName,{"data" : data})
        lookupType = helpers.evalString(self.lookupType,{"data" : data})
        apiToken = auth.getPasswordFromENC(self.apiToken)

        result = whoisxmlapi._whoisxmlapi(apiToken).dnsLookup(domainName,lookupType)

        if result:
            actionResult["result"] = True
            actionResult["rc"] = 0
            actionResult["apiResult"] = result
        else:
            actionResult["result"] = False
            actionResult["rc"] = 404
            actionResult["msg"] = "Failed to get a valid response from whoisxmlapi API"
        return actionResult 

    def setAttribute(self,attr,value,sessionData=None):
        if attr == "apiToken" and not value.startswith("ENC "):
            if db.fieldACLAccess(sessionData,self.acl,attr,accessType="write"):
                self.apiToken = "ENC {0}".format(auth.getENCFromPassword(value))
                return True
            return False
        return super(_whoisxmlapiDNSLookup,self).setAttribute(attr,value,sessionData=sessionData)

class _whoisxmlapiNetblockLookup(action._action):
    apiToken = str()
    ip = str()
    mask = str()
    asn = str()

    def run(self,data,persistentData,actionResult):
        ip = helpers.evalString(self.ip,{"data" : data})
        mask = helpers.evalString(self.mask,{"data" : data})
        asn = helpers.evalString(self.asn,{"data" : data})
        apiToken = auth.getPasswordFromENC(self.apiToken)

        result = None
        if asn:
            result = whoisxmlapi._whoisxmlapi(apiToken).netblock(asn=asn)
        elif ip and mask:
            result = whoisxmlapi._whoisxmlapi(apiToken).netblock(ip=ip,mask=mask)
        elif ip:
            result = whoisxmlapi._whoisxmlapi(apiToken).netblock(ip=ip)

        if result:
            actionResult["result"] = True
            actionResult["rc"] = 0
            actionResult["apiResult"] = result
        else:
            actionResult["result"] = False
            actionResult["rc"] = 404
            actionResult["msg"] = "Failed to get a valid response from whoisxmlapi API"
        return actionResult 

    def setAttribute(self,attr,value,sessionData=None):
        if attr == "apiToken" and not value.startswith("ENC "):
            if db.fieldACLAccess(sessionData,self.acl,attr,accessType="write"):
                self.apiToken = "ENC {0}".format(auth.getENCFromPassword(value))
                return True
            return False
        return super(_whoisxmlapiNetblockLookup,self).setAttribute(attr,value,sessionData=sessionData)

class _whoisxmlapiDomainReputation(action._action):
    apiToken = str()
    domainName = str()

    def run(self,data,persistentData,actionResult):
        domainName = helpers.evalString(self.domainName,{"data" : data})
        apiToken = auth.getPasswordFromENC(self.apiToken)

        result = whoisxmlapi._whoisxmlapi(apiToken).domainReputation(domainName)

        if result:
            actionResult["result"] = True
            actionResult["rc"] = 0
            actionResult["base64Image"] = result
        else:
            actionResult["result"] = False
            actionResult["rc"] = 404
            actionResult["msg"] = "Failed to get a valid response from whoisxmlapi API"
        return actionResult 

    def setAttribute(self,attr,value,sessionData=None):
        if attr == "apiToken" and not value.startswith("ENC "):
            if db.fieldACLAccess(sessionData,self.acl,attr,accessType="write"):
                self.apiToken = "ENC {0}".format(auth.getENCFromPassword(value))
                return True
            return False
        return super(_whoisxmlapiDomainReputation,self).setAttribute(attr,value,sessionData=sessionData)

class _whoisxmlapiDomainCategorization(action._action):
    apiToken = str()
    domainName = str()

    def run(self,data,persistentData,actionResult):
        domainName = helpers.evalString(self.domainName,{"data" : data})
        apiToken = auth.getPasswordFromENC(self.apiToken)

        result = whoisxmlapi._whoisxmlapi(apiToken).domainCategorization(domainName)

        if result:
            actionResult["result"] = True
            actionResult["rc"] = 0
            actionResult["base64Image"] = result
        else:
            actionResult["result"] = False
            actionResult["rc"] = 404
            actionResult["msg"] = "Failed to get a valid response from whoisxmlapi API"
        return actionResult 

    def setAttribute(self,attr,value,sessionData=None):
        if attr == "apiToken" and not value.startswith("ENC "):
            if db.fieldACLAccess(sessionData,self.acl,attr,accessType="write"):
                self.apiToken = "ENC {0}".format(auth.getENCFromPassword(value))
                return True
            return False
        return super(_whoisxmlapiDomainCategorization,self).setAttribute(attr,value,sessionData=sessionData)

class _whoisxmlapiDomainContacts(action._action):
    apiToken = str()
    domainName = str()

    def run(self,data,persistentData,actionResult):
        domainName = helpers.evalString(self.domainName,{"data" : data})
        apiToken = auth.getPasswordFromENC(self.apiToken)

        result = whoisxmlapi._whoisxmlapi(apiToken).websiteContacts(domainName)

        if result:
            actionResult["result"] = True
            actionResult["rc"] = 0
            actionResult["base64Image"] = result
        else:
            actionResult["result"] = False
            actionResult["rc"] = 404
            actionResult["msg"] = "Failed to get a valid response from whoisxmlapi API"
        return actionResult 

    def setAttribute(self,attr,value,sessionData=None):
        if attr == "apiToken" and not value.startswith("ENC "):
            if db.fieldACLAccess(sessionData,self.acl,attr,accessType="write"):
                self.apiToken = "ENC {0}".format(auth.getENCFromPassword(value))
                return True
            return False
        return super(_whoisxmlapiDomainContacts,self).setAttribute(attr,value,sessionData=sessionData)

class _whoisxmlapiDomainAvailabilityCheck(action._action):
    apiToken = str()
    domainName = str()

    def run(self,data,persistentData,actionResult):
        domainName = helpers.evalString(self.domainName,{"data" : data})
        apiToken = auth.getPasswordFromENC(self.apiToken)

        result = whoisxmlapi._whoisxmlapi(apiToken).domainAvailabilityCheck(domainName)

        if result:
            actionResult["result"] = True
            actionResult["rc"] = 0
            actionResult["base64Image"] = result
        else:
            actionResult["result"] = False
            actionResult["rc"] = 404
            actionResult["msg"] = "Failed to get a valid response from whoisxmlapi API"
        return actionResult 

    def setAttribute(self,attr,value,sessionData=None):
        if attr == "apiToken" and not value.startswith("ENC "):
            if db.fieldACLAccess(sessionData,self.acl,attr,accessType="write"):
                self.apiToken = "ENC {0}".format(auth.getENCFromPassword(value))
                return True
            return False
        return super(_whoisxmlapiDomainAvailabilityCheck,self).setAttribute(attr,value,sessionData=sessionData)

