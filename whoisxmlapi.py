from core import plugin, model

class _whoisxmlapi(plugin._plugin):
    version = 0.1

    def install(self):
        # Register models
        model.registerModel("whoisxmlapiWhois","_whoisxmlapiWhois","_action","plugins.whoisxmlapi.models.action")
        model.registerModel("whoisxmlapiWhoisHistory","_whoisxmlapiWhoisHistory","_action","plugins.whoisxmlapi.models.action")
        model.registerModel("whoisxmlapiGetSubdomains","_whoisxmlapiGetSubdomains","_action","plugins.whoisxmlapi.models.action")
        model.registerModel("whoisxmlapiReverseIPLookup","_whoisxmlapiReverseIPLookup","_action","plugins.whoisxmlapi.models.action")
        model.registerModel("whoisxmlapiReverseMXLookup","_whoisxmlapiReverseMXLookup","_action","plugins.whoisxmlapi.models.action")
        model.registerModel("whoisxmlapiWebsiteScreenshot","_whoisxmlapiWebsiteScreenshot","_action","plugins.whoisxmlapi.models.action")
        model.registerModel("whoisxmlapiVerifyEmail","_whoisxmlapiVerifyEmail","_action","plugins.whoisxmlapi.models.action")
        model.registerModel("whoisxmlapiIPGeolocation","_whoisxmlapiIPGeolocation","_action","plugins.whoisxmlapi.models.action")
        model.registerModel("whoisxmlapiDNSLookup","_whoisxmlapiDNSLookup","_action","plugins.whoisxmlapi.models.action")
        model.registerModel("whoisxmlapiNetblockLookup","_whoisxmlapiNetblockLookup","_action","plugins.whoisxmlapi.models.action")
        model.registerModel("whoisxmlapiDomainReputation","_whoisxmlapiDomainReputation","_action","plugins.whoisxmlapi.models.action")
        model.registerModel("whoisxmlapiDomainCategorization","_whoisxmlapiDomainCategorization","_action","plugins.whoisxmlapi.models.action")
        model.registerModel("whoisxmlapiDomainContacts","_whoisxmlapiDomainContacts","_action","plugins.whoisxmlapi.models.action")
        model.registerModel("whoisxmlapiDomainAvailabilityCheck","_whoisxmlapiDomainAvailabilityCheck","_action","plugins.whoisxmlapi.models.action")
        return True

    def uninstall(self):
        # deregister models
        model.deregisterModel("whoisxmlapiWhois","_whoisxmlapiWhois","_action","plugins.whoisxmlapi.models.action")
        model.deregisterModel("whoisxmlapiWhoisHistory","_whoisxmlapiWhoisHistory","_action","plugins.whoisxmlapi.models.action")
        model.deregisterModel("whoisxmlapiGetSubdomains","_whoisxmlapiGetSubdomains","_action","plugins.whoisxmlapi.models.action")
        model.deregisterModel("whoisxmlapiReverseIPLookup","_whoisxmlapiReverseIPLookup","_action","plugins.whoisxmlapi.models.action")
        model.deregisterModel("whoisxmlapiReverseMXLookup","_whoisxmlapiReverseMXLookup","_action","plugins.whoisxmlapi.models.action")
        model.deregisterModel("whoisxmlapiWebsiteScreenshot","_whoisxmlapiWebsiteScreenshot","_action","plugins.whoisxmlapi.models.action")
        model.deregisterModel("whoisxmlapiVerifyEmail","_whoisxmlapiVerifyEmail","_action","plugins.whoisxmlapi.models.action")
        model.deregisterModel("whoisxmlapiIPGeolocation","_whoisxmlapiIPGeolocation","_action","plugins.whoisxmlapi.models.action")
        model.deregisterModel("whoisxmlapiDNSLookup","_whoisxmlapiDNSLookup","_action","plugins.whoisxmlapi.models.action")
        model.deregisterModel("whoisxmlapiNetblockLookup","_whoisxmlapiNetblockLookup","_action","plugins.whoisxmlapi.models.action")
        model.deregisterModel("whoisxmlapiDomainReputation","_whoisxmlapiDomainReputation","_action","plugins.whoisxmlapi.models.action")
        model.deregisterModel("whoisxmlapiDomainCategorization","_whoisxmlapiDomainCategorization","_action","plugins.whoisxmlapi.models.action")
        model.deregisterModel("whoisxmlapiDomainContacts","_whoisxmlapiDomainContacts","_action","plugins.whoisxmlapi.models.action")
        model.deregisterModel("whoisxmlapiDomainAvailabilityCheck","_whoisxmlapiDomainAvailabilityCheck","_action","plugins.whoisxmlapi.models.action")
        return True

    def upgrade(self,LatestPluginVersion):
        pass
        #if self.version < 0.2:
