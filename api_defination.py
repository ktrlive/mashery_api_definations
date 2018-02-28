# -*- coding: utf-8 -*-
import sys, argparse, json
sys.path.append('/Users/kartikshah/Desktop/masheryapi/python/lib/api')
sys.path.append('/Users/kartikshah/Desktop/masheryapi/python/lib/services')

from masheryV3 import MasheryV3
map1 = {'key':'value'}
class ExportApiDefinitions():
    masheryV3 = MasheryV3()
    token = None


    def authenticate(self, mashery_api_key, mashery_api_secret, mashery_username, mashery_password, mashery_area_uuid):
        self.token = self.masheryV3.authenticate(mashery_api_key, mashery_api_secret, mashery_username, mashery_password, mashery_area_uuid)
        if 'error' in self.token:
            print self.token
            return

    def get_apis(self):
        apis = self.masheryV3.get(self.token, '/services', 'fields=id')
        if 'errorCode' in apis:
            print apis
            return
        return apis

    def get_api(self, api_id):
        api = self.masheryV3.get(self.token, '/services/' + api_id, 'fields=id,name,description,securityProfile,qpsLimitOverall,rfc3986Encode,version,cache,endpoints.inboundSslRequired,endpoints.jsonpCallbackParameter,endpoints.jsonpCallbackParameterValue,endpoints.scheduledMaintenanceEvent,endpoints.forwardedHeaders,endpoints.returnedHeaders,endpoints.id,endpoints.name,endpoints.numberOfHttpRedirectsToFollow,endpoints.outboundRequestTargetPath,endpoints.outboundRequestTargetQueryParameters,endpoints.outboundTransportProtocol,endpoints.processor,endpoints.publicDomains,endpoints.requestAuthenticationType,endpoints.requestPathAlias,endpoints.requestProtocol,endpoints.oauthGrantTypes,endpoints.supportedHttpMethods,endpoints.apiMethodDetectionLocations,endpoints.apiMethodDetectionKey,endpoints.systemDomainAuthentication,endpoints.setpassword.setPassword,endpoints.systemDomains,endpoints.trafficManagerDomain,endpoints.updated,endpoints.useSystemDomainCredentials,endpoints.systemDomainCredentialKey,endpoints.systemDomainCredentialSecret,endpoints.methods,endpoints.methods.id,endpoints.methods.name,endpoints.methods.sampleXmlResponse,endpoints.methods.sampleJsonResponse,endpoints.strictSecurity,endpoints.highSecurity,endpoints.allowMissingApiKey,endpoints.hostPassthroughIncludedInBackendCallHeader,endpoints.cors,endpoints.customRequestAuthenticationAdapter,endpoints.headersToExcludeFromIncomingCall,endpoints.rateLimitHeadersEnabled,endpoints.forceGzipOfBackendCall,endpoints.gzipPassthroughSupportEnabled,endpoints.cookiesDuringHttpRedirectsEnabled,endpoints.connectionTimeoutForSystemDomainRequest,endpoints.connectionTimeoutForSystemDomainResponse,endpoints.rateLimitHeadersEnabled,endpoints.dropApiKeyFromIncomingCall,endpoints.cache,endpoints.processor,securityProfile.oauth')
        if 'errorCode' in api:
            print 'problem fetching...' + str(api_id) + ' ERROR:' + json.dumps(api)
            return
        return api

    def get_apis_packages(self):
        apis = self.masheryV3.get(self.token, '/packages', 'fields=id,name')
        if 'errorCode' in apis:
            print apis
            return
        return apis

    def get_apis_packages_plans(self, api_id):
        apis = self.masheryV3.get(self.token, '/packages/' + api_id +'/plans/', 'fields=id,name')
        if 'errorCode' in apis:
            print 'problem fetching...' + str(api_id) + ' ERROR:' + json.dumps(api)
            return
        return apis

    def get_apis_packages_plans_services(self, api_id, api1_id):
        api = self.masheryV3.get(self.token, '/packages/' + api_id+'/plans/'+api1_id+'/services/','fields=id,name')
        if 'errorCode' in api:
            print 'problem fetching...' +    + ' ERROR:' + json.dumps(api)
            return
        return api

    def get_apis_packages_plans_services_endpoints(self, api_id, api1_id,api2_id):
        api = self.masheryV3.get(self.token, '/packages/' + api_id+'/plans/'+api1_id+'/services/'+ api2_id +'/endpoints','fields=id,name')
        if 'errorCode' in api:
            print 'problem fetching...' + str(api_id) + ' ERROR:' + json.dumps(api)
            return
        return api

    def archive_api_defination(self, backup_location, api):
        for endpoint in api["endpoints"] :
            map1[endpoint['name']] = endpoint['publicDomains'][0]['address'] + endpoint['requestPathAlias']+","+endpoint['systemDomains'][0]['address'] + endpoint['outboundRequestTargetPath'] +"," +endpoint['supportedHttpMethods'][0] 
            print endpoint['name']+","+api['name']+","+endpoint['publicDomains'][0]['address'] + endpoint['requestPathAlias']+","+endpoint['systemDomains'][0]['address'] + endpoint['outboundRequestTargetPath'] +"," +endpoint['supportedHttpMethods'][0] ;

    def archive(self, backup_location, api, api1, api2, api3 ):
        try:
            file = open(backup_location+"api_definations.txt","a+")
        except Exception as e:
            print e
        for data in api3: 
            file.write(str(api2['name'])+","+data['name']+","+map1[data['name']]+","+str(api['name'])+","+str(api1['name'])+"\n")
            #print data['name']+","+str(api2['name'])+","+str(api['name'])+","+str(api1['name'])

def main():
    export_api_definitions = ExportApiDefinitions()
    parser = argparse.ArgumentParser()
    parser.add_argument("mashery_api_key", type=str, help="Mashery V3 API Key")
    parser.add_argument("mashery_api_secret", type=str, help="Mashery V3 API Secret")
    parser.add_argument("mashery_area_uuid", type=str, help="Mashery Area/Site UUID")
    parser.add_argument("mashery_username", type=str, help="Mashery Portal Username")
    parser.add_argument("mashery_password", type=str, help="Mashery Portal Password")
    parser.add_argument("output_directory", type=str, help="Output Directory")

    args = parser.parse_args()
  
    mashery_api_key = args.mashery_api_key
    mashery_api_secret = args.mashery_api_secret
    mashery_area_uuid = args.mashery_area_uuid
    mashery_username = args.mashery_username
    mashery_password = args.mashery_password
    output_directory = args.output_directory
    apis = []

    export_api_definitions.authenticate(mashery_api_key, mashery_api_secret, mashery_username, mashery_password, mashery_area_uuid)    

    apis = export_api_definitions.get_apis()
    for api in apis:
        api = export_api_definitions.get_api(api['id'])
        if api != None:
            # print 'exporting... '
            export_api_definitions.archive_api_defination(output_directory, api)

    apis = export_api_definitions.get_apis_packages() 
    for api in apis:
        # plan ids
        api2 = export_api_definitions.get_apis_packages_plans(api['id']) 
        for api1 in api2:
            # //service ids
            api3 = export_api_definitions.get_apis_packages_plans_services(api['id'], api1['id']) 
            for api4 in api3:
                # endpoints
                api5 = export_api_definitions.get_apis_packages_plans_services_endpoints(api['id'], api1['id'], api4['id']) 
                if api5 != None:
                    # print 'exporting... endpoints' 
                    export_api_definitions.archive(output_directory, api, api1, api4, api5)
    
if __name__ == "__main__":
    main()