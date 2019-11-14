'''
    modifynsg.py can be called directly with a slew of command line parameters, or, as this file does, wraps the 
    calls so that you can test it before using it command line. 

    REMINDER command line is:
    -sid [subid] -rg [rg_name] -nsg [nsg_name] -ip [ip_addr] -spc [sp_client] -sps [sp_secret] -spt [sp_tenant]  
'''

from modifynsg import *

subscription_id = 'YOUR_AZURE_SUB_ID'
resource_group = 'YOUR_AZURE_RESOURCE_GROUP_NAME'
nsg_name = 'YOUR_NETWORK_SECURITY_GROUP_NAME'
nsg_rule_name = 'YOUR_NETWORK_SECURITY_RULE_NAME'

sp_client_id = 'YOUR_SERVICE_PRINCIPAL_CLIENT_ID'
sp_secret = 'YOUR_SERVICE_PRINCIPAL_CLIENT_SECRET'
sp_tenant = 'YOUR_SERVICE_PRINCIPAL_TENANTID'

requested_ip = 'IP_TO_ADD_TO_NSG'


# Create the stuff we need
spCreds = getServicePrincipal(sp_client_id, sp_secret, sp_tenant)
nwClient = getNetworkClient( spCreds, subscription_id)
rsClient = getResourceClient( spCreds, subscription_id)

# Not sure this is neccesary....
rsClient.providers.register('Microsoft.Network')

# Try and obtain the rule
secRule = getSecurityRule(nwClient, resource_group, nsg_name, nsg_rule_name)

# Determine if a create/update is required
update = ruleUpdateNeeded(secRule, requested_ip)

# Update/create as needed
if update:
    updateSecurityRule(nwClient, secRule, resource_group, nsg_name, nsg_rule_name, requested_ip)

print("Done")