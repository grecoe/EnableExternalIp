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

# Flag used to either create a new rule on the NSG associated with the VM (True) or to 
# get the effective rules, find the cleanupservice, and add in an IP to an existing inbound rule.  
createNewRule = False

'''
    Use this if you have a service principal you wish to connect with. 
'''
# Create the stuff we need
#spCreds = getServicePrincipal(sp_client_id, sp_secret, sp_tenant)
#nwClient = getNetworkClient( spCreds, subscription_id)
#rsClient = getResourceClient( spCreds, subscription_id)

'''
    Use this if you want to use the logged in profile. 
'''
nwClient = getNetworkClient()
rsClient = getResourceClient()

# Not sure this is neccesary....
#rsClient.providers.register('Microsoft.Network')

if not createNewRule:

    print("Updating existing rule, if there.")
    ssh_port = '22'

    # Get network interfaces
    ints = getNetworkInterfaces(nwClient, resource_group)

    # for each interface, get effective rules. 
    for ninterface in ints:
        rules = getEffectiveRules(nwClient, resource_group,  ninterface)
    
        cleanupgroup = [x for x in rules if x["resource_group"] == 'cleanupservice']
    
        # Did we find the cleanup service? 
        if cleanupgroup and len(cleanupgroup) == 1:
            # For each rule, get it and see (1) if it allows portCheck port, and 2 if the 
            # requested_ip is already there. 
            active_resource_group = cleanupgroup[0]["resource_group"]
            active_nsg = cleanupgroup[0]["network_security_group"]
            for rule in cleanupgroup[0]["rules"]:
                print("Checking ", rule)
                sec_rule = getSecurityRule(nwClient, active_resource_group, active_nsg, rule)

                # Rule has to be inbound / allow
                if sec_rule.access == 'Allow' and sec_rule.direction == 'Inbound':
                    print("Allowable inbound rule...")
                    # Rule has to support port....
                    if sec_rule.destination_port_range == ssh_port or ssh_port in sec_rule.destination_port_ranges:
                        print("Rule set for desired port")
                        # Check for this IP there already. 
                        if requested_ip not in sec_rule.source_address_prefixes:
                            print("IP ", requested_ip, " not in rule, update it....")
                            sec_rule.source_address_prefixes.append(requested_ip)
                            nwClient.security_rules.create_or_update(active_resource_group, active_nsg, rule, sec_rule)
                            break
                        else:
                            print("IP ", requested_ip, " already in rule....")
                    else:
                        print("Rule does not contain desired port...")
                else:
                    print("Not allow or not inbound")


else:
    # Try and obtain the rule
    secRule = getSecurityRule(nwClient, resource_group, nsg_name, nsg_rule_name)

    # Determine if a create/update is required
    update = ruleUpdateNeeded(secRule, requested_ip)

    # Update/create as needed
    if update:
        updateSecurityRule(nwClient, secRule, resource_group, nsg_name, nsg_rule_name, requested_ip)

print("Done")