'''
    modifynsg.py 
    
    Script that can update or create an NSG rule on an Azure NSG to allow an IP to access the SSH port (22) directly. 
    
    Many IT departments will frown on this, and it is not suggested that you in any way subvert your IT department policies. 
    
    However, in a dev subscription you may find a need to allow a single IP address external to your network to SSH into one of 
    your Azure Virtual Machines. If this is the case, this is the approach to take. 

    REMINDER command line is:
    -sid [subid] -rg [rg_name] -nsg [nsg_name] -ip [ip_addr] -spc [sp_client] -sps [sp_secret] -spt [sp_tenant]  
'''

import argparse
import sys
from azure.common.credentials import ServicePrincipalCredentials
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.network.v2017_03_01.models import NetworkSecurityGroup
from azure.mgmt.network.v2017_03_01.models import SecurityRule, SecurityRuleDirection, SecurityRuleProtocol, SecurityRuleAccess
from azure.mgmt.resource.resources import ResourceManagementClient


'''
    Obtain an instance of ServicePrincipalCredentials

    Params:
        sp_client_id : Service Principal Client Id
        sp_secret : Service Principal Client Secret
        sp_tenant : Azure Tenant for Service Principal
'''
def getServicePrincipal(sp_client_id, sp_secret, sp_tenant):
    return ServicePrincipalCredentials(
        client_id = sp_client_id,
        secret = sp_secret,
        tenant = sp_tenant
    )

'''
    Obtain an instance of NetworkManagementClient

    Params:
        spCred : Instance of ServicePrincipalCredentials
        subscription_id : Azure Subscription ID
'''
def getNetworkClient( spCred, subscription_id):
    return NetworkManagementClient(
        spCred,
        subscription_id
    )

'''
    Obtain an instance of ResourceManagementClient

    Params:
        spCred : Instance of ServicePrincipalCredentials
        subscription_id : Azure Subscription ID
'''
def getResourceClient( spCred, subscription_id):
    return ResourceManagementClient(
        spCred,
        subscription_id
    )


'''
    Search a network security group looking for a rule by a specified name. 
    If found, return the instance of SecurityRule. 

    Params:
        network_client : Instance of NetworkManagementClient
        resource_group : Azure Resource Group in the subscription
        security_group : Network security group in the Azure Resource Group
        nsg_rule_name :  Network security rule name to search for
'''
def getSecurityRule(network_client, resource_group, security_group, nsg_rule_name):
    security_rule = None
    result = network_client.security_rules.list(resource_group_name=resource_group, network_security_group_name=security_group)
    try:
        foundRule = result.next()
        while foundRule:
            if( foundRule.name == nsg_rule_name):
                print("Found the rule")
                security_rule = foundRule
                break
            foundRule = result.next()

    except StopIteration as ex:
        print("Iteration complete")
    except Exception as ex:
        print("Unknown exception")

    return security_rule

'''
    Check an existing SecurityRule, if it exists, that the priority is 101 and if the requested_ip is 
    already part of the rule. Returns boolean value determining if the rule needs to be updated for 
    any reason.  

    Params:
        security_rule : Instance of Security_Rule
        requested_ip : External IP Address
'''
def ruleUpdateNeeded(security_rule, requested_ip):
    updateRule = True

    if security_rule and security_rule.priority == 101 : 
        if security_rule.source_address_prefix == requested_ip or requested_ip in security_rule.source_address_prefixes:
            print("Rule already contains the IP, nothing more to do....")
            updateRule = False

    return updateRule

'''
    Update or create a security rule in a given network security group. The rule will allow inbound traffic 
    on port 22 (SSH) through the NSG for the specified IP address. Priority will be set at 101.

    Params:
        network_client : Instance of NetworkManagementClient
        existing_rule : Instance of Security_Rule or None
        resource_group : Azure Resource Group in the subscription
        nsg_name : Network security group in the Azure Resource Group
        nsg_rule_name :  Network security rule name to search for
        requested_ip : External IP Address
'''
def updateSecurityRule(network_client, existing_rule, resource_group, nsg_name, nsg_rule_name, requested_ip):

    print("Create or update rule ", nsg_rule_name)
    ruleConfiguration = {
            'access': SecurityRuleAccess.allow,
            'description':'New Test security rule',
            'destination_address_prefix':'*',
            'destination_port_range':'22',
            'direction': SecurityRuleDirection.inbound,
            'priority': 101,
            'protocol': SecurityRuleProtocol.tcp,
            'source_port_range':'*',        
    }

    # If rule exists, just extend the IP list, otherwise we are creating so just add the one. 
    if existing_rule:
        source_addresses = [requested_ip]
        if existing_rule.source_address_prefix and len(existing_rule.source_address_prefix) > 0:
            source_addresses.append(existing_rule.source_address_prefix)
        else:
            source_addresses.extend(existing_rule.source_address_prefixes)
        ruleConfiguration['source_address_prefixes'] = source_addresses
    else:
        ruleConfiguration['source_address_prefix'] = requested_ip

    async_security_rule = network_client.security_rules.create_or_update(
        resource_group,
        nsg_name,
        nsg_rule_name,
        ruleConfiguration
    )

    security_rule = async_security_rule.result()
    print(security_rule)    



def main():
    parser = argparse.ArgumentParser(description='Modify NSG inputs')
    parser.add_argument("-sid", required=True, type=str, help="Subscription ID")
    parser.add_argument("-rg", required=True, type=str, help="Resource Group Name")
    parser.add_argument("-nsg", required=True, type=str, help="Network Security Group Name")
    parser.add_argument("-ip", required=True, type=str, help="IP Address to clear")
    parser.add_argument("-spc", required=True, type=str, help="Service Principal ID")
    parser.add_argument("-sps", required=True, type=str, help="Service Principal Secret")
    parser.add_argument("-spt", required=True, type=str, help="Service Principal tenent")

    programArgs = parser.parse_args(sys.argv[1:])

    nsg_rule_name = 'build_ssh'

    # Create the stuff we need
    spCreds = getServicePrincipal(programArgs.spc, programArgs.sps, programArgs.spt)
    nwClient = getNetworkClient( spCreds, programArgs.sid)
    rsClient = getResourceClient( spCreds, programArgs.sid)

    # Not sure this is neccesary....
    rsClient.providers.register('Microsoft.Network')

    # Try and obtain the rule
    secRule = getSecurityRule(nwClient, programArgs.rg, programArgs.nsg, nsg_rule_name)

    # Determine if a create/update is required
    update = ruleUpdateNeeded(secRule, programArgs.ip)

    # Update/create as needed
    if update:
        updateSecurityRule(nwClient, secRule, programArgs.rg, programArgs.nsg, nsg_rule_name, programArgs.ip)


if __name__ == '__main__':
    main()