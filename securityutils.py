'''
    OVERVIEW:
        This script is used to get collect and work with Security Rules associated with Azure Networks. 
        
    REQUIREMENTS:
    - Azure Subscription
    - Virtual Machine deployment with Network Interface
    - Access to the resoruce group the virtual machine lives in .
    - Pip install
        azure-common
        azure-mgmt
        azure-cli
        azure-cli-core
'''

import argparse
import sys
from azure.common.client_factory import get_client_from_cli_profile
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
    Obtain an instance of NetworkManagementClient using logged in profile
'''
def getNetworkClient():
    return get_client_from_cli_profile(NetworkManagementClient)

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
    Obtain an instance of ResourceManagementClient using logged in profile
'''
def getResourceClient():
    return get_client_from_cli_profile(ResourceManagementClient)


'''
    Get all network interfaces in a resource group, returns list of NetworkInterfacesOperations
'''
def getNetworkInterfaces(network_client, resource_group):
    network_interfaces = []
    
    interface_list = network_client.network_interfaces.list(resource_group_name=resource_group)

    for interface in interface_list:
        network_interfaces.append(interface)

    return network_interfaces

'''
    Get list of effective ruls in rg and nsg associated with an interface. 

    Takes client and NetworkInterfaceOperations.
'''
def getEffectiveRules(network_client, resource_group, network_interface):
    return getEffectiveRulesByName(network_client, resource_group, network_interface.name)

def getEffectiveRulesByName(network_client, resource_group, network_interface_name):

    returnRules = []
    
    effective_groups = network_client.network_interfaces.list_effective_network_security_groups(resource_group_name=resource_group, network_interface_name=network_interface_name)
    effective_groups_list = effective_groups.result()

    for effective_group in effective_groups_list.value:


        nsgid = effective_group.network_security_group.id.split('/')
        resource_group_index = nsgid.index('resourceGroups')
        nsg_index = nsgid.index('networkSecurityGroups')

        nsg_info = {}
        nsg_info["resource_group"] = nsgid[resource_group_index + 1]
        nsg_info["network_security_group"] = nsgid[nsg_index + 1]
        nsg_info["rules"] = []

        for rl in effective_group.effective_security_rules:
            name = rl.name.split('/')
            nsg_info["rules"].append(name[-1])    
        
        returnRules.append(nsg_info)

    return returnRules

'''
    Load rules associated with a security group. 

    Params:
        network_client : Instance of NetworkManagementClient
        resource_group : Azure Resource Group in the subscription
        security_group : Network security group in the Azure Resource Group
'''
def loadInboundSecurityRules(network_client, resource_group, security_group):
    return_rules = []

    result = network_client.security_rules.list(resource_group_name=resource_group, network_security_group_name=security_group)
    try:
        foundRule = result.next()
        while foundRule:
            if foundRule.direction == 'Inbound':
                return_rules.append(foundRule)
            foundRule = result.next()

    except StopIteration as ex:
        print("Iteration complete")
    except Exception as ex:
        print("Unknown exception")

    return return_rules


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
                security_rule = foundRule
                break
            foundRule = result.next()

    except StopIteration as ex:
        print("Iteration complete")
    except Exception as ex:
        print("Unknown exception")

    return security_rule

'''
    Takes a list of SecurityRule objects and splits them, based on destination port, 
    into an allow and deny dictionaries of dict[priority] = rule

    Params:
        rule_list : List of SecurityRule objects
        destination_port : Port for access
'''
def splitRules(rule_list, destination_port):
    allow = {}
    deny = {}

    for rule in rule_list:
        current_dict = allow

        if rule.access != 'Allow':
            current_dict = deny

        str_port = str(destination_port)

        if (rule.destination_port_range == str_port) or (rule.destination_port_range == '*') or (str_port in rule.destination_port_ranges):
            current_dict[rule.priority] = rule

    return allow, deny

'''
    Takes an instances of SecurityRule and determines if it's IP based. 

    Security rule is IP based IF:
    - source_address prefix is NOT equal to 'AzureLoadBalancer' or 'VirtualNetwork'
    - source_address_prefix is not None or source_address_prefixes is not empty
'''
def isRuleIpBased(security_rule):
    return_value = False
    if security_rule.source_address_prefix == 'AzureLoadBalancer' or security_rule.source_address_prefix == 'VirtualNetwork':
        return_value = False 
    elif security_rule.source_address_prefix != None or len(security_rule.source_address_prefixes) > 0:
        return_value = True
    return return_value

'''
    Takes an instances of SecurityRule and determines an IP is in it. 
'''
def isIpPresent(security_rule, ip_addr):
    return_value = False
    if security_rule.source_address_prefix ==ip_addr or ip_addr in security_rule.source_address_prefixes:
        return_value = True
    return return_value

'''
    Updates an existing security rule to add in new IP address.

    Params:
        network_client : Instance of NetworkManagementClient
        existing_rule : Instance of Security_Rule or None
        resource_group : Azure Resource Group in the subscription
        nsg_name : Network security group in the Azure Resource Group
        requested_ip : External IP Address
'''
def updateSecurityRule(network_client, existing_rule, resource_group, nsg_name, requested_ip):
    existing_rule.source_address_prefixes.append(requested_ip)
    async_security_rule = network_client.security_rules.create_or_update(resource_group, nsg_name, existing_rule.name, existing_rule)

    updated_security_rule = async_security_rule.result()
    print(updated_security_rule)    


'''
    Create a security rule in a given network security group. The rule will allow inbound traffic 
    on the selected port through the NSG for the specified IP address. 

    Params:
        network_client : Instance of NetworkManagementClient
        resource_group : Azure Resource Group in the subscription
        nsg_name : Network security group in the Azure Resource Group
        nsg_rule_name :  Network security rule name to search for
        priority: Priority between 100 - 4001
        port: Port  for access
        requested_ip : External IP Address
'''
def createSecurityRule(network_client, resource_group, nsg_name, nsg_rule_name, priority, port, requested_ip):

    print("Create or update rule ", nsg_rule_name)
    ruleConfiguration = {
            'access': SecurityRuleAccess.allow,
            'description':'New Test security rule',
            'destination_address_prefix':'*',
            'destination_port_range': str(port),
            'direction': SecurityRuleDirection.inbound,
            'priority': int(priority),
            'protocol': SecurityRuleProtocol.tcp,
            'source_port_range':'*', 
            'source_address_prefix' : requested_ip       
    }

    async_security_rule = network_client.security_rules.create_or_update(
        resource_group,
        nsg_name,
        nsg_rule_name,
        ruleConfiguration
    )

    security_rule = async_security_rule.result()
    print(security_rule)    

