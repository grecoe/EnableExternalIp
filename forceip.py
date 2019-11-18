'''
    OVERVIEW:
        This script will, for a logged in user with the subscription set appropriately, modify a Network Security Group
        to add in an IP address to an inbound rule OR create a new rule if neccesary and able. Steps

        - Check the NIC for Inbound rules, both allow and deny
        - Filter the rules to only those supporting the requested port number
        - Filter out allowable rules with the deny list as any allow rule with a higher priority than the deny
          rule will be ignored anyway.
        - Filter out remaining allow rules to only those that support IP addresses
            - If the list is empty, try and create an inbound rule with priority less than any deny rules.
            - If the list is not empty, check to see if the IP address is already part of the rule.
                - YES : Ignore and end script
                - NO : Add the IP to the existing rule and update it. 

    REQUIREMENTS:
    - Azure Subscription
    - Virtual Machine deployment with Network Interface
    - Access to the resoruce group the virtual machine lives in .
    - Pip install
        azure-common
        azure-mgmt
        azure-cli
        azure-cli-core

    USE:
    Provide an IP address in port_ip and a resource group name. Optioal Network Interface name only if there is more 
    than one in the resource group. 
'''

from securityutils import *
from resourceutils import * 

'''
    Port number external access is requested on 
'''
port_access = 22
'''
    IP to add to the access rule
'''
port_ip = '71.184.130.226'
'''
    Resource group name where the Network interface resides
'''
resource_group_name = 'dangdeletetest'
'''
    [optiona] Network Interface name. If the RG has only one, it's not neccesary 
    to provide a name here, it will be searched for instead. 
'''
selected_nic = None
'''
    Azure resource type if looking for network interfaces on the resource group.
'''
network_interface_provider = 'Microsoft.Network/networkInterfaces'




# Gather the clients you need to get work done
rsrcMgmtClient = getResourceManagementClient()
networkClient = getNetworkClient()

# If NIC not provided, acquire all NIC from the resource group. 
if not selected_nic:
    # Get the list of network interfaces from the resrouce group. If more than one, make them choose. 
    nic_list = findResources(rsrcMgmtClient, resource_group_name, network_interface_provider)
    selected_nic = None

    if len(nic_list) > 1:
        print("Add in logic to choose")
    else:
        selected_nic = nic_list[0]


# If we have a nic then we are good
if selected_nic:
    print("Using interface : ", selected_nic.name)

    nic_rules = getEffectiveRulesByName(networkClient, resource_group_name,  selected_nic.name)
    # Appears that the last one is processed first
    active_nsg = nic_rules[-1]
    active_resource_group_name =  active_nsg["resource_group"]
    active_nsg_name = active_nsg["network_security_group"]
    
    
    print("Checking NSG - ", active_nsg_name)
    active_rules = loadInboundSecurityRules(networkClient, active_resource_group_name, active_nsg_name)

    print("Nic has ", len(active_nsg["rules"]), "rules, and ", len(active_rules), " were returned")
    allow, deny = splitRules(active_rules, port_access)
    print("There are ", len(allow.keys()), " allow rules and ",len(deny.keys()), " delete rules....")

    deny_priority = None
    original_allow_priorities = sorted(allow.keys())

    # If we have allow/deny clean it up and see if we still haven anything with access. 
    if len(deny.keys()) > 0:
        # Remove any allow prior to 
        deny_keys = sorted(deny.keys())
        # We only care about the highest priority deny, the lowest number
        deny_priority = deny_keys[0]

        # If we have allow rules, get rid of the ones blocked by the deny...
        if len(allow.keys()) > 0:
            allow_keys = sorted(allow.keys())
            delete_allow = []
            for key in allow_keys:
                if key > deny_priority:
                    delete_allow.append(key)

            for delkey in delete_allow:
                del allow[delkey]
        
    
    # If we have allow rules left, get only the one(s) with IP access defined
    security_rule_to_update = None
    force_update = True
    print("There are ", len(allow.keys()), " allow rules left after filtering on deny rules.")
    if len(allow.keys()) > 0:
        # Filter out any allow that are NOT IP based
        print("Filter allow rules only on IP based rules..... ")
        delete_allow = []
        for key in allow.keys():
            if isRuleIpBased(allow[key]) == False:
                delete_allow.append(key)

        for delkey in delete_allow:
            del allow[delkey]
    
        # Now see if the IP is on that rule? 
        print("There are ", len(allow.keys()), " allow rules left after filtering on IP based rules.")
        active_rule_key = None
        for key in allow.keys():
            if isIpPresent(allow[key], port_ip):
                active_rule_key = key
                break

        # If wae have an active rule key, we are all set, otherwise we are going to need to add the IP OR 
        # create a rule.  
        if active_rule_key:
            print("IP address is already part of the inbound rule ", allow[active_rule_key].name)
            force_update = False
        elif len(allow.keys()) > 0:
            sorted_keys = sorted(allow.keys())
            security_rule_to_update = allow[sorted_keys[0]]
            print("IP Address not found in any rules....use existing rule - ", security_rule_to_update.name)
        else:
            print("Have to create a new rule....")

    
    if security_rule_to_update:
        print("Update rule ", security_rule_to_update.name)
        updateSecurityRule(networkClient, security_rule_to_update, active_resource_group_name, active_nsg_name, port_ip)
    elif force_update:
        print("Creating new rule")

        rule_name = str(port_access) + "_access_rule"
        rule_port = port_access
        priority = 100
        valid_priority = False

        if not deny_priority:
            deny_priority = 1000

        while priority < deny_priority:
            if priority in original_allow_priorities:
                priority += 1
            else:
                valid_priority = True
                break

        if valid_priority:
            createSecurityRule(networkClient, active_resource_group_name, active_nsg_name, rule_name, priority, rule_port, port_ip )
        else:
            print("Could not find a slot to put new rule in.")



else:
    print("No NIC selected....")


print("Done")
                
