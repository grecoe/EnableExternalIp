'''
    OVERVIEW:
        This script is used to get a ResourceManagementClient and to find resources by 
        a specific type. 

        Of course, more could be done here, but the requirements were only to need to collect resources, 
        specifically network interface resources in Azure. 

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

from azure.common.client_factory import get_client_from_cli_profile
from azure.mgmt.resource import ResourceManagementClient

def getResourceManagementClient():
    return get_client_from_cli_profile(ResourceManagementClient)


def findResources(mgmtClient, resourceGroup, typeFilter):

    returnResources = []

    filter = None
    if typeFilter:
        filter = "resourceType eq '{}'".format(typeFilter)
    
    pagedResources = mgmtClient.resources.list_by_resource_group(resource_group_name = resourceGroup, filter= filter)

    for rsrc in pagedResources:
        returnResources.append(rsrc)

    return returnResources