# EnableExternalIp
<sub>Dan Grecoe a Microsoft Employee</sub>

This repo contains a script (forceip.py) that allows you to add an external IP to a Network Interface attached to an Azure virtual machine. 

While this can be done manually, if your IT department implements additional security measures on your subscription changes may only be temporary. If this is the case you may need to run the script each time you want to connect to the machine itself. 

Of course, if this is just a temporary fix to getting around implemented policies (which I'm not suggesting you do, just showing you how to do it) you would opt for a long term solution such as setting up a Point-to-site VPN solution. 

Point-to-site VPN solutions are a completely acceptable and secure solution and details on setting that up can be found [here](https://docs.microsoft.com/en-us/azure/vpn-gateway/vpn-gateway-howto-point-to-site-resource-manager-portal)

## Requirements

1. An Azure Subscripiton that contains a resource group containing a Network Interface (attached to the Virtural machine you are trying to access). 
2. Access to that account from bash, cmd, or Powershell
   * Option1: Log in on whatever shell you are using using az login. 
   * Option 2 (not utilized in forceip.py currently): Use a service principal, but you must be able to create a [Service Principal](https://docs.microsoft.com/en-us/powershell/azure/create-azure-service-principal-azureps?view=azps-3.0.0) on your Azure Subscription. 
4. In your shell you must pip install the following packages. You may want to set up a conda environment so you can clean it up easily. 
   * azure-common
   * azure-mgmt
   * azure-cli
   * azure-cli-core
5. Code does not select your subscription. You will need to use az account set -s [your-sub-id] to point to the sub you are trying to work with. 

## Usage

Open forceip.py and put in the IP address and resource group name containing the Network Interface you want to modify. 

If there is more than one Network Interface, you can supply it's name at the top of the file as well. 

NOTE: Code has not been implemented to select one of many network interfaces from the returned list of resources. This could be added on line 70. 
