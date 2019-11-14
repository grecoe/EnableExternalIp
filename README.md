# EnableExternalIp
<sub>Dan Grecoe a Microsoft Employee</sub>

This repo contains two Python scripts that enable you, as an Azure user, to enable a single IP address to SSH into your Azure Virtual Machine from an external network. 

```
NOTE:

Many IT departments will frown the approach taken in these files. 

In no way is this a suggestion to subvert your corporate or IT policies in any way. 

However, in a development subscription you may find a need to allow a single external IP to SSH into one of 
your your Azure Virtual Machines. If this is the case, this is one of many approaches you can take.  
```

There may be a case where your attached network security groups are connected to wider security groups put out by policy on your Azure subscription. In fact, many of the development subscriptions I work on have this exact problem. 

It's good security, for sure, but when I'm not on the corporate network, which SSH traffic is allowed to come from, I'm generally blocked. 

Now for long term solutions, I really do recommend setting up a Point-to-site VPN solution. This is a completely acceptable and secure solution and details on setting that up can be found [here](https://docs.microsoft.com/en-us/azure/vpn-gateway/vpn-gateway-howto-point-to-site-resource-manager-portal)

For a short term solution, again not the most recommended solution out there, you can modify your network security group associated with the Azure VM to enable SSH on port 22 for specified IP addresses. This doesn't expose your machines to all internet traffic, but does leave a hole open that when you are done, you should close. 

## Purpose
Allow access to a specified IP address to initiate an SSH session with a security group protected Azure Virtual Machine.  

## Requirements

1. You must be able to create a [Service Principal](https://docs.microsoft.com/en-us/powershell/azure/create-azure-service-principal-azureps?view=azps-3.0.0) on your Azure Subscription. 
2. You must have access to an Azure Subscription in which the Service Principal has access rights.
3. The subscription must contain at least one virtual machine that has it's own NSG. 
4. You must pip install azure-common and azure-mgmt

## Usage

modifynsg.py is a complete script that performs all of the neccesary tasks. It is run using a slew of command line arguments. 

modifynsgdriver.py wraps modifynsg.py by allowing you to identify the important information required to pass along. 
