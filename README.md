# BadZure
[![Open_Threat_Research Community](https://img.shields.io/badge/Open_Threat_Research-Community-brightgreen.svg)](https://twitter.com/OTR_Community)

BadZure is a PowerShell script that leverages the Microsoft Graph SDK to orchestrate the setup of Azure Active Directory tenants, populating them with diverse entities while also introducing common security misconfigurations to create vulnerable tenants with multiple attack paths.

Specifically, BadZure automates the process of creating multiple entities such as: users, groups, application registrations, service principals and administrative units. To simulate common security misconfigurations in real environments, it randomly assigns Azure AD roles, Graph permissions and application ownership privileges to randomly picked security principals enabling the creation of unique attack paths. In line with the 'Assume Breach' principle, BadZure provides users with two methods of initial access to the vulnerable tenants it creates thereby simulating account takeover scenarios.

The key advantage of BadZure lies in its ability to rapidly populate and purge existing Azure AD tenants with randomly generated vulnerable configurations and pre-configured initial access facilitating continous and iterative attack simulation (red team) and detection development (blue team) experimentation. It is designed for security practitioners with an interest in exploring and understanding Azure AD security. 

## Goals / Use Cases

BadZure was initialy written to host the [Azure AD Battle School: Hands-on Attack and Defense](https://www.x33fcon.com/#!s/MauricioVelazco.md) workshop at X33fcon 2023.

An Azure AD tenant populated with BadZure also enables red and blue teams to:

* Experiment with common Azure AD attack vectors and tools (for ideas => [AzureAD Attack and Defense Playbook](https://github.com/Cloud-Architekt/AzureAD-Attack-Defense))
* Quickly stand up misconfigured Azure AD lab tenants.
* Obtain attack telemetry to build, test and enhance detection controls
* Execute purple team exercises in a safe setting
* Faciliate hands-on Azure AD security training
* Host dynamic Azure AD Capture the Flag (CTF) events

## Attack Paths

### Initial Access

BadZure facilitates initial access by simulating account takover vectors such as password attacks and token theft. It achieves this through the assignment of a password (randomly generated or user-defined) or by supplying principal JWT access tokens. To support testing strategies such as password spraying, BadZure also automatically generates a 'users.txt' file containing the usernames of the created accounts. The credentials or tokens, made available in the output, enable users to step into the shoes of an attacker who is targeting an Azure AD tenant.

### Privilege Escalation

BadZure crafts three privilege escalation attack vectors by simulating service principal abuse scenarios. It achieves this by intentionally introducing misconfigurations caused by Azure AD roles, Graph permissions and application ownerships. A BloodHound-generated graph, showcasing the attack paths BadZure creates, is shown below.

![](img/attack_paths.png)

## Demo

[![BadZure](https://img.youtube.com/vi/7IdyU7tQgww/0.jpg)](https://www.youtube.com/watch?v=7IdyU7tQgww)


## Quick Start Guide

### Create an Azure AD Tenant 

[Creating an Azure subscription](https://learn.microsoft.com/en-us/training/modules/create-an-azure-account/1-introduction) will also provide you an Azure AD tenant. 

**Note:** Utilizing BadZure within your Azure subscription won't lead to any additional costs as it only requires an [Azure AD Free license](https://azure.microsoft.com/en-us/free/).

### Create a new Global Administrator

[Assign Azure AD roles to users](https://learn.microsoft.com/en-us/azure/active-directory/roles/manage-roles-portal)


### Install Dependencies

````
Install-Module Microsoft.Graph -Scope CurrentUser
````

### Clone Repository and Import Script

````
git clone https://github.com/mvelazc0/BadZure
cd BadZure
. ./Invoke-BadZure.ps1
````
### Set up AzureAD with BadZure

````
# Get Help Menu
Get-Help Invoke-BadZure -Detailed

# Populate a tenant and configure all attack paths with verbose logging
# Note: Authenticate with the new global administrator created in the same directory. 
Invoke-BadZure -Build -Verbose -LoginTenantId "abcd1234-abcd-1234-abcd-1234abcd1234"

# Populate a tenant and configure a random attack path
Invoke-BadZure -Build $RandomAttackPath -LoginTenantId "abcd1234-abcd-1234-abcd-1234abcd1234"

# Populate a tenant, configure all attack paths and use a custom password for initial access
Invoke-BadZure -Build -Password Summer2023! -LoginTenantId "abcd1234-abcd-1234-abcd-1234abcd1234"

# Populate a tenant, configure a random attack path and provide JWT access tokens for initial access
Invoke-BadZure -Build -RandomAttackPath -Token -LoginTenantId "abcd1234-abcd-1234-abcd-1234abcd1234"

# Populate a tenant without attack paths
Invoke-BadZure -Build -NoAttackPaths -LoginTenantId "abcd1234-abcd-1234-abcd-1234abcd1234"

````

### Experiment

* Simulate attacks
* Review resulting telemetry

### Purge AzureAD with BadZure

````
# Destroy all created identities
Invoke-BadZure -Destroy -Verbose -LoginTenantId "abcd1234-abcd-1234-abcd-1234abcd1234"
````

## Author

* **Mauricio Velazco** - [@mvelazco](https://twitter.com/mvelazco)

## References

* [Cloud Katana](https://github.com/Azure/Cloud-Katana) by [Roberto Rodriguez](https://twitter.com/Cyb3rWard0g)
* [AADInternals](https://github.com/Gerenios/AADInternals) by [Nestori Syynimaa](https://twitter.com/DrAzureAD)
* [Azure Attack Paths](https://cloudbrothers.info/en/azure-attack-paths/) by [Fabian Bader](https://twitter.com/fabian_bader)
* [ROADtools](https://github.com/dirkjanm/ROADtools) by [Dirkjan Mollema](https://twitter.com/_dirkjan)
* [PurpleCloud](https://github.com/iknowjason/PurpleCloud) by [Jason Ostrom](https://twitter.com/securitypuck) 
* [Azure AD - Attack and Defense Playbook](https://github.com/Cloud-Architekt/AzureAD-Attack-Defense) by [Sami Lamppu](https://twitter.com/samilamppu) and [Thomas Naunheim](https://twitter.com/Thomas_Live)
* [BloodHound/AzureHound](https://github.com/BloodHoundAD/AzureHound) by [Andy Robbins](https://twitter.com/_wald0) 
* Blog posts, talks and tools by [@Haus3c](https://twitter.com/Haus3c), [@kfosaaen](https://twitter.com/kfosaaen), [@inversecos](https://twitter.com/inversecos) and others.

## License

This project is licensed under the Apache 2.0 License - see the [LICENSE](LICENSE) file for details
