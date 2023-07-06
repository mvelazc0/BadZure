# BadZure

BadZure is a PowerShell script that leverages the Microsoft Graph SDK to orchestrate the setup of Azure Active Directory environments, populating them with diverse entities while also introducing common security misconfigurations to create vulnerable Azure AD tenants with multiple attack paths.

Specifically, BadZure automates the process of creating multiple entities such as: users, groups, application registrations, service principals and administrative units. To simulate common security misconfigurations in real environments, it randomly assigns Azure AD roles, Graph permissions and application ownership privileges to randomly picked security principals enabling the creation of unique attack paths within a controlled and vulnerable tenant. 

BadZure is designed for security practitioners with an interest in exploring and understanding Azure AD security. The key advantage of BadZure lies in its ability to rapidly build and destroy populated and randomly generated vulnerable Azure AD tenants facilitating iterative red and blue experimentation. 

in an existing azure ad tenant.

## Goals / Use Cases

It enables  detection engineering teams to collect attack telemetry, develop detection strategies for safeguarding their Azure AD environments against real-world attacks. 

An Azure AD tenant populated with BadZure enables red and blue teams to:

* Experiment with common Azure AD attack vectors (for ideas => [AzureAD Attack and Defense Playbook](https://github.com/Cloud-Architekt/AzureAD-Attack-Defense))
* Obtain attack telemetry to build, test and enhance detection controls
* Execute purple team exercises in a safe setting
* Faciliate hands-on Azure AD security training

## Attack Paths

### Initial Access

BadZure facilitates initial access by simulating account takover vectors such as password attacks and token theft scenarios. It achieves this through the assignment of a known password (randomly generated or user-defined) or by supplying access tokens to randomly selected users with special privileges. These users serve as the initial access vector, creating a realistic starting point for security exploration.

### Privilege Escalation

BadZure crafts privilege escalation attack vectors by simulating service principal abuse scenarios. It achieves this by intentionally introducing misconfigurations, typically exploited in real-world threat scenarios. A BloodHound-generated graph, showcasing the scenarios BadZure simulates, is shown below.

![](img/attack_paths.png)

## Quick Start Guide

### Create an Azure AD Tenant 

[Creating an Azure subscription](https://learn.microsoft.com/en-us/training/modules/create-an-azure-account/1-introduction) will also provide you an Azure AD tenant. 

### Install Dependencies

````
Install-Module Microsoft.Graph -Scope CurrentUser
````

### Clone Repository and Import Module

````
git clone https://github.com/mvelazc0/BadZure
cd BadZure
. ./Invoke-BadZure.ps1
````
### Run BadZure

````
# Get Help Menu
Invoke-BadZure

# Populate a tenant and enable attack paths
Invoke-BadZure -Build

# Populate a tenant without attack paths
Invoke-BadZure -Build -NoAttackPaths

# Destroy all created identities
Invoke-BadZure -Destroy
````

## Author

* **Mauricio Velazco** - [@mvelazco](https://twitter.com/mvelazco)

## License

This project is licensed under the Apache 2.0 License - see the [LICENSE](LICENSE) file for details
