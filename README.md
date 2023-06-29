# BadZure

BadZure is a PowerShell script that leverages the Microsft Graph SDK to automate the process of populating an Azure Active Directory environment with various entities such as users, groups, applications, and service principals. To simulate common security misconfigurations in real environments, it randomly assigns Azure AD Roles, Graph API permissions and application ownership privileges to users and service principals enabling the creation of unique attack paths within a controlled and vulnerable tenant. 

BadZure is designed for security practitioners with an interest in exploring and understanding Azure AD security. The key advantage of BadZure lies in its ability to rapidly build and destroy these populated and vulnerable Azure AD tenants facilitating iterative learning as well as experimentation. It empowers users to learn, test, and develop detection strategies for safeguarding their Azure AD environments against real-world attacks. 

## Goals / Use Cases

An Azure AD tenant populated with BadZure enables red and blue teams to:

* Experiment with common Azure AD attack vectors
* Obtain attack telemetry to build, test and enhance detection controls
* Execute purple team exercises in a safe setting
* Faciliate hands-on Azure AD security training

## Attack Paths

BadZure automatically creates two unique attack paths that leverage Service Principal privilege escalation as shown below.

![](images/attack_paths.png)



## Quick Start Guide

### Create an Azure AD Tenant 

[Creating an Azure subscription](https://learn.microsoft.com/en-us/training/modules/create-an-azure-account/1-introduction) will also provide you an Azure AD tenant. Creating a
subscription will require you to submit a valid credit card. However, if you
only leverage Azure AD and not use any other Azure services like VMs or storage,
there will be no charges to your credit card.

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
