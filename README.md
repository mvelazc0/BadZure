# BadZure

BadZure is a PowerShell script that leverages the Microsft Graph SDK to automate the process of populating an Azure Active Directory environment with various entities such as users, groups, applications, and service principals. It then randomly assigns Azure AD Roles and API Graph permissions to users and service principals enabling the creation of simulated and unique attack paths within a controlled and vulnerable tenant. 

BadZure is designed for security practitioners with an interest in exploring and understanding Azure AD security. The core value BadZure lies in its ability to build and destroy these populated and vulnerable Azure AD tenants rapidly facilitating iterative learning as well as experimentation. It empowers users to learn, test, and develop detection strategies for safeguarding their Azure AD environments against real-world attacks. 

## Goals / Use Cases

And Azure AD tenant populated with BadZure enables red and blue teams to:

* Experiment with Azure AD attack vectors
* Obtain attack telemetry to build, test and enhance detection controls
* Azure AD Capture The Flag scenarios.

## Quick Start Guide

### Clone Repo and Import Module

````
git clone https://github.com/mvelazc0/BadZure
. .\Invoke-BadZure.ps1
Invoke-BadZure
````
### Run BadZure

````
Invoke-BadZure
Invoke-BadZure -Build
````

## Authors

* **Mauricio Velazco** - [@mvelazco](https://twitter.com/mvelazco)


## License

This project is licensed under the Apache 2.0 License - see the [LICENSE](LICENSE) file for details