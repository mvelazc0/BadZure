import os
import json
import yaml
import click
from python_terraform import Terraform
from src.constants import ENTRA_ROLES, GRAPH_API_PERMISSIONS, HIGH_PRIVILEGED_ENTRA_ROLES, HIGH_PRIVILEGED_GRAPH_API_PERMISSIONS
import random
import string
import requests
import time
import logging

# Ensure AZURE_CONFIG_DIR is set the Azure CLI config directory
os.environ['AZURE_CONFIG_DIR'] = os.path.expanduser('~/.azure')



TERRAFORM_DIR = os.path.join(os.path.dirname(__file__), 'terraform')
tf = Terraform(working_dir=TERRAFORM_DIR)

banner = """                                  

            ____            _ ______              
            |  _ \          | |___  /              
            | |_) | __ _  __| |  / /_   _ _ __ ___ 
            |  _ < / _` |/ _` | / /| | | | '__/ _ \\
            | |_) | (_| | (_| |/ /_| |_| | | |  __/
            |____/ \__,_|\__,_/_____\__,_|_|  \___|
                                                    
                                                                                                                                    
                                by Mauricio Velazco                                                      
                                @mvelazco

"""

extra = {'include_timestamp': False}

def setup_logging(level, include_timestamp=True):

    custom_formats = {
        logging.INFO: "{timestamp}[+] %(message)s",
        logging.ERROR: "{timestamp}[!] %(message)s",
        "DEFAULT": "{timestamp}[%(levelname)s] - %(message)s",
    }
    custom_time_format = "%Y-%m-%d %H:%M:%S"

    class CustomFormatter(logging.Formatter):
        def __init__(self, fmt=None, datefmt=None, style='%'):
            super().__init__(fmt, datefmt=custom_time_format, style=style)

        def format(self, record):
            if hasattr(record, 'include_timestamp') and not record.include_timestamp:
                timestamp = ""
            else:
                timestamp = f"{self.formatTime(record, self.datefmt)} "

            # Replace the {timestamp} placeholder in the format with the actual timestamp or empty string
            self._style._fmt = custom_formats.get(record.levelno, custom_formats["DEFAULT"]).format(timestamp=timestamp)
            return super().format(record)

    root_logger = logging.getLogger()
    root_logger.handlers.clear()
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(CustomFormatter())
    root_logger.addHandler(console_handler)
    root_logger.setLevel(level)
    

def parse_terraform_output(output):
    # Parse the Terraform state output and extract the essential information
    resources = []

    try:
        state = json.loads(output)
        for module in state.get('values', {}).get('root_module', {}).get('resources', []):
            resource_type = module.get('type')
            resource_name = module.get('name')
            if resource_type == 'azuread_domains' or resource_type == 'azuread_administrative_unit_member' or resource_type == 'azuread_group_member' or resource_type == 'azuread_directory_role_assignment':
                #print(module.get('values', {}))                         
                continue
            if resource_type == 'azuread_user':
                key_attr = module.get('values', {}).get('user_principal_name')
            elif resource_type == 'azuread_group':
                key_attr = module.get('values', {}).get('display_name')
            elif resource_type == 'azuread_application_registration':
                key_attr = module.get('values', {}).get('display_name')
            elif resource_type == 'azuread_administrative_unit':
                key_attr = module.get('values', {}).get('display_name')          
            elif resource_type == 'azuread_service_principal':
                key_attr = module.get('values', {}).get('id')
                #print(module.get('values', {}))                         
            else:
                key_attr = "N/A"

            #resources.append(f"Resource Type: {resource_type}, Name: {resource_name}, Key Attribute: {key_attr}")
            resources.append(f"Resource Type: {resource_type}, Identifier: {key_attr}")

    except json.JSONDecodeError:
        logging.error("Failed to parse Terraform state output")
    
    return resources    

def write_users_to_file(users, domain, file_path):
    with open(file_path, 'w') as file:
        for user in users.values():
            file.write(f"{user['user_principal_name']}@{domain}\n")

def get_ms_token_username_pass(tenant_id, username, password, scope):

    # https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth-ropc

    #logging.info("Using resource owner password OAuth flow to obtain a token")

    token_url = f'https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token'

    full_scope = f'{scope} offline_access'

    token_data = {

        'client_id': '1950a258-227b-4e31-a9cf-717495945fc2', # Microsoft Azure PowerShell
        #'client_id': '00b41c95-dab0-4487-9791-b9d2c32c80f2',  # Office 365 Management. Works to read emails Graph and EWS.
        #'client_id': 'd3590ed6-52b3-4102-aeff-aad2292ab01c',  # Microsoft Office. Also works to read emails Graph and EWS.
        #'client_id': '00000002-0000-0ff1-ce00-000000000000', # Office 365 Exchange Online
        #'client_id': '00000006-0000-0ff1-ce00-000000000000', # Microsoft Office 365 Portal
        #'client_id': 'fb78d390-0c51-40cd-8e17-fdbfab77341b', # Microsoft Exchange REST API Based Powershell
        # 'client_id': '00000003-0000-0000-c000-000000000000', # Microsoft Graph
        #'client_id': 'de8bc8b5-d9f9-48b1-a8ad-b748da725064', # Graph Explorer
        #'client_id': '14d82eec-204b-4c2f-b7e8-296a70dab67e', # Microsoft Graph Command Line Tools	

        'grant_type': 'password',
        'username': username,
        'password': password,
        'scope': full_scope
    }

    response = requests.post(token_url, data=token_data)
    refresh_token = response.json().get('refresh_token')
    access_token = response.json().get('access_token')
    
    if refresh_token and access_token:
        return {'access_token': access_token, 'refresh_token': refresh_token}
    else:
        logging.error (f'Error obtaining token. Http response: {response.status_code}')
        logging.error (response.text)

def create_attack_path(attack_patch_config, users, applications, domain, password):
 
    app_owner_assignments = {}  
    user_role_assignments = {}
    app_role_assignments = {}  
    app_api_permission_assignments = {}
    
    # Pick a random application registration
    app_keys = list(applications.keys())
    random_app = random.choice(app_keys)
    #app_id = applications[random_app]['display_name']
    
    attack_path_id = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
    key = f"attack-path-{attack_path_id}"

    # Pick a random user
    user_keys = list(users.keys())
    random_user = random.choice(user_keys)
    user_principal_name = f"{users[random_user]['user_principal_name']}@{domain}"
    password = users[random_user]['password']

    if attack_patch_config['scenario'] == "direct":
        
        initial_access_user = {
        "user_principal_name": user_principal_name,
        "password": password
        }
        
    elif attack_patch_config['scenario'] == "helpdesk":
        
        helpdesk_admin_role_id = "729827e3-9c14-49f7-bb1b-9608f156bbb8"  # ID for "Helpdesk Administrator"
        second_random_user = random.choice(user_keys)
        second_user_principal_name = f"{users[second_random_user]['user_principal_name']}@{domain}"        
        second_user_password = users[second_random_user]['password']

        initial_access_user = {    
            "user_principal_name": second_user_principal_name,
            "password": second_user_password
        }
        
        user_role_assignments[key]  = {
            'user_name': second_random_user,
            'role_definition_id': helpdesk_admin_role_id        
    } 
    
    app_owner_assignments[key]  = {
        'app_name': random_app,            
        'user_principal_name': user_principal_name,        
    }    

    
    if attack_patch_config['method'] == "AzureADRole":
        
        
        if attack_patch_config['entra_role'] != 'random':
            
            privileged_role_id = attack_patch_config['entra_role']
        
        else:
            privileged_role_id = random.choice(list(HIGH_PRIVILEGED_ENTRA_ROLES.values()))
            
        # Assign "Privileged Role Administrator" role to the application
        #privileged_role_id = "e8611ab8-c189-46e8-94e1-60213ab1f814"  # ID for "Privileged Role Administrator"
        
        app_role_assignments[key]  = {
            'app_name': random_app,
            'role_id': privileged_role_id,        
        }     

    elif attack_patch_config['method'] == "GraphAPIPermission":
        
        if attack_patch_config['app_role'] != 'random':
            
            api_permission_id = attack_patch_config['app_role']
        
        else:
            api_permission_id = random.choice([permission["id"] for permission in HIGH_PRIVILEGED_GRAPH_API_PERMISSIONS.values()])
        
        # Assign API permission to the application
        #api_permission_id = "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8"  # ID for "RoleManagement.ReadWrite.Directory"       
        
        app_api_permission_assignments[key]  = {
            'app_name': random_app,
            'api_permission_id': api_permission_id,
        }    

    return initial_access_user, app_owner_assignments, user_role_assignments, app_role_assignments, app_api_permission_assignments

def load_config(file_path):
    """Load and return the configuration from a YAML file."""
    try:
        with open(file_path, 'r') as file:
            config = yaml.safe_load(file)
            return config
    except FileNotFoundError:
        #logging.error(f"Configuration file not found at: {file_path}")
        exit(1)
    except yaml.YAMLError as e:
        #logging.error(f"Error parsing the YAML file: {e}")
        exit(1)

def create_random_assignments(users, groups, administrative_units, applications):

    user_group_assignments = {}
    user_au_assignments = {}
    user_role_assignments = {}
    app_role_assignments = {}
    app_api_permission_assignments={}

    user_keys = list(users.keys())
    group_keys = list(groups.keys())
    au_keys = list(administrative_units.keys())
    app_keys = list(applications.keys())

    # Calculate subset size as one-third of the total users
    user_subset_size = max(1, len(user_keys) // 3)
 
    # Randomly select a subset of users for group assignments   
    logging.info("Creating random user to group assignments")
    group_assigned_users = random.sample(user_keys, user_subset_size)
    for user in group_assigned_users:
        if groups:
            group = random.choice(group_keys)
            assignment_key = f"{user}-{group}"
            user_group_assignments[assignment_key] = {
                'user_name': user,
                'group_name': group
            }    
            
    # Randomly select a subset of users for administrative unit assignments
    logging.info("Creating random user to administrative unit assignments")
    au_assigned_users = random.sample(user_keys, user_subset_size)
    for user in au_assigned_users:
        if administrative_units:
            au = random.choice(au_keys)
            assignment_key = f"{user}-{au}"
            user_au_assignments[assignment_key] = {
                'user_name': user,
                'administrative_unit_name': au
            }

    # Randomly select a subset of users for role assignments
    logging.info("Creating random azure ad role assignments to users")
    role_assigned_users = random.sample(user_keys, user_subset_size)
    for user in role_assigned_users:
        if ENTRA_ROLES:
            role_name = random.choice(list(ENTRA_ROLES.keys()))
            role_id = ENTRA_ROLES[role_name]
            assignment_key = f"{user}-{role_name}"
            user_role_assignments[assignment_key] = {
                'user_name': user,
                'role_definition_id': role_id
            }

    app_subset_size = max(1, len(app_keys) // 2)
    role_assigned_apps = random.sample(app_keys, app_subset_size)

    logging.info("Creating random azure ad role assignments to applications")
    for app in role_assigned_apps:
        if ENTRA_ROLES:
            role_name = random.choice(list(ENTRA_ROLES.keys()))
            role_id = ENTRA_ROLES[role_name]
            assignment_key = f"{app}-{role_name}"
            app_role_assignments[assignment_key] = {
                'app_name': app,
                'role_id': role_id
            }


    logging.info("Creating random Graph api permission assignments to applications")
    api_assigned_apps = random.sample(app_keys, app_subset_size)
    for app in api_assigned_apps:
        if GRAPH_API_PERMISSIONS:
            api_name = random.choice(list(GRAPH_API_PERMISSIONS.keys()))
            api_permission_id = GRAPH_API_PERMISSIONS[api_name]['id']
            assignment_key = f"{app}-{api_name}"
            app_api_permission_assignments[assignment_key] = {
                'app_name': app,
                'api_permission_id': api_permission_id,
            }

    return user_group_assignments, user_au_assignments, user_role_assignments, app_role_assignments, app_api_permission_assignments

def generate_random_password(length=15):
    if length < 8:
        raise ValueError("Password length must be at least 8 characters")

    password = [
        random.choice(string.ascii_uppercase),
        random.choice(string.ascii_lowercase),
        random.choice(string.digits),
        random.choice(string.punctuation)
    ]

    password += random.choices(string.ascii_letters + string.digits + string.punctuation, k=length - 4)
    random.shuffle(password)
    return ''.join(password)

def read_lines_from_file(file_path):
    with open(file_path, mode='r') as file:
        return [line.strip() for line in file.readlines()]    

def generate_user_details(first_names_file, last_names_file, number_of_users):
    
    first_names = read_lines_from_file(first_names_file)
    last_names = read_lines_from_file(last_names_file)
    users = {}
    
    for _ in range(number_of_users):
        first_name = random.choice(first_names)
        last_name = random.choice(last_names)
        key = f"{first_name}.{last_name}".lower()
        users[key] = {
            'user_principal_name': key,
            'display_name': f"{first_name.capitalize()} {last_name.capitalize()}",
            'mail_nickname': key,
            'password': generate_random_password()
        }
    
    return users

def generate_group_details(file_path, number_of_groups):
    
    groups = {}

    group_names = read_lines_from_file(file_path)
        
    selected_groups = random.sample(group_names, number_of_groups)
    
    for group_name in selected_groups:
        groups[group_name] = {
            'display_name': group_name
        }
    
    return groups

def generate_app_details(prefix_file, core_file, suffix_file, number_of_names):
    
    prefixes = read_lines_from_file(prefix_file)
    core_names = read_lines_from_file(core_file)
    suffixes = read_lines_from_file(suffix_file)
    
    app_names = set()
    
    while len(app_names) < number_of_names:
        prefix = random.choice(prefixes)
        core_name = random.choice(core_names)
        suffix = random.choice(suffixes) if random.random() > 0.5 else ""
        app_name = f"{prefix}{core_name}{suffix}"
        app_names.add(app_name)
    
    applications = {}
    for name in app_names:
        applications[name] = {
            'display_name': name
        }
    
    return applications

def generate_administrative_units_details(file_path, number_of_aunits):
    
    aunits = {}

    aunit_names = read_lines_from_file(file_path)
        
    selected_groups = random.sample(aunit_names, number_of_aunits)
    
    for group_name in selected_groups:
        aunits[group_name] = {
            'display_name': group_name
        }
    
    return aunits
                   
@click.group()
def cli():
    pass

@cli.command()
@click.option('--config', type=click.Path(exists=True), default='badzure.yml', help="Path to the configuration YAML file")
@click.option('--verbose', is_flag=True, help="Enable verbose output")
def build(config, verbose):
    """Create resources and attack paths"""
    azure_config_dir = os.path.expanduser('~/.azure')
    os.environ['AZURE_CONFIG_DIR'] = azure_config_dir
    
    # Load configuration
    logging.info(f"Loading BadZure configuration from {config}")
    config = load_config(config)
    tenant_id = config['tenant']['tenant_id']
    domain = config['tenant']['domain']
    
    max_users = config['tenant']['users']
    max_groups = config['tenant']['groups']
    max_apps =  config['tenant']['applications']
    max_aunits =  config['tenant']['administrative_units']
    

    # Generate random users
    logging.info(f"Generating {max_users} random users")
    users = generate_user_details('entity_data/first-names.txt', 'entity_data/last-names.txt', max_users)

    # Generate random groups
    logging.info(f"Generating {max_groups} random groups")
    groups = generate_group_details('entity_data/group-names.txt', max_groups)

    # Generate random application registrations
    logging.info(f"Generating {max_apps} random application registrations/service principals")
    applications = generate_app_details('entity_data/app-prefixes.txt', 'entity_data/app-core-names.txt','entity_data/app-sufixes.txt', max_apps)

    # Generate random administratuve units
    logging.info(f"Generating {max_aunits} random administrative units")
    administrative_units = generate_administrative_units_details('entity_data/administrative-units.txt', max_aunits)

     # Create random assignments
    #logging.info("Creating random assignments for groups, administrative units, azure ad roles and graph api permissions")
    
    user_group_assignments, user_au_assignments, user_role_assignments, app_role_assignments, app_api_permission_assignments = create_random_assignments(users, groups, administrative_units, applications)
    
    attack_path_application_owner_assignments, attack_path_user_role_assignments, attack_path_app_role_assignments, attack_path_app_api_permission_assignments = {}, {}, {}, {}
    
    user_creds = {}
  
    for attack_path in config['attack_paths']:
        
        if config['attack_paths'][attack_path]['enabled']:
                        
            #password = config['attack_paths'][attack_path]['password']
            logging.info(f"Creating assignments for attack path '{attack_path}'")
            initial_access, ap_app_owner_assignments, ap_user_role_assignments, ap_app_role_assignments, ap_app_api_permission_assignments = create_attack_path(config['attack_paths'][attack_path], users, applications, domain, "test")
            attack_path_application_owner_assignments = {**attack_path_application_owner_assignments, **ap_app_owner_assignments}
            attack_path_user_role_assignments = {**attack_path_user_role_assignments, **ap_user_role_assignments}
            attack_path_app_role_assignments = {**attack_path_app_role_assignments, **ap_app_role_assignments}
            attack_path_app_api_permission_assignments = {**attack_path_app_api_permission_assignments, **ap_app_api_permission_assignments}
            user_creds[attack_path] = initial_access
            #update_password(users, initial_access['user_principal_name'].split('@')[0], password)    
                               
   
    # Prepare Terraform variables
    user_vars = {user['user_principal_name']: user for user in users.values()}
    group_vars = {group['display_name']: group for group in groups.values()}
    application_vars = {app['display_name']: app for app in applications.values()}
    administrative_unit_vars = {au['display_name']: au for au in administrative_units.values()}

    tf_vars = {
        'tenant_id': tenant_id,
        'domain': domain,
        'users': user_vars,
        'azure_config_dir': azure_config_dir,
        'groups': group_vars,
        'applications': application_vars,
        'administrative_units': administrative_unit_vars,
        'user_group_assignments': user_group_assignments,
        'user_au_assignments': user_au_assignments,
        'user_role_assignments': user_role_assignments,
        'app_role_assignments': app_role_assignments,
        'app_api_permission_assignments' : app_api_permission_assignments,
        'attack_path_application_owner_assignments' : attack_path_application_owner_assignments,
        'attack_path_user_role_assignments' : attack_path_user_role_assignments,
        'attack_path_application_role_assignments' : attack_path_app_role_assignments,
        'attack_path_application_api_permission_assignments' : attack_path_app_api_permission_assignments
    }
    
    # Write the Terraform variables to a file
    logging.info(f"Creating terraform.tfvars.json")
    with open(os.path.join(TERRAFORM_DIR, 'terraform.tfvars.json'), 'w') as f:
        json.dump(tf_vars, f, indent=4)



    # Initialize and apply the Terraform configuration
    logging.info(f"Calling terraform init.")
    return_code, stdout, stderr = tf.init()
    if return_code != 0:
        logging.error(f"Terraform init failed: {stderr}")
        if verbose:
            logging.error(stdout)
            logging.error(stderr)
        return

    logging.info(f"Calling terraform apply to create resources, this may take several minutes ...")
    return_code, stdout, stderr = tf.apply(skip_plan=True, capture_output=not verbose)
    if return_code != 0:
        logging.error(f"Terraform apply failed: {stderr}")
        if verbose:
            logging.error(stdout)
            logging.error(stderr)
        return

    logging.info("Azure AD tenant setup completed with assigned permissions and configurations!")
    write_users_to_file(users, domain, 'users.txt')
    logging.info("Created users.txt file.")
    logging.info("Attack Path Details")

    for attack_path in config['attack_paths']:
        
        if config['attack_paths'][attack_path]['enabled']:
            logging.info(f"*** {attack_path} ***")
            logging.info(f"Initial access user: {user_creds[attack_path]['user_principal_name']}")
            
            if config['attack_paths'][attack_path]['initial_access'] == "password":
                logging.info(f"Password: {user_creds[attack_path]['password']}")
                
            elif config['attack_paths'][attack_path]['initial_access'] == "token":
                logging.info(f"Obtaining tokens...")
                #logging.info(f"Will use {user_creds[attack_path]['user_principal_name']} and {user_creds[attack_path]['password']}")
                tokens = get_ms_token_username_pass(tenant_id, user_creds[attack_path]['user_principal_name'], user_creds[attack_path]['password'], "https://graph.microsoft.com/.default")
                with open("tokens.txt", "a") as file:
                    file.write(f"Attack Path : {attack_path}\n")
                    file.write(f"User : {user_creds[attack_path]['user_principal_name']}\n")
                    file.write(f"Access Token: {tokens['access_token']}\n")
                    file.write(f"Refresh Token: {tokens['refresh_token']}\n")
                logging.info(f"Tokens saved in tokens.txt!.")
                  
    logging.info("Good bye.")
                  
@cli.command()
@click.option('--verbose', is_flag=True, help="Enable verbose output")
def show(verbose):
    """Show all the created resources in the tenant"""

    # Ensure terraform.tfvars.json exists
    tfvars_path = os.path.join(TERRAFORM_DIR, 'terraform.tfvars.json')
    if not os.path.exists(tfvars_path):
        logging.error("Error: terraform.tfvars.json file not found.")
        return

    # Initialize the Terraform configuration
    return_code, stdout, stderr = tf.init()
    if return_code != 0:
        logging.error(f"Terraform init failed: {stderr}")
        return
    
    logging.info(f"Calling terraform show to display the current state ...")

    # Execute the terraform show command
    return_code, stdout, stderr = tf.show(json=True, capture_output=not verbose)

    if return_code != 0:
        logging.error(f"Terraform show failed: {stderr}")
        logging.error(stdout)
        logging.error(stderr)
        return

    if verbose:
        print(stdout)
    else:
        resources = parse_terraform_output(stdout)
        for resource in resources:
            logging.info(resource)
        #logging.info(stdout)

    logging.info("Current state of Azure AD tenant resources displayed successfully.")
    
@cli.command()
@click.option('--verbose', is_flag=True, help="Enable verbose output")
def destroy(verbose):
    """Destroy all created resources in the tenant"""

    # Ensure terraform.tfvars.json exists
    tfvars_path = os.path.join(TERRAFORM_DIR, 'terraform.tfvars.json')
    if not os.path.exists(tfvars_path):
        logging.error("Error: terraform.tfvars.json file not found.")
        return

    # Initialize and destroy the Terraform configuration
    return_code, stdout, stderr = tf.init()
    if return_code != 0:
        logging.error(f"Terraform init failed: {stderr}")
        return
    

    logging.info(f"Calling terraform destroy, this may take several minutes ...")
    #return_code, stdout, stderr = tf.destroy(force=True, input=False, auto_approve=True, capture_output=verbose)
    return_code, stdout, stderr = tf.apply(skip_plan=True, destroy=True, auto_approve=True, capture_output=not verbose)

    if return_code != 0:
        logging.error(f"Terraform apply failed: {stderr}")
        logging.error(stdout)
        logging.error(stderr)
        return

    logging.info("Azure AD tenant resources have been successfully destroyed!")

    # Remove the state files after destroying the resources
    logging.info(f"Deleting terraform state files ")
    for file in ["terraform.tfstate", "terraform.tfstate.backup", "terraform.tfvars.json"]:
        try:
            os.remove(os.path.join(TERRAFORM_DIR, file))
        except FileNotFoundError:
            pass

    logging.info("Good bye.")

if __name__ == '__main__':
    
    setup_logging(logging.INFO)
    print (banner)
    time.sleep(2)
    cli()
