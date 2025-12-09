import os
import json
import yaml
import click
from python_terraform import Terraform
from src.constants import ENTRA_ROLES, GRAPH_API_PERMISSIONS, HIGH_PRIVILEGED_ENTRA_ROLES, HIGH_PRIVILEGED_GRAPH_API_PERMISSIONS
from src.crypto import generate_certificate_and_key
import src.utils as utils
import random
import string
import requests
import time
import logging
import base64

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
            

def create_kv_attack_path_flexible(attack_patch_config, applications, keyvaults, users, service_principals, virtual_machines):

    attack_path_kv_abuse_assignments = {}
    app_role_assignments = {}
    app_api_permission_assignments = {}
    vm_contributor_assignments = {}

    attack_path_id = ''.join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=6))
    key = f"attack-path-{attack_path_id}"

    # Pick a random application
    app_keys = list(applications.keys())
    random_app = random.choice(app_keys)

    # Pick a random Key Vault
    kv_keys = list(keyvaults.keys())
    random_kv = random.choice(kv_keys)
    
    principal_type = attack_patch_config['principal_type']

    if principal_type == "user":
        principal_keys = list(users.keys())
        random_principal = random.choice(principal_keys)
    elif principal_type == "service_principal":
        principal_keys = list(service_principals.keys())
        random_principal = random.choice(principal_keys)
    elif principal_type == "managed_identity":
        principal_keys = list(virtual_machines.keys())
        random_principal = random.choice(principal_keys)
        
        # When using managed identity, assign a user with VM Contributor role
        user_keys = list(users.keys())
        random_user = random.choice(user_keys)
        vm_contributor_assignments[key] = {
            'user_name': random_user,
            'virtual_machine': random_principal
        }

    attack_path_kv_abuse_assignments[key] = {
        "key_vault": random_kv,
        "principal_type": principal_type,
        "principal_name": random_principal,  # Can be user, service principal, or VM
        "virtual_machine": random_principal if principal_type == "managed_identity" else None,
        "app_name": random_app,
        'initial_access_user': random_user if principal_type == "managed_identity" else None
    }
    
    if attack_patch_config['method'] == "AzureADRole":
    
        if isinstance(attack_patch_config['entra_role'], list):
            role_ids = attack_patch_config['entra_role']
        elif attack_patch_config['entra_role'] == 'random':
            role_ids = [random.choice(list(HIGH_PRIVILEGED_ENTRA_ROLES.values()))]
        else:
            role_ids = [attack_patch_config['entra_role']]

        app_role_assignments[key] = {
            'app_name': random_app,
            'role_ids': role_ids
        }

    elif attack_patch_config['method'] == "GraphAPIPermission":
        
        if isinstance(attack_patch_config['app_role'], list):
            api_permission_ids = attack_patch_config['app_role']
        elif attack_patch_config['app_role'] != 'random':
            api_permission_ids = [attack_patch_config['app_role']]
        else:
            api_permission_ids = [random.choice(
                [perm["id"] for perm in HIGH_PRIVILEGED_GRAPH_API_PERMISSIONS.values()]
            )]
        
        app_api_permission_assignments[key] = {
            'app_name': random_app,
            'api_permission_ids': api_permission_ids,
        }

    return attack_path_kv_abuse_assignments, app_role_assignments, app_api_permission_assignments, vm_contributor_assignments

def create_storage_attack_path_flexible(attack_patch_config, applications, storage_accounts, users, service_principals, virtual_machines):

    attack_path_storage_abuse_assignments = {}
    app_role_assignments = {}
    app_api_permission_assignments = {}
    vm_contributor_assignments = {}

    attack_path_id = ''.join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=6))
    key = f"attack-path-{attack_path_id}"

    # Pick a random application
    app_keys = list(applications.keys())
    random_app = random.choice(app_keys)

    # Pick a random Storage Account
    sa_keys = list(storage_accounts.keys())
    random_sa = random.choice(sa_keys)
    
    principal_type = attack_patch_config['principal_type']
    
    # Generate a self-signed certificate
    cert_path, key_path = generate_certificate_and_key(random_app)

    if principal_type == "user":
        principal_keys = list(users.keys())
        random_principal = random.choice(principal_keys)
    elif principal_type == "service_principal":
        principal_keys = list(service_principals.keys())
        random_principal = random.choice(principal_keys)
    elif principal_type == "managed_identity":
        principal_keys = list(virtual_machines.keys())
        random_principal = random.choice(principal_keys)
        
        # When using managed identity, assign a user with VM Contributor role
        user_keys = list(users.keys())
        random_user = random.choice(user_keys)
        vm_contributor_assignments[key] = {
            'user_name': random_user,
            'virtual_machine': random_principal
        }

    attack_path_storage_abuse_assignments[key] = {
        
        "app_name": random_app ,
        "storage_account": random_sa,
        "principal_type": principal_type,
        "principal_name": random_principal,  # Can be user, service principal, or VM
        "virtual_machine": random_principal if principal_type == "managed_identity" else None,
        'certificate_path': cert_path,
        'private_key_path': key_path,
        'initial_access_user': random_user if principal_type == "managed_identity" else None
    }

    if attack_patch_config['method'] == "AzureADRole":
    
        if isinstance(attack_patch_config['entra_role'], list):
            role_ids = attack_patch_config['entra_role']
        elif attack_patch_config['entra_role'] == 'random':
            role_ids = [random.choice(list(HIGH_PRIVILEGED_ENTRA_ROLES.values()))]
        else:
            role_ids = [attack_patch_config['entra_role']]

        app_role_assignments[key] = {
            'app_name': random_app,
            'role_ids': role_ids
        }

    elif attack_patch_config['method'] == "GraphAPIPermission":
        
        if isinstance(attack_patch_config['app_role'], list):
            api_permission_ids = attack_patch_config['app_role']
        elif attack_patch_config['app_role'] != 'random':
            api_permission_ids = [attack_patch_config['app_role']]
        else:
            api_permission_ids = [random.choice(
                [perm["id"] for perm in HIGH_PRIVILEGED_GRAPH_API_PERMISSIONS.values()]
            )]
        
        app_api_permission_assignments[key] = {
            'app_name': random_app,
            'api_permission_ids': api_permission_ids,
        }

    return attack_path_storage_abuse_assignments, app_role_assignments, app_api_permission_assignments, vm_contributor_assignments


def create_sp_attack_path(attack_patch_config, users, applications, domain, password):
 
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
    
    scenario = attack_patch_config.get('scenario', 'direct') 

    if scenario == "direct":
        
        initial_access_user = {
        "user_principal_name": user_principal_name,
        "password": password
        }
        
    elif scenario == "helpdesk":
        
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
    
        if isinstance(attack_patch_config['entra_role'], list):
            role_ids = attack_patch_config['entra_role']
        elif attack_patch_config['entra_role'] == 'random':
            role_ids = [random.choice(list(HIGH_PRIVILEGED_ENTRA_ROLES.values()))]
        else:
            role_ids = [attack_patch_config['entra_role']]

        app_role_assignments[key] = {
            'app_name': random_app,
            'role_ids': role_ids
        }

    elif attack_patch_config['method'] == "GraphAPIPermission":
        
        if isinstance(attack_patch_config['app_role'], list):
            api_permission_ids = attack_patch_config['app_role']
        elif attack_patch_config['app_role'] != 'random':
            api_permission_ids = [attack_patch_config['app_role']]
        else:
            api_permission_ids = [random.choice(
                [perm["id"] for perm in HIGH_PRIVILEGED_GRAPH_API_PERMISSIONS.values()]
            )]
        
        app_api_permission_assignments[key] = {
            'app_name': random_app,
            'api_permission_ids': api_permission_ids,
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
        logging.error(f"Error parsing the YAML file: {e}")
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

def generate_resource_groups_details(file_path, number_of_rgs):
    
    rgs = {}
    
    rg_names = read_lines_from_file(file_path)
    random_rgs = random.sample(rg_names, number_of_rgs)
    
    for rg in random_rgs:
        rgs[rg] = {
            'name': rg,
            'location': "West US"
        }

    return rgs

def generate_keyvault_details(file_path, number_of_kvs, resource_groups):
    
    kvs = {}

    kv_names = read_lines_from_file(file_path)
    selected_kvs = random.sample(kv_names, number_of_kvs)

    for kv in selected_kvs:
        random_rg = random.choice(list(resource_groups.keys()))
        random_suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=2))
        kvs[kv +"-"+ random_suffix] = {
            'name': kv +"-"+ random_suffix,
            'location': "West US",
            'resource_group_name': random_rg ,
            'sku_name' : "standard"
        }
    
    return kvs

def generate_storage_account_details(file_path, number_of_sas, resource_groups):
    
    sas = {}
    sa_names = read_lines_from_file(file_path)  
    selected_sas = random.sample(sa_names, number_of_sas)  

    for sa in selected_sas:
        random_suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=3))
        unique_sa_name = f"{sa}{random_suffix}" 
        random_rg = random.choice(list(resource_groups.keys())) 

        sas[unique_sa_name] = {
            'name': unique_sa_name.lower(),
            'location': "West US",
            'resource_group_name': random_rg,
            'account_tier': "Standard",
            'account_replication_type': "LRS"
        }

    return sas

def generate_vm_details(file_path, number_of_vms, resource_groups):
    """
    Generate random virtual machine details (Linux & Windows) and assign them to random resource groups.
    """
    vms = {}

    vm_names = read_lines_from_file(file_path)
    selected_vms = random.sample(vm_names, number_of_vms)

    for vm in selected_vms:
        random_rg = random.choice(list(resource_groups.keys()))
        #os_type = random.choice(["Linux", "Windows"])
        os_type = "Linux"
        random_suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=2))
        vm_name = f"{vm}-{random_suffix}"

        vms[vm_name] = {
            "name": vm_name,
            "location": "West US",
            "resource_group_name": random_rg,
            "vm_size": "Standard_D2s_v3",
            "admin_username": "badzureadmin",
            "admin_password": generate_random_password(12),
            "os_type": os_type
        }

    return vms
              
# ============================================================================
# TARGETED MODE FUNCTIONS
# ============================================================================

def validate_targeted_config(config):
    """
    Validates targeted mode configuration.
    Returns: (is_valid, error_messages)
    """
    errors = []
    
    for path_name, path_config in config['attack_paths'].items():
        if not path_config.get('enabled', False):
            continue
            
        # Check entities section exists
        if 'entities' not in path_config:
            errors.append(f"{path_name}: Missing 'entities' section in targeted mode")
            continue
        
        entities = path_config['entities']
        
        # Validate based on privilege_escalation type
        priv_esc = path_config.get('privilege_escalation')
        
        if priv_esc == 'ServicePrincipalAbuse':
            if 'users' not in entities or not entities['users']:
                errors.append(f"{path_name}: ServicePrincipalAbuse requires at least one user")
            if 'applications' not in entities or not entities['applications']:
                errors.append(f"{path_name}: ServicePrincipalAbuse requires at least one application")
                
        elif priv_esc == 'KeyVaultAbuse':
            if 'applications' not in entities or not entities['applications']:
                errors.append(f"{path_name}: KeyVaultAbuse requires at least one application")
            if 'key_vaults' not in entities or not entities['key_vaults']:
                errors.append(f"{path_name}: KeyVaultAbuse requires at least one key_vault")
            if 'resource_groups' not in entities or not entities['resource_groups']:
                errors.append(f"{path_name}: KeyVaultAbuse requires at least one resource_group")
            
            # Validate principal_type requirements
            principal_type = path_config.get('principal_type', 'user')
            if principal_type == 'user' and ('users' not in entities or not entities['users']):
                errors.append(f"{path_name}: principal_type 'user' requires at least one user")
            elif principal_type == 'managed_identity':
                if 'virtual_machines' not in entities or not entities['virtual_machines']:
                    errors.append(f"{path_name}: principal_type 'managed_identity' requires at least one virtual_machine")
                if 'users' not in entities or not entities['users']:
                    errors.append(f"{path_name}: principal_type 'managed_identity' requires at least one user for VM Contributor access")
                
        elif priv_esc == 'StorageAccountAbuse':
            if 'applications' not in entities or not entities['applications']:
                errors.append(f"{path_name}: StorageAccountAbuse requires at least one application")
            if 'storage_accounts' not in entities or not entities['storage_accounts']:
                errors.append(f"{path_name}: StorageAccountAbuse requires at least one storage_account")
            if 'resource_groups' not in entities or not entities['resource_groups']:
                errors.append(f"{path_name}: StorageAccountAbuse requires at least one resource_group")
                
            # Validate principal_type requirements
            principal_type = path_config.get('principal_type', 'user')
            if principal_type == 'user' and ('users' not in entities or not entities['users']):
                errors.append(f"{path_name}: principal_type 'user' requires at least one user")
            elif principal_type == 'managed_identity':
                if 'virtual_machines' not in entities or not entities['virtual_machines']:
                    errors.append(f"{path_name}: principal_type 'managed_identity' requires at least one virtual_machine")
                if 'users' not in entities or not entities['users']:
                    errors.append(f"{path_name}: principal_type 'managed_identity' requires at least one user for VM Contributor access")
    
    return len(errors) == 0, errors


def collect_entities_from_attack_paths(config):
    """
    Collects all entities from enabled attack paths.
    Handles name collisions and returns aggregated entity lists.
    """
    all_entities = {
        'users': [],
        'groups': [],
        'applications': [],
        'administrative_units': [],
        'resource_groups': [],
        'key_vaults': [],
        'storage_accounts': [],
        'virtual_machines': []
    }
    
    seen_names = {
        'users': set(),
        'applications': set(),
        'groups': set(),
        'administrative_units': set(),
        'resource_groups': set(),
        'key_vaults': set(),
        'storage_accounts': set(),
        'virtual_machines': set()
    }
    
    for path_name, path_config in config['attack_paths'].items():
        if not path_config.get('enabled', False):
            continue
        
        entities = path_config.get('entities', {})
        
        # Process each entity type
        for entity_type in all_entities.keys():
            if entity_type in entities:
                for entity in entities[entity_type]:
                    entity_name = entity.get('name', 'random')
                    
                    # Handle random names - always add them (will be generated later)
                    if entity_name == 'random':
                        all_entities[entity_type].append(entity)
                    else:
                        # Check for duplicate specific names
                        if entity_name in seen_names[entity_type]:
                            logging.warning(f"Duplicate {entity_type} name '{entity_name}' found in {path_name}, skipping duplicate")
                            continue
                        
                        seen_names[entity_type].add(entity_name)
                        all_entities[entity_type].append(entity)
    
    return all_entities


def generate_targeted_users(user_specs):
    """Generate users based on targeted specifications."""
    users = {}
    
    for spec in user_specs:
        name = spec.get('name', 'random')
        password_spec = spec.get('password', 'random')
        
        # Generate random name if specified
        if name == 'random':
            first_name = random.choice(read_lines_from_file('entity_data/first-names.txt'))
            last_name = random.choice(read_lines_from_file('entity_data/last-names.txt'))
            name = f"{first_name}.{last_name}".lower()
        
        # Generate random password if specified
        if password_spec == 'random':
            password = generate_random_password()
        else:
            password = password_spec
        
        users[name] = {
            'user_principal_name': name,
            'display_name': name.replace('.', ' ').title(),
            'mail_nickname': name,
            'password': password
        }
    
    return users


def generate_targeted_groups(group_specs):
    """Generate groups based on targeted specifications."""
    groups = {}
    
    for spec in group_specs:
        name = spec.get('name', 'random')
        
        if name == 'random':
            group_names = read_lines_from_file('entity_data/group-names.txt')
            name = random.choice(group_names)
        
        groups[name] = {
            'display_name': name
        }
    
    return groups


def generate_targeted_applications(app_specs):
    """Generate applications based on targeted specifications."""
    applications = {}
    
    for spec in app_specs:
        name = spec.get('name', 'random')
        
        if name == 'random':
            prefixes = read_lines_from_file('entity_data/app-prefixes.txt')
            core_names = read_lines_from_file('entity_data/app-core-names.txt')
            suffixes = read_lines_from_file('entity_data/app-sufixes.txt')
            
            prefix = random.choice(prefixes)
            core_name = random.choice(core_names)
            suffix = random.choice(suffixes) if random.random() > 0.5 else ""
            name = f"{prefix}{core_name}{suffix}"
        
        applications[name] = {
            'display_name': name
        }
    
    return applications


def generate_targeted_administrative_units(au_specs):
    """Generate administrative units based on targeted specifications."""
    aunits = {}
    
    for spec in au_specs:
        name = spec.get('name', 'random')
        
        if name == 'random':
            au_names = read_lines_from_file('entity_data/administrative-units.txt')
            name = random.choice(au_names)
        
        aunits[name] = {
            'display_name': name
        }
    
    return aunits


def generate_targeted_resource_groups(rg_specs):
    """Generate resource groups based on targeted specifications."""
    rgs = {}
    
    for spec in rg_specs:
        name = spec.get('name', 'random')
        location = spec.get('location', 'West US')
        
        if name == 'random':
            rg_names = read_lines_from_file('entity_data/resource-groups.txt')
            name = random.choice(rg_names)
        
        rgs[name] = {
            'name': name,
            'location': location
        }
    
    return rgs


def generate_targeted_key_vaults(kv_specs, resource_groups):
    """Generate key vaults based on targeted specifications."""
    kvs = {}
    
    for spec in kv_specs:
        name = spec.get('name', 'random')
        rg_name = spec.get('resource_group')
        
        if name == 'random':
            kv_names = read_lines_from_file('entity_data/keyvaults.txt')
            base_name = random.choice(kv_names)
            random_suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=2))
            name = f"{base_name}-{random_suffix}"
        
        # Handle "random" resource group reference - use the first available resource group
        if rg_name == 'random':
            if not resource_groups:
                logging.error(f"Key vault '{name}' references 'random' resource group but no resource groups exist")
                continue
            rg_name = list(resource_groups.keys())[0]
            logging.info(f"Key vault '{name}' using resource group '{rg_name}' (resolved from 'random')")
        
        # Validate resource group exists
        if rg_name not in resource_groups:
            logging.error(f"Key vault '{name}' references non-existent resource group '{rg_name}'")
            continue
        
        kvs[name] = {
            'name': name,
            'location': resource_groups[rg_name]['location'],
            'resource_group_name': rg_name,
            'sku_name': 'standard'
        }
    
    return kvs


def generate_targeted_storage_accounts(sa_specs, resource_groups):
    """Generate storage accounts based on targeted specifications."""
    sas = {}
    
    for spec in sa_specs:
        name = spec.get('name', 'random')
        rg_name = spec.get('resource_group')
        
        if name == 'random':
            sa_names = read_lines_from_file('entity_data/storage-accounts.txt')
            base_name = random.choice(sa_names)
            random_suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=3))
            name = f"{base_name}{random_suffix}"
        
        # Handle "random" resource group reference - use the first available resource group
        if rg_name == 'random':
            if not resource_groups:
                logging.error(f"Storage account '{name}' references 'random' resource group but no resource groups exist")
                continue
            rg_name = list(resource_groups.keys())[0]
            logging.info(f"Storage account '{name}' using resource group '{rg_name}' (resolved from 'random')")
        
        # Validate resource group exists
        if rg_name not in resource_groups:
            logging.error(f"Storage account '{name}' references non-existent resource group '{rg_name}'")
            continue
        
        sas[name] = {
            'name': name.lower(),
            'location': resource_groups[rg_name]['location'],
            'resource_group_name': rg_name,
            'account_tier': 'Standard',
            'account_replication_type': 'LRS'
        }
    
    return sas


def generate_targeted_virtual_machines(vm_specs, resource_groups):
    """Generate virtual machines based on targeted specifications."""
    vms = {}
    
    for spec in vm_specs:
        name = spec.get('name', 'random')
        rg_name = spec.get('resource_group')
        os_type = spec.get('os_type', 'Linux')
        
        if name == 'random':
            vm_names = read_lines_from_file('entity_data/virtual-machines.txt')
            base_name = random.choice(vm_names)
            random_suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=2))
            name = f"{base_name}-{random_suffix}"
        
        # Handle "random" resource group reference - use the first available resource group
        if rg_name == 'random':
            if not resource_groups:
                logging.error(f"Virtual machine '{name}' references 'random' resource group but no resource groups exist")
                continue
            rg_name = list(resource_groups.keys())[0]
            logging.info(f"Virtual machine '{name}' using resource group '{rg_name}' (resolved from 'random')")
        
        # Validate resource group exists
        if rg_name not in resource_groups:
            logging.error(f"Virtual machine '{name}' references non-existent resource group '{rg_name}'")
            continue
        
        vms[name] = {
            'name': name,
            'location': resource_groups[rg_name]['location'],
            'resource_group_name': rg_name,
            'vm_size': 'Standard_D2s_v3',
            'admin_username': 'badzureadmin',
            'admin_password': generate_random_password(12),
            'os_type': os_type
        }
    
    return vms


@click.group()
def cli():
    pass

@cli.command()
@click.option('--config', type=click.Path(exists=True), default='badzure.yml', help="Path to the configuration YAML file")
@click.option('--verbose', is_flag=True, help="Enable verbose output")
def build(config, verbose):
    """Create resources and attack paths"""
    
    # Load configuration
    logging.info(f"Loading BadZure configuration from {config}")
    config = load_config(config)
    
    # Detect mode (default to random for backward compatibility)
    mode = config.get('mode', 'random')
    logging.info(f"Running in '{mode}' mode")
    
    if mode == 'targeted':
        # Validate targeted configuration
        is_valid, errors = validate_targeted_config(config)
        if not is_valid:
            logging.error("Configuration validation failed:")
            for error in errors:
                logging.error(f"  - {error}")
            return
        
        # Use targeted mode logic
        build_targeted_mode(config, verbose)
    else:
        # Use existing random mode logic
        build_random_mode(config, verbose)


def create_targeted_attack_path_assignments(config, users, groups, applications, administrative_units,
                                           resource_groups, key_vaults, storage_accounts, virtual_machines, domain):
    """
    Creates attack path assignments using the specified entities from the config.
    """
    assignments = {
        'app_owners': {},
        'user_roles': {},
        'app_roles': {},
        'app_api_permissions': {},
        'kv_abuse': {},
        'storage_abuse': {},
        'vm_contributor': {}
    }
    
    user_creds = {}
    
    for path_name, path_config in config['attack_paths'].items():
        if not path_config.get('enabled', False):
            continue
        
        priv_esc = path_config.get('privilege_escalation')
        entities = path_config.get('entities', {})
        
        # Generate unique attack path ID
        attack_path_id = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
        key = f"attack-path-{attack_path_id}"
        
        if priv_esc == 'ServicePrincipalAbuse':
            # Get first user and first application from entities
            user_list = list(entities.get('users', []))
            if not user_list:
                continue
                
            user_spec = user_list[0]
            user_name = user_spec.get('name', 'random')
            if user_name == 'random':
                # Find the first user that matches this spec
                user_name = list(users.keys())[0]
            
            app_list = list(entities.get('applications', []))
            if not app_list:
                continue
                
            app_spec = app_list[0]
            app_name = app_spec.get('name', 'random')
            if app_name == 'random':
                app_name = list(applications.keys())[0]
            
            scenario = path_config.get('scenario', 'direct')
            method = path_config.get('method')
            
            # Create app owner assignment
            user_principal_name = f"{user_name}@{domain}"
            assignments['app_owners'][key] = {
                'app_name': app_name,
                'user_principal_name': user_principal_name
            }
            
            # Handle helpdesk scenario
            if scenario == 'helpdesk':
                # Need a second user for helpdesk admin
                if len(user_list) > 1:
                    second_user_spec = user_list[1]
                    second_user_name = second_user_spec.get('name', 'random')
                    if second_user_name == 'random':
                        # Get second user from users dict
                        user_keys = list(users.keys())
                        second_user_name = user_keys[1] if len(user_keys) > 1 else user_keys[0]
                else:
                    # Reuse first user
                    logging.warning(f"{path_name}: Helpdesk scenario requires 2 users, only 1 defined. Reusing first user.")
                    second_user_name = user_name
                
                helpdesk_admin_role_id = "729827e3-9c14-49f7-bb1b-9608f156bbb8"
                assignments['user_roles'][key] = {
                    'user_name': second_user_name,
                    'role_definition_id': helpdesk_admin_role_id
                }
                
                user_creds[path_name] = {
                    'user_principal_name': f"{second_user_name}@{domain}",
                    'password': users[second_user_name]['password']
                }
            else:
                user_creds[path_name] = {
                    'user_principal_name': user_principal_name,
                    'password': users[user_name]['password']
                }
            
            # Assign privileges to application
            if method == 'AzureADRole':
                entra_role = path_config.get('entra_role')
                if entra_role == 'random':
                    role_ids = [random.choice(list(HIGH_PRIVILEGED_ENTRA_ROLES.values()))]
                elif isinstance(entra_role, list):
                    role_ids = entra_role
                else:
                    role_ids = [entra_role]
                
                assignments['app_roles'][key] = {
                    'app_name': app_name,
                    'role_ids': role_ids
                }
            
            elif method == 'GraphAPIPermission':
                app_role = path_config.get('app_role')
                if app_role == 'random':
                    api_permission_ids = [random.choice([perm["id"] for perm in HIGH_PRIVILEGED_GRAPH_API_PERMISSIONS.values()])]
                elif isinstance(app_role, list):
                    api_permission_ids = app_role
                else:
                    api_permission_ids = [app_role]
                
                assignments['app_api_permissions'][key] = {
                    'app_name': app_name,
                    'api_permission_ids': api_permission_ids
                }
        
        elif priv_esc == 'KeyVaultAbuse':
            # Get entities
            app_list = list(entities.get('applications', []))
            if not app_list:
                continue
            app_spec = app_list[0]
            app_name = app_spec.get('name', 'random')
            if app_name == 'random':
                app_name = list(applications.keys())[0]
            
            kv_list = list(entities.get('key_vaults', []))
            if not kv_list:
                continue
            kv_spec = kv_list[0]
            kv_name = kv_spec.get('name', 'random')
            if kv_name == 'random':
                kv_name = list(key_vaults.keys())[0]
            
            principal_type = path_config.get('principal_type', 'user')
            
            if principal_type == 'user':
                user_list = list(entities.get('users', []))
                if not user_list:
                    continue
                user_spec = user_list[0]
                principal_name = user_spec.get('name', 'random')
                if principal_name == 'random':
                    principal_name = list(users.keys())[0]
                    
                user_creds[path_name] = {
                    'user_principal_name': f"{principal_name}@{domain}",
                    'password': users[principal_name]['password']
                }
                
            elif principal_type == 'service_principal':
                principal_name = app_name  # Use the same app
                
            elif principal_type == 'managed_identity':
                vm_list = list(entities.get('virtual_machines', []))
                if not vm_list:
                    continue
                vm_spec = vm_list[0]
                principal_name = vm_spec.get('name', 'random')
                if principal_name == 'random':
                    principal_name = list(virtual_machines.keys())[0]
                
                # Assign VM Contributor to a user
                user_list = list(entities.get('users', []))
                if not user_list:
                    continue
                user_spec = user_list[0]
                user_name = user_spec.get('name', 'random')
                if user_name == 'random':
                    user_name = list(users.keys())[0]
                
                assignments['vm_contributor'][key] = {
                    'user_name': user_name,
                    'virtual_machine': principal_name
                }
                
                user_creds[path_name] = {
                    'user_principal_name': f"{user_name}@{domain}",
                    'password': users[user_name]['password']
                }
            
            assignments['kv_abuse'][key] = {
                'key_vault': kv_name,
                'principal_type': principal_type,
                'principal_name': principal_name,
                'virtual_machine': principal_name if principal_type == 'managed_identity' else None,
                'app_name': app_name,
                'initial_access_user': user_name if principal_type == 'managed_identity' else None
            }
            
            # Assign privileges to application
            method = path_config.get('method')
            if method == 'AzureADRole':
                entra_role = path_config.get('entra_role')
                if entra_role == 'random':
                    role_ids = [random.choice(list(HIGH_PRIVILEGED_ENTRA_ROLES.values()))]
                elif isinstance(entra_role, list):
                    role_ids = entra_role
                else:
                    role_ids = [entra_role]
                
                assignments['app_roles'][key] = {
                    'app_name': app_name,
                    'role_ids': role_ids
                }
            
            elif method == 'GraphAPIPermission':
                app_role = path_config.get('app_role')
                if app_role == 'random':
                    api_permission_ids = [random.choice([perm["id"] for perm in HIGH_PRIVILEGED_GRAPH_API_PERMISSIONS.values()])]
                elif isinstance(app_role, list):
                    api_permission_ids = app_role
                else:
                    api_permission_ids = [app_role]
                
                assignments['app_api_permissions'][key] = {
                    'app_name': app_name,
                    'api_permission_ids': api_permission_ids
                }
        
        elif priv_esc == 'StorageAccountAbuse':
            # Get entities
            app_list = list(entities.get('applications', []))
            if not app_list:
                continue
            app_spec = app_list[0]
            app_name = app_spec.get('name', 'random')
            if app_name == 'random':
                app_name = list(applications.keys())[0]
            
            sa_list = list(entities.get('storage_accounts', []))
            if not sa_list:
                continue
            sa_spec = sa_list[0]
            sa_name = sa_spec.get('name', 'random')
            if sa_name == 'random':
                sa_name = list(storage_accounts.keys())[0]
            
            principal_type = path_config.get('principal_type', 'user')
            
            # Generate certificate for storage account authentication
            cert_path, key_path = generate_certificate_and_key(app_name)
            
            if principal_type == 'user':
                user_list = list(entities.get('users', []))
                if not user_list:
                    continue
                user_spec = user_list[0]
                principal_name = user_spec.get('name', 'random')
                if principal_name == 'random':
                    principal_name = list(users.keys())[0]
                    
                user_creds[path_name] = {
                    'user_principal_name': f"{principal_name}@{domain}",
                    'password': users[principal_name]['password']
                }
                
            elif principal_type == 'service_principal':
                principal_name = app_name
                
            elif principal_type == 'managed_identity':
                vm_list = list(entities.get('virtual_machines', []))
                if not vm_list:
                    continue
                vm_spec = vm_list[0]
                principal_name = vm_spec.get('name', 'random')
                if principal_name == 'random':
                    principal_name = list(virtual_machines.keys())[0]
                
                # Assign VM Contributor to a user
                user_list = list(entities.get('users', []))
                if not user_list:
                    continue
                user_spec = user_list[0]
                user_name = user_spec.get('name', 'random')
                if user_name == 'random':
                    user_name = list(users.keys())[0]
                
                assignments['vm_contributor'][key] = {
                    'user_name': user_name,
                    'virtual_machine': principal_name
                }
                
                user_creds[path_name] = {
                    'user_principal_name': f"{user_name}@{domain}",
                    'password': users[user_name]['password']
                }
            
            assignments['storage_abuse'][key] = {
                'app_name': app_name,
                'storage_account': sa_name,
                'principal_type': principal_type,
                'principal_name': principal_name,
                'virtual_machine': principal_name if principal_type == 'managed_identity' else None,
                'certificate_path': cert_path,
                'private_key_path': key_path,
                'initial_access_user': user_name if principal_type == 'managed_identity' else None
            }
            
            # Assign privileges to application
            method = path_config.get('method')
            if method == 'AzureADRole':
                entra_role = path_config.get('entra_role')
                if entra_role == 'random':
                    role_ids = [random.choice(list(HIGH_PRIVILEGED_ENTRA_ROLES.values()))]
                elif isinstance(entra_role, list):
                    role_ids = entra_role
                else:
                    role_ids = [entra_role]
                
                assignments['app_roles'][key] = {
                    'app_name': app_name,
                    'role_ids': role_ids
                }
            
            elif method == 'GraphAPIPermission':
                app_role = path_config.get('app_role')
                if app_role == 'random':
                    api_permission_ids = [random.choice([perm["id"] for perm in HIGH_PRIVILEGED_GRAPH_API_PERMISSIONS.values()])]
                elif isinstance(app_role, list):
                    api_permission_ids = app_role
                else:
                    api_permission_ids = [app_role]
                
                assignments['app_api_permissions'][key] = {
                    'app_name': app_name,
                    'api_permission_ids': api_permission_ids
                }
    
    # Store user credentials for output
    assignments['user_creds'] = user_creds
    
    return assignments


def output_targeted_attack_paths(config, assignments, users, domain):
    """
    Output attack path details for targeted mode.
    """
    logging.info("=" * 60)
    logging.info("TARGETED ATTACK PATH DETAILS")
    logging.info("=" * 60)
    
    user_creds = assignments.get('user_creds', {})
    
    for path_name, path_config in config['attack_paths'].items():
        if not path_config.get('enabled', False):
            continue
        
        logging.info(f"\n*** {path_name} ***")
        description = path_config.get('description', 'N/A')
        if description != 'N/A':
            logging.info(f"Description: {description}")
        
        priv_esc = path_config.get('privilege_escalation')
        
        if priv_esc == 'ServicePrincipalAbuse':
            # Find the attack path assignment
            for key, assignment in assignments['app_owners'].items():
                if path_name in user_creds:
                    logging.info(f"Attack Path ID: {key}")
                    logging.info(f"Initial Access Identity: User - {user_creds[path_name]['user_principal_name']}")
                    logging.info(f"Password: {user_creds[path_name]['password']}")
                    logging.info(f"Owned Application: {assignment['app_name']}")
                    
                    # Show assigned privileges
                    if key in assignments['app_roles']:
                        logging.info(f"Application Privileges: Entra Role(s)")
                    elif key in assignments['app_api_permissions']:
                        logging.info(f"Application Privileges: Graph API Permission(s)")
                    break
        
        elif priv_esc == 'KeyVaultAbuse':
            for key, assignment in assignments['kv_abuse'].items():
                logging.info(f"Attack Path ID: {key}")
                
                principal_type = assignment['principal_type']
                principal_name = assignment['principal_name']
                key_vault = assignment['key_vault']
                
                if principal_type == 'user':
                    logging.info(f"Initial Access Identity: User - {principal_name}@{domain}")
                    if principal_name in users:
                        logging.info(f"Password: {users[principal_name]['password']}")
                    logging.info(f"Key Vault Access: {key_vault} (Key Vault Contributor)")
                elif principal_type == 'service_principal':
                    logging.info(f"Initial Access Identity: Service Principal - {principal_name}")
                    logging.info(f"Key Vault Access: {key_vault} (Key Vault Contributor)")
                elif principal_type == 'managed_identity':
                    vm_name = assignment['virtual_machine']
                    initial_user = assignment.get('initial_access_user')
                    logging.info(f"Initial Access Identity: User - {initial_user}@{domain} (with VM Contributor on {vm_name})")
                    if initial_user in users:
                        logging.info(f"Password: {users[initial_user]['password']}")
                    logging.info(f"Target Managed Identity: {vm_name}")
                    logging.info(f"Key Vault Access: {key_vault} (Key Vault Contributor)")
                
                logging.info(f"Target Application: {assignment['app_name']}")
                break
        
        elif priv_esc == 'StorageAccountAbuse':
            for key, assignment in assignments['storage_abuse'].items():
                logging.info(f"Attack Path ID: {key}")
                
                principal_type = assignment['principal_type']
                principal_name = assignment['principal_name']
                storage_account = assignment['storage_account']
                
                if principal_type == 'user':
                    logging.info(f"Initial Access Identity: User - {principal_name}@{domain}")
                    if principal_name in users:
                        logging.info(f"Password: {users[principal_name]['password']}")
                    logging.info(f"Storage Account Access: {storage_account} (Storage Blob Data Reader)")
                elif principal_type == 'service_principal':
                    logging.info(f"Initial Access Identity: Service Principal - {principal_name}")
                    logging.info(f"Storage Account Access: {storage_account} (Storage Blob Data Reader)")
                elif principal_type == 'managed_identity':
                    vm_name = assignment['virtual_machine']
                    initial_user = assignment.get('initial_access_user')
                    logging.info(f"Initial Access Identity: User - {initial_user}@{domain} (with VM Contributor on {vm_name})")
                    if initial_user in users:
                        logging.info(f"Password: {users[initial_user]['password']}")
                    logging.info(f"Target Managed Identity: {vm_name}")
                    logging.info(f"Storage Account Access: {storage_account} (Storage Blob Data Reader)")
                
                logging.info(f"Target Application: {assignment['app_name']}")
                logging.info(f"Certificate stored in: {storage_account}/cert-container/")
                break
    
    logging.info("\n" + "=" * 60)

def build_targeted_mode(config, verbose):
    """
    New targeted mode - creates only entities defined in attack paths.
    """
    azure_config_dir = os.path.expanduser('~/.azure')
    os.environ['AZURE_CONFIG_DIR'] = azure_config_dir
    
    tenant_id = config['tenant']['tenant_id']
    subscription_id = config['tenant']['subscription_id']
    domain = config['tenant']['domain']
    public_ip = utils.get_public_ip()
    
    # Collect all entities from enabled attack paths
    logging.info("Collecting entities from attack paths")
    all_entities = collect_entities_from_attack_paths(config)
    
    # Generate entity details
    logging.info("Generating entity details")
    users = generate_targeted_users(all_entities.get('users', []))
    groups = generate_targeted_groups(all_entities.get('groups', []))
    applications = generate_targeted_applications(all_entities.get('applications', []))
    administrative_units = generate_targeted_administrative_units(all_entities.get('administrative_units', []))
    resource_groups = generate_targeted_resource_groups(all_entities.get('resource_groups', []))
    key_vaults = generate_targeted_key_vaults(all_entities.get('key_vaults', []), resource_groups)
    storage_accounts = generate_targeted_storage_accounts(all_entities.get('storage_accounts', []), resource_groups)
    virtual_machines = generate_targeted_virtual_machines(all_entities.get('virtual_machines', []), resource_groups)
    
    # Create attack path assignments using the defined entities
    logging.info("Creating attack path assignments")
    attack_path_assignments = create_targeted_attack_path_assignments(
        config, users, groups, applications, administrative_units,
        resource_groups, key_vaults, storage_accounts, virtual_machines, domain
    )
    
    # Prepare Terraform variables
    user_vars = {user['user_principal_name']: user for user in users.values()}
    group_vars = {group['display_name']: group for group in groups.values()}
    application_vars = {app['display_name']: app for app in applications.values()}
    administrative_unit_vars = {au['display_name']: au for au in administrative_units.values()}
    
    tf_vars = {
        'tenant_id': tenant_id,
        'domain': domain,
        'public_ip': public_ip,
        'subscription_id': subscription_id,
        'users': user_vars,
        'azure_config_dir': azure_config_dir,
        'groups': group_vars,
        'applications': application_vars,
        'administrative_units': administrative_unit_vars,
        'resource_groups': resource_groups,
        'key_vaults': key_vaults,
        'storage_accounts': storage_accounts,
        'virtual_machines': virtual_machines,
        
        # Empty random assignments (not used in targeted mode)
        'user_group_assignments': {},
        'user_au_assignments': {},
        'user_role_assignments': {},
        'app_role_assignments': {},
        'app_api_permission_assignments': {},
        
        # Attack path assignments
        'attack_path_application_owner_assignments': attack_path_assignments.get('app_owners', {}),
        'attack_path_user_role_assignments': attack_path_assignments.get('user_roles', {}),
        'attack_path_application_role_assignments': attack_path_assignments.get('app_roles', {}),
        'attack_path_application_api_permission_assignments': attack_path_assignments.get('app_api_permissions', {}),
        'attack_path_kv_abuse_assignments': attack_path_assignments.get('kv_abuse', {}),
        'attack_path_storage_abuse_assignments': attack_path_assignments.get('storage_abuse', {}),
        'attack_path_vm_contributor_assignments': attack_path_assignments.get('vm_contributor', {})
    }
    
    # Write Terraform vars and execute
    logging.info("Creating terraform.tfvars.json")
    with open(os.path.join(TERRAFORM_DIR, 'terraform.tfvars.json'), 'w') as f:
        json.dump(tf_vars, f, indent=4)
    
    # Terraform init and apply
    logging.info("Calling terraform init")
    return_code, stdout, stderr = tf.init()
    if return_code != 0:
        logging.error(f"Terraform init failed: {stderr}")
        if verbose:
            logging.error(stdout)
            logging.error(stderr)
        return
    
    logging.info("Calling terraform apply to create resources, this may take several minutes...")
    return_code, stdout, stderr = tf.apply(skip_plan=True, capture_output=not verbose)
    if return_code != 0:
        logging.error(f"Terraform apply failed: {stderr}")
        if verbose:
            logging.error(stdout)
            logging.error(stderr)
        return
    
    logging.info("Azure AD tenant setup completed!")
    write_users_to_file(users, domain, 'users.txt')
    logging.info("Created users.txt file")
    
    # Output attack path details
    output_targeted_attack_paths(config, attack_path_assignments, users, domain)
    logging.info("Good bye.")


def build_random_mode(config, verbose):
    """
    Existing build logic - creates random resources then assigns attack paths.
    This is the current implementation moved into its own function.
    """
    azure_config_dir = os.path.expanduser('~/.azure')
    os.environ['AZURE_CONFIG_DIR'] = azure_config_dir
    
    tenant_id = config['tenant']['tenant_id']
    subscription_id = config['tenant']['subscription_id']
    domain = config['tenant']['domain']
    
    max_users = config['tenant']['users']
    max_groups = config['tenant']['groups']
    max_apps = config['tenant']['applications']
    max_aunits = config['tenant']['administrative_units']
    
    max_rgroups = config['tenant']['resource_groups']
    max_kvs = config['tenant']['key_vaults']
    max_sas = config['tenant']['storage_accounts']
    max_vms = config['tenant']['virtual_machines']

    public_ip = utils.get_public_ip()

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

    # Generate random resource groups
    logging.info(f"Generating {max_rgroups} resource groups")
    resource_groups = generate_resource_groups_details('entity_data/resource-groups.txt', max_rgroups)
    
    # Generate random key vaults
    logging.info(f"Generating {max_kvs} key vaults")
    key_vaults = generate_keyvault_details('entity_data/keyvaults.txt', max_kvs, resource_groups)

    # Generate storage accounts
    logging.info(f"Generating {max_sas} storage accounts")
    storage_accounts = generate_storage_account_details('entity_data/storage-accounts.txt', max_sas, resource_groups)
    
    # Generate virtual machines
    logging.info(f"Generating {max_vms} virtual machines")
    virtual_machines = generate_vm_details('entity_data/virtual-machines.txt', max_vms, resource_groups)

    # Create random assignments
    user_group_assignments, user_au_assignments, user_role_assignments, app_role_assignments, app_api_permission_assignments = create_random_assignments(users, groups, administrative_units, applications)
    
    attack_path_application_owner_assignments, attack_path_user_role_assignments, attack_path_application_role_assignments, attack_path_app_api_permission_assignments = {}, {}, {}, {}
        
    attack_path_kv_abuse_assignments, attack_path_storage_abuse_assignments = {}, {}
    attack_path_vm_contributor_assignments = {}
    
    user_creds = {}
  
    for attack_path_name, attack_path_data in config['attack_paths'].items():
        
        if attack_path_data['enabled'] and attack_path_data['privilege_escalation']=='ServicePrincipalAbuse':
                        
            logging.info(f"Creating assignments for attack path '{attack_path_name}'")
            initial_access, ap_app_owner_assignments, ap_user_role_assignments, ap_app_role_assignments, ap_app_api_permission_assignments = create_sp_attack_path(attack_path_data, users, applications, domain, "test")
            attack_path_application_owner_assignments = {**attack_path_application_owner_assignments, **ap_app_owner_assignments}
            attack_path_user_role_assignments = {**attack_path_user_role_assignments, **ap_user_role_assignments}
            attack_path_application_role_assignments = {**attack_path_application_role_assignments, **ap_app_role_assignments}
            attack_path_app_api_permission_assignments = {**attack_path_app_api_permission_assignments, **ap_app_api_permission_assignments}
            user_creds[attack_path_name] = initial_access
            
        elif attack_path_data['enabled'] and attack_path_data['privilege_escalation'] == 'KeyVaultAbuse':
                        
            kv_abuse_assignments, kv_app_role_assignments, kv_app_api_permission_assignments, kv_vm_contributor_assignments = create_kv_attack_path_flexible(attack_path_data, applications, key_vaults, users, applications, virtual_machines)
            attack_path_kv_abuse_assignments = {**attack_path_kv_abuse_assignments, **kv_abuse_assignments}
            attack_path_application_role_assignments = {**attack_path_application_role_assignments, **kv_app_role_assignments}
            attack_path_app_api_permission_assignments = {**attack_path_app_api_permission_assignments, **kv_app_api_permission_assignments}
            attack_path_vm_contributor_assignments = {**attack_path_vm_contributor_assignments, **kv_vm_contributor_assignments}
            
        elif attack_path_data['enabled'] and attack_path_data['privilege_escalation']=='StorageAccountAbuse':

            sa_abuse_assignments, sa_app_role_assignments, sa_app_api_permission_assignments, sa_vm_contributor_assignments = create_storage_attack_path_flexible(attack_path_data, applications, storage_accounts, users, applications, virtual_machines)
            attack_path_storage_abuse_assignments = {**attack_path_storage_abuse_assignments, **sa_abuse_assignments}
            attack_path_application_role_assignments = {**attack_path_application_role_assignments, **sa_app_role_assignments}
            attack_path_app_api_permission_assignments = {**attack_path_app_api_permission_assignments, **sa_app_api_permission_assignments}
            attack_path_vm_contributor_assignments = {**attack_path_vm_contributor_assignments, **sa_vm_contributor_assignments}

    # Prepare Terraform variables
    user_vars = {user['user_principal_name']: user for user in users.values()}
    group_vars = {group['display_name']: group for group in groups.values()}
    application_vars = {app['display_name']: app for app in applications.values()}
    administrative_unit_vars = {au['display_name']: au for au in administrative_units.values()}

    tf_vars = {
        
        # Environment
        'tenant_id': tenant_id,
        'domain': domain,
        'public_ip' : public_ip,
        'subscription_id': subscription_id, 
        
        # Entities
        'users': user_vars,
        'azure_config_dir': azure_config_dir,
        'groups': group_vars,
        'applications': application_vars,
        'administrative_units': administrative_unit_vars,
        
        # ARM Resources
        'resource_groups': resource_groups,
        'key_vaults': key_vaults,
        'storage_accounts': storage_accounts,
        'virtual_machines': virtual_machines,        
        
        # Assignments
        'user_group_assignments': user_group_assignments,
        'user_au_assignments': user_au_assignments,
        'user_role_assignments': user_role_assignments,
        'app_role_assignments': app_role_assignments,
        'app_api_permission_assignments' : app_api_permission_assignments,
        
        # Attack Paths
        'attack_path_application_owner_assignments' : attack_path_application_owner_assignments,
        'attack_path_user_role_assignments' : attack_path_user_role_assignments,
        'attack_path_application_role_assignments' : attack_path_application_role_assignments,
        'attack_path_application_api_permission_assignments' : attack_path_app_api_permission_assignments,
        
        'attack_path_kv_abuse_assignments': attack_path_kv_abuse_assignments,
        'attack_path_storage_abuse_assignments': attack_path_storage_abuse_assignments,
        'attack_path_vm_contributor_assignments': attack_path_vm_contributor_assignments
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
    
    for attack_path_name, attack_path_data in config['attack_paths'].items():
        
        if attack_path_data['enabled']:
            logging.info(f"*** {attack_path_name} ***")
            
            # Display attack path details based on privilege escalation type
            if attack_path_data['privilege_escalation'] == 'ServicePrincipalAbuse':
                # Extract attack path ID from the key
                attack_path_id = list(attack_path_application_owner_assignments.keys())[0].split('-')[-1]
                logging.info(f"Attack Path ID: attack-path-{attack_path_id}")
                logging.info(f"Initial Access Identity: User - {user_creds[attack_path_name]['user_principal_name']}")
                
            elif attack_path_data['privilege_escalation'] == 'KeyVaultAbuse':
                # Extract attack path ID and principal details from KeyVault abuse assignments
                for key, assignment in attack_path_kv_abuse_assignments.items():
                    attack_path_id = key.split('-')[-1]
                    logging.info(f"Attack Path ID: {key}")
                    
                    principal_type = assignment['principal_type']
                    principal_name = assignment['principal_name']
                    key_vault = assignment['key_vault']
                    
                    if principal_type == "user":
                        logging.info(f"Initial Access Identity: User - {principal_name}@{domain}")
                        logging.info(f"Key Vault Access: {key_vault} (Key Vault Contributor)")
                    elif principal_type == "service_principal":
                        logging.info(f"Initial Access Identity: Service Principal - {principal_name}")
                        logging.info(f"Key Vault Access: {key_vault} (Key Vault Contributor)")
                    elif principal_type == "managed_identity":
                        vm_name = assignment['virtual_machine']
                        initial_user = assignment.get('initial_access_user')
                        logging.info(f"Initial Access Identity: User - {initial_user}@{domain} (with VM Contributor on {vm_name})")
                        logging.info(f"Target Managed Identity: {vm_name}")
                        logging.info(f"Key Vault Access: {key_vault} (Key Vault Contributor)")
                        
            elif attack_path_data['privilege_escalation'] == 'StorageAccountAbuse':
                # Extract attack path ID and principal details from Storage Account abuse assignments
                for key, assignment in attack_path_storage_abuse_assignments.items():
                    attack_path_id = key.split('-')[-1]
                    logging.info(f"Attack Path ID: {key}")
                    
                    principal_type = assignment['principal_type']
                    principal_name = assignment['principal_name']
                    storage_account = assignment['storage_account']
                    
                    if principal_type == "user":
                        logging.info(f"Initial Access Identity: User - {principal_name}@{domain}")
                        logging.info(f"Storage Account Access: {storage_account} (Storage Blob Data Reader)")
                    elif principal_type == "service_principal":
                        logging.info(f"Initial Access Identity: Service Principal - {principal_name}")
                        logging.info(f"Storage Account Access: {storage_account} (Storage Blob Data Reader)")
                    elif principal_type == "managed_identity":
                        vm_name = assignment['virtual_machine']
                        initial_user = assignment.get('initial_access_user')
                        logging.info(f"Initial Access Identity: User - {initial_user}@{domain} (with VM Contributor on {vm_name})")
                        logging.info(f"Target Managed Identity: {vm_name}")
                        logging.info(f"Storage Account Access: {storage_account} (Storage Blob Data Reader)")
                      
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
