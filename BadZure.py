import os
import json
import yaml
import click
from python_terraform import Terraform
import random
import string

TERRAFORM_DIR = os.path.join(os.path.dirname(__file__), 'terraform')
tf = Terraform(working_dir=TERRAFORM_DIR)

# Ensure AZURE_CONFIG_DIR is set to your current Azure CLI config directory
os.environ['AZURE_CONFIG_DIR'] = os.path.expanduser('~/.azure')

def create_attack_path_1(users, applications, domain, password):
    attack_path_apps = {}

    # Pick a random application
    app_keys = list(applications.keys())
    random_app = random.choice(app_keys)
    app_id = applications[random_app]['display_name']

    # Assign "Privileged Role Administrator" role to the application
    privileged_role_id = "e8611ab8-c189-46e8-94e1-60213ab1f814"  # ID for "Privileged Role Administrator"

    # Pick a random user
    user_keys = list(users.keys())
    random_user = random.choice(user_keys)
    user_principal_name = f"{users[random_user]['user_principal_name']}@{domain}"

    assignment_key = f"{random_app}-{random_user}"

    attack_path_apps[assignment_key] = {
        'app_name': random_app,
        'role_id': privileged_role_id,
        'user_principal_name': user_principal_name,
        'display_name': users[random_user]['display_name'],
        'password': password
    }

    return attack_path_apps


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

# List of Azure AD role definition IDs and their display names
AZURE_AD_ROLES = [
    ("4a5d8f65-41da-4de4-8968-e035b65339cf", "Reports Reader"),
    ("c4e39bd9-1100-46d3-8c65-fb160da0071f", "Authentication Administrator"),
    ("88d8e3e3-8f55-4a1e-953a-9b9898b8876b", "Directory Readers"),
    ("95e79109-95c0-4d8e-aee3-d01accf2d47b", "Guest Inviter"),
    ("790c1fb9-7f7d-4f88-86a1-ef1f95c05c1b", "Message Center Reader"),
    ("fdd7a751-b60b-444a-984c-02652fe8fa1c", "Groups Administrator"),
    ("d37c8bed-0711-4417-ba38-b4abe66ce4c2", "Network Administrator")
]

AZURE_AD_APP_ROLES = [
    ("29232cdf-9323-42fd-ade2-1d097af3e4de", "Exchange Administrator"),
    ("5f2222b1-57c3-48ba-8ad5-d4759f1fde6f", "Security Operator"),
    ("d37c8bed-0711-4417-ba38-b4abe66ce4c2", "Network Administrator"),
    ("3a2c62db-5318-420d-8d74-23affee5d9d5", "Intune Administrator"),
    ("c430b396-e693-46cc-96f3-db01bf8bb62a", "Attack Simulation Administrator"),
    ("cf1c38e5-3621-4004-a7cb-879624dced7c", "Application Developer")
]

def create_random_assignments(users, groups, administrative_units, applications):
    user_group_assignments = {}
    user_au_assignments = {}
    user_role_assignments = {}
    app_role_assignments = {}

    user_keys = list(users.keys())
    group_keys = list(groups.keys())
    au_keys = list(administrative_units.keys())
    app_keys = list(applications.keys())


    for user in user_keys:
        if groups:
            group = random.choice(group_keys)
            assignment_key = f"{user}-{group}"
            user_group_assignments[assignment_key] = {
                'user_name': user,
                'group_name': group
            }

        if administrative_units:
            au = random.choice(au_keys)
            assignment_key = f"{user}-{au}"
            user_au_assignments[assignment_key] = {
                'user_name': user,
                'administrative_unit_name': au
            }

        if AZURE_AD_ROLES:
            role = random.choice(AZURE_AD_ROLES)
            assignment_key = f"{user}-{role[1]}"
            user_role_assignments[assignment_key] = {
                'user_name': user,
                'role_definition_id': role[0]
            }

    for app in app_keys:
        if AZURE_AD_APP_ROLES:
            role = random.choice(AZURE_AD_APP_ROLES)
            assignment_key = f"{app}-{role[1]}"
            app_role_assignments[assignment_key] = {
                'app_name': app,
                'role_id': role[0]
            }

    return user_group_assignments, user_au_assignments, user_role_assignments, app_role_assignments



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


def load_users_from_csv(file_path):
    import csv
    users = {}
    with open(file_path, mode='r') as infile:
        reader = csv.DictReader(infile)
        for row in reader:
            key = f"{row['FirstName']}.{row['LastName']}".lower()  
            users[key] = {
                'user_principal_name': key,
                'display_name': f"{row['FirstName']} {row['LastName']}",
                'mail_nickname': key,
                'password': generate_random_password()  
            }
    return users

def load_groups_from_csv(file_path):
    import csv
    groups = {}
    with open(file_path, mode='r') as infile:
        reader = csv.DictReader(infile)
        for row in reader:
            key = row['DisplayName']  
            groups[key] = {
                'display_name': row['DisplayName']
            }
    return groups

def load_applications_from_csv(file_path):
    import csv
    applications = {}
    with open(file_path, mode='r') as infile:
        reader = csv.DictReader(infile)
        for row in reader:
            key = row['DisplayName']  # Use DisplayName as the key
            applications[key] = {
                'display_name': row['DisplayName']
            }
    return applications

def load_administrative_units_from_csv(file_path):
    import csv
    administrative_units = {}
    with open(file_path, mode='r') as infile:
        reader = csv.DictReader(infile)
        for row in reader:
            key = row['DisplayName']  # Use DisplayName as the key
            administrative_units[key] = {
                'display_name': row['DisplayName']
            }
    return administrative_units

@click.group()
def cli():
    pass

@cli.command()
@click.option('--verbose', is_flag=True, help="Enable verbose output")
def build(verbose):
    """Build and configure Azure AD users and groups"""
    # Load configuration
    config = load_config('badzure.yml')
    tenant_id = config['tenant']['tenant_id']
    domain = config['tenant']['domain']

    # Load users data from CSV
    users = load_users_from_csv('Csv/users.csv')

    # Load groups data from CSV
    groups = load_groups_from_csv('Csv/groups.csv')

    # Load applications data from CSV
    applications = load_applications_from_csv('Csv/apps.csv')

    # Load administrative units data from CSV
    administrative_units = load_administrative_units_from_csv('Csv/a_units.csv')

     # Create random assignments
    user_group_assignments, user_au_assignments, user_role_assignments, app_role_assignments = create_random_assignments(users, groups, administrative_units, applications)

     # Create attack path 1 assignments
    attack_path_1_assignments = None
    if config['attack_paths']['attack_path_1']['enabled']:
        password = config['attack_paths']['attack_path_1']['password']
        attack_path_1_assignments = create_attack_path_1(users, applications, domain, password)
  
   
    # Prepare Terraform variables
    user_vars = {user['user_principal_name']: user for user in users.values()}
    group_vars = {group['display_name']: group for group in groups.values()}
    application_vars = {app['display_name']: app for app in applications.values()}
    administrative_unit_vars = {au['display_name']: au for au in administrative_units.values()}

    azure_config_dir = os.path.expanduser('~/.azure')
    os.environ['AZURE_CONFIG_DIR'] = azure_config_dir

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
        'attack_path_1_assignments': attack_path_1_assignments if attack_path_1_assignments is not None else {}
    }

    # Write the Terraform variables to a file
    with open(os.path.join(TERRAFORM_DIR, 'terraform.tfvars.json'), 'w') as f:
        json.dump(tf_vars, f, indent=4)

    # Initialize and apply the Terraform configuration
    return_code, stdout, stderr = tf.init()
    if return_code != 0:
        click.echo(f"Error during terraform init: {stderr}")
        if verbose:
            click.echo(stdout)
            click.echo(stderr)
        return

    return_code, stdout, stderr = tf.apply(skip_plan=True, capture_output=not verbose)
    if return_code != 0:
        click.echo(f"Error during terraform apply: {stderr}")
        if verbose:
            click.echo(stdout)
            click.echo(stderr)
        return

    click.echo("Azure AD users and groups created.")


@cli.command()
@click.option('--verbose', is_flag=True, help="Enable verbose output")
def destroy(verbose):
    """Destroy Azure AD users"""
    # Ensure the terraform directory exists
    os.makedirs(TERRAFORM_DIR, exist_ok=True)

    # Ensure terraform.tfvars.json exists
    tfvars_path = os.path.join(TERRAFORM_DIR, 'terraform.tfvars.json')
    if not os.path.exists(tfvars_path):
        click.echo("Error: terraform.tfvars.json file not found.")
        return

    # Initialize and destroy the Terraform configuration
    return_code, stdout, stderr = tf.init()
    if return_code != 0:
        click.echo(f"Error during terraform init: {stderr}")
        return

    #return_code, stdout, stderr = tf.destroy(force=True, input=False, auto_approve=True, capture_output=verbose)
    return_code, stdout, stderr = tf.apply(skip_plan=True, destroy=True, auto_approve=True, capture_output=not verbose)

    if return_code != 0:
        click.echo(f"Error during terraform destroy: {stderr}")
        click.echo(stdout)
        click.echo(stderr)
        return

    # Remove the state files after destroying the resources
    for file in ["terraform.tfstate", "terraform.tfstate.backup"]:
        try:
            os.remove(os.path.join(TERRAFORM_DIR, file))
        except FileNotFoundError:
            pass

    click.echo("Azure AD users configuration destroyed.")

if __name__ == '__main__':
    cli()
