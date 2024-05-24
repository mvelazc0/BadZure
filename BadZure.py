import os
import json
import yaml
import click
from python_terraform import Terraform
import random
import string


TERRAFORM_DIR = os.path.join(os.path.dirname(__file__), 'terraform')
tf = Terraform(working_dir=TERRAFORM_DIR)

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
    tenant_id = config.get('tenant_id')
    domain = config.get('domain')

    # Load users data from CSV
    users = load_users_from_csv('Csv/users.csv')

    # Load groups data from CSV
    groups = load_groups_from_csv('Csv/groups.csv')

    # Load applications data from CSV
    applications = load_applications_from_csv('Csv/apps.csv')

    # Load administrative units data from CSV
    administrative_units = load_administrative_units_from_csv('Csv/a_units.csv')


    # Prepare Terraform variables
    user_vars = {user['user_principal_name']: user for user in users.values()}
    group_vars = {group['display_name']: group for group in groups.values()}
    application_vars = {app['display_name']: app for app in applications.values()}
    administrative_unit_vars = {au['display_name']: au for au in administrative_units.values()}

    tf_vars = {
        'tenant_id': tenant_id,
        'domain': domain,
        'users': user_vars,
        'groups': group_vars,
        'applications': application_vars,
        'administrative_units': administrative_unit_vars
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
