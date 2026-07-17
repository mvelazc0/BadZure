"""
Terraform management for BadZure.
Handles all Terraform operations and variable building.
"""
import os
import json
import logging
import shutil
from typing import Dict, Tuple
from python_terraform import Terraform


class TerraformNotFoundError(RuntimeError):
    """Raised when the `terraform` binary isn't installed / on PATH."""

    def __init__(self):
        super().__init__(
            "Terraform is not installed or not on PATH. Install it from "
            "https://developer.hashicorp.com/terraform/install and make sure "
            "the `terraform` command is available in your shell, then retry."
        )


class TerraformManager:
    """Manages Terraform operations."""

    def __init__(self, terraform_dir: str = "terraform"):
        self.terraform_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), terraform_dir)
        self.tf = Terraform(working_dir=self.terraform_dir)

    @staticmethod
    def ensure_installed() -> None:
        """Raise a friendly error up front if `terraform` isn't on PATH."""
        if shutil.which("terraform") is None:
            raise TerraformNotFoundError()

    @staticmethod
    def _run(fn, *args, **kwargs) -> Tuple[int, str, str]:
        """Run a python_terraform call, converting a missing binary into a
        friendly TerraformNotFoundError instead of a raw FileNotFoundError
        traceback from subprocess.Popen."""
        try:
            return fn(*args, **kwargs)
        except FileNotFoundError:
            raise TerraformNotFoundError()

    def init(self) -> Tuple[int, str, str]:
        """Initialize Terraform."""
        return self._run(self.tf.init)

    def apply(self, verbose: bool = False) -> Tuple[int, str, str]:
        """Apply Terraform configuration."""
        return self._run(self.tf.apply, skip_plan=True, capture_output=not verbose)

    def destroy(self, verbose: bool = False) -> Tuple[int, str, str]:
        """Destroy Terraform resources."""
        return self._run(self.tf.apply, skip_plan=True, destroy=True, auto_approve=True, capture_output=not verbose)

    def show(self, verbose: bool = False) -> Tuple[int, str, str]:
        """Show Terraform state."""
        return self._run(self.tf.show, json=True, capture_output=not verbose)

    def get_outputs(self) -> Dict:
        """Get Terraform outputs as a dictionary."""
        return_code, stdout, stderr = self.tf.cmd('output', '-json')
        if return_code != 0:
            logging.warning(f"Failed to get Terraform outputs: {stderr}")
            return {}
        try:
            raw = json.loads(stdout)
            # Terraform output -json wraps each output in {value: ..., type: ..., sensitive: ...}
            return {k: v.get('value') for k, v in raw.items()}
        except (json.JSONDecodeError, AttributeError):
            logging.warning("Failed to parse Terraform output JSON")
            return {}
    
    def write_terraform_vars(self, tf_vars: Dict) -> None:
        """Write Terraform variables to file."""
        tfvars_path = os.path.join(self.terraform_dir, 'terraform.tfvars.json')
        logging.info("Creating terraform.tfvars.json")
        with open(tfvars_path, 'w') as f:
            json.dump(tf_vars, f, indent=4)
    
    def cleanup_state_files(self) -> None:
        """Remove Terraform state files and generated certificates."""
        logging.info("Deleting terraform state files")
        for file in ["terraform.tfstate", "terraform.tfstate.backup", "terraform.tfvars.json"]:
            try:
                os.remove(os.path.join(self.terraform_dir, file))
            except FileNotFoundError:
                pass
        
        # Clean up generated certificate and key files
        logging.info("Deleting generated certificates and keys")
        try:
            for file in os.listdir(self.terraform_dir):
                if file.endswith('.pem') or file.endswith('.key'):
                    file_path = os.path.join(self.terraform_dir, file)
                    try:
                        os.remove(file_path)
                        logging.debug(f"Deleted {file}")
                    except Exception as e:
                        logging.warning(f"Failed to delete {file}: {e}")
        except Exception as e:
            logging.warning(f"Error cleaning up certificates: {e}")
    
    def parse_terraform_output(self, output: str) -> list:
        """
        Parse Terraform state output and extract essential information.
        
        Args:
            output: JSON output from terraform show
            
        Returns:
            List of resource descriptions
        """
        resources = []
        
        try:
            state = json.loads(output)
            for module in state.get('values', {}).get('root_module', {}).get('resources', []):
                resource_type = module.get('type')
                resource_name = module.get('name')
                
                # Skip certain resource types
                if resource_type in ['azuread_domains', 'azuread_administrative_unit_member',
                                    'azuread_group_member', 'azuread_directory_role_assignment']:
                    continue
                
                # Extract key attribute based on resource type
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
                else:
                    key_attr = "N/A"
                
                resources.append(f"Resource Type: {resource_type}, Identifier: {key_attr}")
        
        except json.JSONDecodeError:
            logging.error("Failed to parse Terraform state output")
        
        return resources