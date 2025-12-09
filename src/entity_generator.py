"""
Entity generators for BadZure.
Handles generation of all Entra ID and Azure resource entities.
"""
import random
import string
from typing import Dict, List


class EntityGenerator:
    """Generates entities for both random and targeted modes."""
    
    def __init__(self, data_dir: str = "entity_data"):
        self.data_dir = data_dir
        self._name_cache = {}
    
    def _read_names_from_file(self, filename: str) -> List[str]:
        """Read names from file with caching."""
        if filename not in self._name_cache:
            file_path = f"{self.data_dir}/{filename}"
            with open(file_path, 'r') as file:
                self._name_cache[filename] = [line.strip() for line in file.readlines()]
        return self._name_cache[filename]
    
    def _generate_random_password(self, length: int = 15) -> str:
        """Generate a random password."""
        if length < 8:
            raise ValueError("Password length must be at least 8 characters")
        
        password = [
            random.choice(string.ascii_uppercase),
            random.choice(string.ascii_lowercase),
            random.choice(string.digits),
            random.choice(string.punctuation)
        ]
        
        password += random.choices(
            string.ascii_letters + string.digits + string.punctuation,
            k=length - 4
        )
        random.shuffle(password)
        return ''.join(password)
    
    # User generation
    def generate_users(self, count: int) -> Dict:
        """Generate random users."""
        users = {}
        first_names = self._read_names_from_file('first-names.txt')
        last_names = self._read_names_from_file('last-names.txt')
        
        for _ in range(count):
            first_name = random.choice(first_names)
            last_name = random.choice(last_names)
            key = f"{first_name}.{last_name}".lower()
            users[key] = {
                'user_principal_name': key,
                'display_name': f"{first_name.capitalize()} {last_name.capitalize()}",
                'mail_nickname': key,
                'password': self._generate_random_password()
            }
        
        return users
    
    def generate_users_targeted(self, user_specs: List[Dict]) -> Dict:
        """Generate users from targeted specifications."""
        users = {}
        first_names = self._read_names_from_file('first-names.txt')
        last_names = self._read_names_from_file('last-names.txt')
        
        for spec in user_specs:
            name = spec.get('name', 'random')
            password_spec = spec.get('password', 'random')
            
            if name == 'random':
                first_name = random.choice(first_names)
                last_name = random.choice(last_names)
                name = f"{first_name}.{last_name}".lower()
            
            password = (self._generate_random_password() 
                       if password_spec == 'random' 
                       else password_spec)
            
            users[name] = {
                'user_principal_name': name,
                'display_name': name.replace('.', ' ').title(),
                'mail_nickname': name,
                'password': password
            }
        
        return users
    
    # Group generation
    def generate_groups(self, count: int) -> Dict:
        """Generate random groups."""
        groups = {}
        group_names = self._read_names_from_file('group-names.txt')
        selected_groups = random.sample(group_names, count)
        
        for group_name in selected_groups:
            groups[group_name] = {'display_name': group_name}
        
        return groups
    
    def generate_groups_targeted(self, group_specs: List[Dict]) -> Dict:
        """Generate groups from targeted specifications."""
        groups = {}
        group_names = self._read_names_from_file('group-names.txt')
        
        for spec in group_specs:
            name = spec.get('name', 'random')
            if name == 'random':
                name = random.choice(group_names)
            groups[name] = {'display_name': name}
        
        return groups
    
    # Application generation
    def generate_applications(self, count: int) -> Dict:
        """Generate random applications."""
        applications = {}
        prefixes = self._read_names_from_file('app-prefixes.txt')
        core_names = self._read_names_from_file('app-core-names.txt')
        suffixes = self._read_names_from_file('app-sufixes.txt')
        
        app_names = set()
        while len(app_names) < count:
            prefix = random.choice(prefixes)
            core_name = random.choice(core_names)
            suffix = random.choice(suffixes) if random.random() > 0.5 else ""
            app_name = f"{prefix}{core_name}{suffix}"
            app_names.add(app_name)
        
        for name in app_names:
            applications[name] = {'display_name': name}
        
        return applications
    
    def generate_applications_targeted(self, app_specs: List[Dict]) -> Dict:
        """Generate applications from targeted specifications."""
        applications = {}
        prefixes = self._read_names_from_file('app-prefixes.txt')
        core_names = self._read_names_from_file('app-core-names.txt')
        suffixes = self._read_names_from_file('app-sufixes.txt')
        
        for spec in app_specs:
            name = spec.get('name', 'random')
            if name == 'random':
                prefix = random.choice(prefixes)
                core_name = random.choice(core_names)
                suffix = random.choice(suffixes) if random.random() > 0.5 else ""
                name = f"{prefix}{core_name}{suffix}"
            applications[name] = {'display_name': name}
        
        return applications
    
    # Administrative Unit generation
    def generate_administrative_units(self, count: int) -> Dict:
        """Generate random administrative units."""
        aunits = {}
        aunit_names = self._read_names_from_file('administrative-units.txt')
        selected_aunits = random.sample(aunit_names, count)
        
        for name in selected_aunits:
            aunits[name] = {'display_name': name}
        
        return aunits
    
    def generate_administrative_units_targeted(self, au_specs: List[Dict]) -> Dict:
        """Generate administrative units from targeted specifications."""
        aunits = {}
        au_names = self._read_names_from_file('administrative-units.txt')
        
        for spec in au_specs:
            name = spec.get('name', 'random')
            if name == 'random':
                name = random.choice(au_names)
            aunits[name] = {'display_name': name}
        
        return aunits
    
    # Resource Group generation
    def generate_resource_groups(self, count: int) -> Dict:
        """Generate random resource groups."""
        rgs = {}
        rg_names = self._read_names_from_file('resource-groups.txt')
        random_rgs = random.sample(rg_names, count)
        
        for rg in random_rgs:
            rgs[rg] = {
                'name': rg,
                'location': "West US"
            }
        
        return rgs
    
    def generate_resource_groups_targeted(self, rg_specs: List[Dict]) -> Dict:
        """Generate resource groups from targeted specifications."""
        rgs = {}
        rg_names = self._read_names_from_file('resource-groups.txt')
        
        for spec in rg_specs:
            name = spec.get('name', 'random')
            location = spec.get('location', 'West US')
            
            if name == 'random':
                name = random.choice(rg_names)
            
            rgs[name] = {
                'name': name,
                'location': location
            }
        
        return rgs
    
    # Key Vault generation
    def generate_key_vaults(self, count: int, resource_groups: Dict) -> Dict:
        """Generate random key vaults."""
        kvs = {}
        kv_names = self._read_names_from_file('keyvaults.txt')
        selected_kvs = random.sample(kv_names, count)
        
        for kv in selected_kvs:
            random_rg = random.choice(list(resource_groups.keys()))
            random_suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=2))
            kv_name = f"{kv}-{random_suffix}"
            
            kvs[kv_name] = {
                'name': kv_name,
                'location': "West US",
                'resource_group_name': random_rg,
                'sku_name': "standard"
            }
        
        return kvs
    
    def generate_key_vaults_targeted(self, kv_specs: List[Dict], resource_groups: Dict) -> Dict:
        """Generate key vaults from targeted specifications."""
        kvs = {}
        kv_names = self._read_names_from_file('keyvaults.txt')
        
        for spec in kv_specs:
            name = spec.get('name', 'random')
            rg_name = spec.get('resource_group')
            
            if name == 'random':
                base_name = random.choice(kv_names)
                random_suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=2))
                name = f"{base_name}-{random_suffix}"
            
            # Handle "random" resource group reference
            if rg_name == 'random':
                if not resource_groups:
                    continue
                rg_name = list(resource_groups.keys())[0]
            
            # Validate resource group exists
            if rg_name not in resource_groups:
                continue
            
            kvs[name] = {
                'name': name,
                'location': resource_groups[rg_name]['location'],
                'resource_group_name': rg_name,
                'sku_name': 'standard'
            }
        
        return kvs
    
    # Storage Account generation
    def generate_storage_accounts(self, count: int, resource_groups: Dict) -> Dict:
        """Generate random storage accounts."""
        sas = {}
        sa_names = self._read_names_from_file('storage-accounts.txt')
        selected_sas = random.sample(sa_names, count)
        
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
    
    def generate_storage_accounts_targeted(self, sa_specs: List[Dict], resource_groups: Dict) -> Dict:
        """Generate storage accounts from targeted specifications."""
        sas = {}
        sa_names = self._read_names_from_file('storage-accounts.txt')
        
        for spec in sa_specs:
            name = spec.get('name', 'random')
            rg_name = spec.get('resource_group')
            
            if name == 'random':
                base_name = random.choice(sa_names)
                random_suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=3))
                name = f"{base_name}{random_suffix}"
            
            # Handle "random" resource group reference
            if rg_name == 'random':
                if not resource_groups:
                    continue
                rg_name = list(resource_groups.keys())[0]
            
            # Validate resource group exists
            if rg_name not in resource_groups:
                continue
            
            sas[name] = {
                'name': name.lower(),
                'location': resource_groups[rg_name]['location'],
                'resource_group_name': rg_name,
                'account_tier': 'Standard',
                'account_replication_type': 'LRS'
            }
        
        return sas
    
    # Virtual Machine generation
    def generate_virtual_machines(self, count: int, resource_groups: Dict) -> Dict:
        """Generate random virtual machines."""
        vms = {}
        vm_names = self._read_names_from_file('virtual-machines.txt')
        selected_vms = random.sample(vm_names, count)
        
        for vm in selected_vms:
            random_rg = random.choice(list(resource_groups.keys()))
            os_type = "Linux"
            random_suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=2))
            vm_name = f"{vm}-{random_suffix}"
            
            vms[vm_name] = {
                "name": vm_name,
                "location": "West US",
                "resource_group_name": random_rg,
                "vm_size": "Standard_D2s_v3",
                "admin_username": "badzureadmin",
                "admin_password": self._generate_random_password(12),
                "os_type": os_type
            }
        
        return vms
    
    def generate_virtual_machines_targeted(self, vm_specs: List[Dict], resource_groups: Dict) -> Dict:
        """Generate virtual machines from targeted specifications."""
        vms = {}
        vm_names = self._read_names_from_file('virtual-machines.txt')
        
        for spec in vm_specs:
            name = spec.get('name', 'random')
            rg_name = spec.get('resource_group')
            os_type = spec.get('os_type', 'Linux')
            
            if name == 'random':
                base_name = random.choice(vm_names)
                random_suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=2))
                name = f"{base_name}-{random_suffix}"
            
            # Handle "random" resource group reference
            if rg_name == 'random':
                if not resource_groups:
                    continue
                rg_name = list(resource_groups.keys())[0]
            
            # Validate resource group exists
            if rg_name not in resource_groups:
                continue
            
            vms[name] = {
                'name': name,
                'location': resource_groups[rg_name]['location'],
                'resource_group_name': rg_name,
                'vm_size': 'Standard_D2s_v3',
                'admin_username': 'badzureadmin',
                'admin_password': self._generate_random_password(12),
                'os_type': os_type
            }
        
        return vms