"""
Attack path management for BadZure.
Handles creation of all attack path types for both random and targeted modes.
"""
import random
import string
import logging
from typing import Dict, Tuple, Optional
from src.constants import (
    HIGH_PRIVILEGED_ENTRA_ROLES,
    HIGH_PRIVILEGED_GRAPH_API_PERMISSIONS,
    ALL_HIGH_PRIVILEGED_PERMISSIONS,
    API_REGISTRY,
    APP_ADMIN_ROLE_ID,
    CLOUD_APP_ADMIN_ROLE_ID,
    RECON_DIRECTORY_READ_ALL_ID
)
from src.crypto import generate_certificate_and_key
from src.entity_generator import EntityGenerator
from src.primitives import (
    ATTACK_PATH,
    AppCredential,
    DataInject,
    AzureRbacAssignment,
    EntraRoleAssignment,
    ApiPermission,
    GroupMembership,
    GroupOwnership,
    AppOwnership,
)


class AttackPathManager:
    """Manages creation of attack paths for both random and targeted modes."""
    
    def __init__(self, entity_generator: EntityGenerator = None):
        """
        Initialize AttackPathManager.
        
        Args:
            entity_generator: EntityGenerator instance for creating attack path groups.
                            If not provided, a new instance will be created.
        """
        self.entity_generator = entity_generator or EntityGenerator()

    def build_recon_permissions(self, user_creds: Dict) -> Tuple[Dict, Dict]:
        """
        Build recon permissions for all initial access identities.

        - Service principals get Directory.Read.All (Graph API) for Entra ID enumeration
        - All identities (users and SPs) get subscription-level Reader role for Azure resource enumeration
        - Users already have directory read access by default in Entra ID
        """
        recon_api_permissions = {}
        subscription_reader_assignments = {}

        for path_name, credentials in user_creds.items():
            identity_type = credentials.get('initial_access')

            if identity_type == 'service_principal':
                sp_name = credentials.get('service_principal_name')
                if sp_name:
                    # Directory.Read.All for Entra ID enumeration
                    api_key = f"recon_{sp_name}"
                    if api_key not in recon_api_permissions:
                        recon_api_permissions[api_key] = {
                            'app_name': sp_name,
                            'api_permission_ids': [RECON_DIRECTORY_READ_ALL_ID],
                            'api_type': 'graph'
                        }
                    # Subscription Reader for Azure resource enumeration
                    reader_key = f"recon_{sp_name}"
                    if reader_key not in subscription_reader_assignments:
                        subscription_reader_assignments[reader_key] = {
                            'initial_access': 'service_principal',
                            'principal_name': sp_name
                        }

            elif identity_type == 'user':
                # Extract bare username from UPN (remove @domain)
                upn = credentials.get('user_principal_name', '')
                principal_name = upn.split('@')[0] if '@' in upn else upn
                if principal_name:
                    # Subscription Reader only (users already have directory read)
                    reader_key = f"recon_{principal_name}"
                    if reader_key not in subscription_reader_assignments:
                        subscription_reader_assignments[reader_key] = {
                            'initial_access': 'user',
                            'principal_name': principal_name
                        }

        return recon_api_permissions, subscription_reader_assignments

    # ========================================================================
    # Phase 4 macros — identity-based + managed-identity techniques.
    # Each emits generic primitives (like the KV/Storage/Cosmos macros) and
    # reuses the legacy entity selectors + _assign_app_privileges verbatim.
    # ========================================================================
    HELPDESK_ADMIN_ROLE_ID = "729827e3-9c14-49f7-bb1b-9608f156bbb8"

    # ManagedIdentityTheft role sets (parity with the legacy main.tf blocks).
    SOURCE_CONTRIBUTOR_ROLE = {
        'vm': 'Virtual Machine Contributor', 'logic_app': 'Logic App Contributor',
        'automation_account': 'Automation Contributor', 'function_app': 'Website Contributor',
    }
    SOURCE_SCOPE_RESOURCE_TYPE = {
        'vm': 'virtual_machine', 'logic_app': 'logic_app',
        'automation_account': 'automation_account', 'function_app': 'function_app',
    }
    MI_KV_ROLES = ['Key Vault Contributor', 'Key Vault Secrets User', 'Key Vault Reader']
    MI_KV_CERTIFICATE_ROLE = 'Key Vault Certificate User'
    MI_STORAGE_ROLES = ['Storage Blob Data Reader', 'Storage Account Contributor']

    # ---- shared macro helpers ----------------------------------------------
    @staticmethod
    def _attack_path_key(mode: str, path_name: Optional[str]) -> str:
        aid = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
        if mode == 'targeted' and path_name:
            return f"attack-path-{path_name}-{aid}"
        if mode == 'random' and path_name:
            return f"{path_name}-{aid}"
        return f"attack-path-{aid}"

    def _app_privilege_primitives(self, attack_config: Dict, app_name: str, key: str):
        """Translate the looted app's privileges (method/entra_role/app_role) into
        EntraRoleAssignment / ApiPermission primitives. Reuses the legacy resolver.
        Returns (primitives, entra_role_ids, api_perm_ids, api_type)."""
        legacy_roles, legacy_perms = {}, {}
        self._assign_app_privileges(attack_config, app_name, key, legacy_roles, legacy_perms)
        prims, entra_role_ids, api_perm_ids, api_type = [], [], [], None
        if key in legacy_roles:
            entra_role_ids = legacy_roles[key]['role_ids']
            for idx, role_id in enumerate(entra_role_ids):
                prims.append(EntraRoleAssignment(
                    f"{key}_app_role_{idx}", ATTACK_PATH,
                    principal_ref=app_name, principal_type="service_principal", role=role_id,
                ))
        if key in legacy_perms:
            api_perm_ids = legacy_perms[key]['api_permission_ids']
            api_type = legacy_perms[key].get('api_type', 'graph')
            for idx, perm_id in enumerate(api_perm_ids):
                prims.append(ApiPermission(
                    f"{key}_app_perm_{idx}", ATTACK_PATH,
                    principal_ref=app_name, permission_id=perm_id, api_type=api_type,
                ))
        return prims, entra_role_ids, api_perm_ids, api_type

    def _initial_access_credentials(self, identity_type, principal_name, users, domain,
                                    entry_point, key, primitives):
        """Operator credentials for the initial-access identity. For a service
        principal, mint its own secret (appended to `primitives`) so the operator
        can authenticate; surfaced via the generic_app_credentials TF output."""
        if identity_type == 'user':
            return {
                "initial_access": "user",
                "user_principal_name": f"{principal_name}@{domain}",
                "password": users[principal_name]['password'],
                "entry_point": entry_point,
            }
        sp_cred_key = f"{key}_initial_sp"
        primitives.append(AppCredential(
            sp_cred_key, ATTACK_PATH, app_ref=principal_name, type="password",
            display_name="BadZureInitialAccess",
        ))
        return {
            "initial_access": "service_principal",
            "service_principal_name": principal_name,
            "entry_point": entry_point,
            "generic_credential_key": f"ap:{sp_cred_key}",
        }

    def _attack_group(self, assignment_type, principal_name, identity_type):
        if assignment_type == 'group_owner':
            return self.entity_generator.generate_attack_path_group(
                owner_name=principal_name, owner_type=identity_type)
        return self.entity_generator.generate_attack_path_group()

    @staticmethod
    def _group_link_primitive(assignment_type, key, principal_name, identity_type, group_name):
        if assignment_type == 'group_member':
            return GroupMembership(f"{key}_grp_member", ATTACK_PATH,
                                   principal_ref=principal_name, principal_type=identity_type,
                                   group_ref=group_name)
        return GroupOwnership(f"{key}_grp_owner", ATTACK_PATH,
                              principal_ref=principal_name, principal_type=identity_type,
                              group_ref=group_name)

    # ---- ApplicationOwnershipAbuse -----------------------------------------
    def macro_application_ownership_abuse(
        self, attack_config: Dict, users: Dict, applications: Dict, domain: str,
        mode: str = 'random', entities: Optional[Dict] = None,
        path_name: Optional[str] = None, used_apps: Optional[set] = None,
        used_users: Optional[set] = None
    ) -> Dict:
        """ApplicationOwnershipAbuse as generic building blocks (Phase 4 macro).

        The attacker OWNS a high-priv app (AppOwnership) -> can add credentials ->
        authenticate as its SP, which carries the privileges (entra_role / api_perm).
        Azure AD forbids GROUPS owning apps, so group_member/group_owner fall back to
        direct (parity with the legacy method). A 'helpdesk' scenario adds a second
        user with Helpdesk Administrator (who can reset the owner's password).
        Returns {primitives, credentials, groups, summary}.
        """
        identity_type = attack_config.get('initial_access', 'user')
        entry_point = attack_config.get('entry_point', 'compromised_identity')
        scenario = attack_config.get('scenario', 'direct')
        assignment_type = attack_config.get('assignment_type', 'direct')
        if assignment_type in ('group_member', 'group_owner'):
            logging.warning(
                f"{path_name}: assignment_type '{assignment_type}' is not supported for "
                "ApplicationOwnershipAbuse (Azure AD forbids group app owners). Falling back to 'direct'.")
            assignment_type = 'direct'
        if scenario == 'helpdesk' and identity_type == 'service_principal':
            logging.warning(f"{path_name}: helpdesk scenario needs a user; using user initial access.")
            identity_type = 'user'

        key = self._attack_path_key(mode, path_name)
        if mode == 'random':
            app_name, principal_name, second_user_name = self._select_random_entities_app_ownership(
                users, applications, scenario, identity_type, used_apps, used_users)
        else:
            app_name, principal_name, second_user_name = self._select_targeted_entities_app_ownership(
                users, applications, entities, scenario, identity_type, path_name)

        primitives = []
        # The principal owns the target app (groups can't own apps -> always direct).
        primitives.append(AppOwnership(
            f"{key}_app_owner", ATTACK_PATH, principal_ref=principal_name,
            principal_type=identity_type, app_ref=app_name))
        access_lines = [f"Owned Application: {app_name}"]

        if scenario == 'helpdesk' and identity_type == 'user':
            # The operator compromises the helpdesk admin, who resets the owner's password.
            primitives.append(EntraRoleAssignment(
                f"{key}_helpdesk", ATTACK_PATH, principal_ref=second_user_name,
                principal_type='user', role=self.HELPDESK_ADMIN_ROLE_ID))
            credentials = {
                "initial_access": "user",
                "user_principal_name": f"{second_user_name}@{domain}",
                "password": users[second_user_name]['password'],
                "entry_point": entry_point,
            }
            access_lines.append(
                f"Helpdesk Admin (resets {principal_name}'s password): {second_user_name}@{domain}")
        else:
            credentials = self._initial_access_credentials(
                identity_type, principal_name, users, domain, entry_point, key, primitives)

        priv_prims, entra_role_ids, api_perm_ids, api_type = self._app_privilege_primitives(
            attack_config, app_name, key)
        primitives.extend(priv_prims)

        summary = {
            "path_name": path_name, "key": key, "technique": "ApplicationOwnershipAbuse",
            "identity_type": identity_type, "principal_name": principal_name,
            "assignment_type": "direct", "group_name": None, "app_name": app_name,
            "access_lines": access_lines, "show_target_app": False,
            "entra_role_ids": entra_role_ids, "api_perm_ids": api_perm_ids, "api_type": api_type,
        }
        return {"primitives": primitives, "credentials": credentials, "groups": {}, "summary": summary}

    # ---- Application / Cloud Application Administrator Abuse -----------------
    def macro_application_administrator_abuse(self, attack_config, users, applications, domain,
                                              mode='random', entities=None, path_name=None,
                                              used_apps=None, used_users=None) -> Dict:
        return self._macro_admin_role_abuse(
            attack_config, users, applications, domain, APP_ADMIN_ROLE_ID,
            "Application Administrator", "ApplicationAdministratorAbuse",
            mode, entities, path_name, used_apps, used_users)

    def macro_cloud_app_administrator_abuse(self, attack_config, users, applications, domain,
                                            mode='random', entities=None, path_name=None,
                                            used_apps=None, used_users=None) -> Dict:
        return self._macro_admin_role_abuse(
            attack_config, users, applications, domain, CLOUD_APP_ADMIN_ROLE_ID,
            "Cloud Application Administrator", "CloudAppAdministratorAbuse",
            mode, entities, path_name, used_apps, used_users)

    def _macro_admin_role_abuse(self, attack_config, users, applications, domain, admin_role_id,
                                role_label, technique, mode, entities, path_name,
                                used_apps, used_users) -> Dict:
        """Shared macro for Application/Cloud Application Administrator abuse.

        The attacker holds the admin Entra role (directory-wide or scoped to one app)
        -> can add credentials to the target app -> authenticate as it. The role can
        go to the principal directly or to a group (group_member / group_owner).
        Returns {primitives, credentials, groups, summary}.
        """
        identity_type = attack_config.get('initial_access', 'user')
        entry_point = attack_config.get('entry_point', 'compromised_identity')
        assignment_type = attack_config.get('assignment_type', 'direct')
        scope = attack_config.get('scope', 'directory')

        key = self._attack_path_key(mode, path_name)
        if mode == 'random':
            app_name, principal_name = self._select_random_entities_app_administrator(
                users, applications, identity_type, used_apps, used_users)
        else:
            app_name, principal_name = self._select_targeted_entities_app_administrator(
                users, applications, entities, identity_type, path_name)

        scope_app_ref = app_name if scope == 'application' else None
        primitives, groups = [], {}
        if assignment_type in ('group_member', 'group_owner'):
            group_spec = self._attack_group(assignment_type, principal_name, identity_type)
            group_name = group_spec['display_name']
            groups[group_name] = group_spec
            primitives.append(EntraRoleAssignment(
                f"{key}_admin_role", ATTACK_PATH, principal_ref=group_name,
                principal_type='group', role=admin_role_id, scope_app_ref=scope_app_ref))
            primitives.append(self._group_link_primitive(
                assignment_type, key, principal_name, identity_type, group_name))
        else:
            group_name = None
            primitives.append(EntraRoleAssignment(
                f"{key}_admin_role", ATTACK_PATH, principal_ref=principal_name,
                principal_type=identity_type, role=admin_role_id, scope_app_ref=scope_app_ref))

        credentials = self._initial_access_credentials(
            identity_type, principal_name, users, domain, entry_point, key, primitives)
        priv_prims, entra_role_ids, api_perm_ids, api_type = self._app_privilege_primitives(
            attack_config, app_name, key)
        primitives.extend(priv_prims)

        scope_str = f" (scoped to application {app_name})" if scope_app_ref else " (directory-wide)"
        summary = {
            "path_name": path_name, "key": key, "technique": technique,
            "identity_type": identity_type, "principal_name": principal_name,
            "assignment_type": assignment_type, "group_name": group_name, "app_name": app_name,
            "access_lines": [f"Principal Role: {role_label}{scope_str}"], "show_target_app": True,
            "entra_role_ids": entra_role_ids, "api_perm_ids": api_perm_ids, "api_type": api_type,
        }
        return {"primitives": primitives, "credentials": credentials, "groups": groups, "summary": summary}

    # ---- ManagedIdentityTheft ----------------------------------------------
    def macro_managed_identity_theft(
        self, attack_config: Dict, applications: Dict, key_vaults: Dict,
        storage_accounts: Dict, users: Dict, domain: str, virtual_machines: Dict,
        logic_apps: Dict, automation_accounts: Dict, function_apps: Dict,
        mode: str = 'random', entities: Optional[Dict] = None, path_name: Optional[str] = None,
        used_apps: Optional[set] = None, used_users: Optional[set] = None,
        cosmos_dbs: Optional[Dict] = None
    ) -> Dict:
        """ManagedIdentityTheft as generic building blocks (Phase 4 macro).

        The attacker holds Contributor on a SOURCE compute resource (VM/Logic App/
        Automation/Function) -> runs code -> steals the source's managed identity
        token -> the MI has grants on a TARGET (KV/Storage/Cosmos) holding the looted
        app's credential.

        Building blocks:
          1. AzureRbacAssignment — source-specific Contributor to the principal/group.
          2. AzureRbacAssignment(s) — the MI's grants on the target (per target type;
                               data_plane=cosmos_sql for Cosmos).
          3. AppCredential — the looted app's secret/certificate.
          4. DataInject(s) — plant that credential in the target (none for Cosmos: TF
                               can't write Cosmos items).
          5. EntraRoleAssignment / ApiPermission — the looted app's privileges.
          6. GroupMembership / GroupOwnership — for indirect (group-based) access.
          7. AppCredential — SP initial-access secret (service_principal only).
        Returns {primitives, credentials, groups, summary}.
        """
        cosmos_dbs = cosmos_dbs or {}
        source_type = attack_config.get('source_type', 'vm')
        target_resource_type = attack_config.get('target_resource_type')
        entry_point = attack_config.get('entry_point', 'compromised_identity')
        identity_type = attack_config.get('initial_access', 'user')
        credential_type = attack_config.get('credential_type', 'secret')
        assignment_type = attack_config.get('assignment_type', 'direct')

        key = self._attack_path_key(mode, path_name)
        if mode == 'random':
            app_name, target_name, source_name, principal_name = self._select_random_entities_mi_theft(
                applications, key_vaults, storage_accounts, virtual_machines, logic_apps,
                automation_accounts, function_apps, users, source_type, target_resource_type,
                identity_type, used_apps, used_users, cosmos_dbs=cosmos_dbs)
        else:
            app_name, target_name, source_name, principal_name = self._select_targeted_entities_mi_theft(
                applications, key_vaults, storage_accounts, virtual_machines, logic_apps,
                automation_accounts, function_apps, users, entities, source_type,
                target_resource_type, identity_type, path_name, cosmos_dbs=cosmos_dbs)

        primitives, groups = [], {}

        # 1. Source-specific Contributor to the initial-access principal (or group).
        src_role = self.SOURCE_CONTRIBUTOR_ROLE.get(source_type, 'Contributor')
        src_scope_rtype = self.SOURCE_SCOPE_RESOURCE_TYPE.get(source_type, 'virtual_machine')
        if assignment_type in ('group_member', 'group_owner'):
            group_spec = self._attack_group(assignment_type, principal_name, identity_type)
            group_name = group_spec['display_name']
            groups[group_name] = group_spec
            primitives.append(AzureRbacAssignment(
                f"{key}_src_contrib", ATTACK_PATH, principal_ref=group_name,
                principal_type='group', role=src_role, scope_type='resource',
                scope_resource_type=src_scope_rtype, scope_ref=source_name))
            primitives.append(self._group_link_primitive(
                assignment_type, key, principal_name, identity_type, group_name))
        else:
            group_name = None
            primitives.append(AzureRbacAssignment(
                f"{key}_src_contrib", ATTACK_PATH, principal_ref=principal_name,
                principal_type=identity_type, role=src_role, scope_type='resource',
                scope_resource_type=src_scope_rtype, scope_ref=source_name))

        # 2. The source's managed identity gains access to the target.
        mi_common = dict(
            principal_ref=source_name, principal_type='managed_identity',
            mi_source_type=source_type, scope_type='resource',
            scope_resource_type=target_resource_type, scope_ref=target_name)
        if target_resource_type == 'key_vault':
            roles = list(self.MI_KV_ROLES)
            if credential_type == 'certificate':
                roles.append(self.MI_KV_CERTIFICATE_ROLE)
            for idx, role in enumerate(roles):
                primitives.append(AzureRbacAssignment(f"{key}_mi_kv_{idx}", ATTACK_PATH, role=role, **mi_common))
        elif target_resource_type == 'storage_account':
            for idx, role in enumerate(self.MI_STORAGE_ROLES):
                primitives.append(AzureRbacAssignment(f"{key}_mi_sa_{idx}", ATTACK_PATH, role=role, **mi_common))
        elif target_resource_type == 'cosmos_db':
            primitives.append(AzureRbacAssignment(
                f"{key}_mi_cosmos", ATTACK_PATH, role=self.COSMOS_DATA_CONTRIBUTOR_ROLE,
                data_plane='cosmos_sql', **mi_common))

        # 3. Mint the looted app's credential + 4. plant it in the target.
        app_cred_key = f"{key}_app_credential"
        cert_paths = None
        if credential_type == 'certificate':
            cert_path, key_path, pfx_path = generate_certificate_and_key(app_name)
            cert_paths = {"cert": cert_path, "key": key_path, "pfx": pfx_path}
            primitives.append(AppCredential(
                app_cred_key, ATTACK_PATH, app_ref=app_name, type="certificate",
                certificate_path=cert_path, display_name="BadZureClientCertificate"))
        else:
            primitives.append(AppCredential(
                app_cred_key, ATTACK_PATH, app_ref=app_name, type="password",
                display_name="BadZureClientSecret"))
        primitives.extend(self._mi_data_injects(
            key, target_resource_type, target_name, app_name, credential_type,
            app_cred_key, cert_paths))

        # 5. The looted app's privileges + 6/7. initial-access credentials.
        priv_prims, entra_role_ids, api_perm_ids, api_type = self._app_privilege_primitives(
            attack_config, app_name, key)
        primitives.extend(priv_prims)
        credentials = self._initial_access_credentials(
            identity_type, principal_name, users, domain, entry_point, key, primitives)

        summary = {
            "path_name": path_name, "key": key, "technique": "ManagedIdentityTheft",
            "identity_type": identity_type, "principal_name": principal_name,
            "assignment_type": assignment_type, "group_name": group_name, "app_name": app_name,
            "source_type": source_type, "source_name": source_name,
            "target_resource_type": target_resource_type, "target_name": target_name,
            "access_lines": [
                f"Source Resource: {source_type} - {source_name} (with {src_role})",
                f"Managed Identity → Target: {target_resource_type} - {target_name}",
            ],
            "show_target_app": True,
            "entra_role_ids": entra_role_ids, "api_perm_ids": api_perm_ids, "api_type": api_type,
        }
        return {"primitives": primitives, "credentials": credentials, "groups": groups, "summary": summary}

    def _mi_data_injects(self, key, target_type, target_name, app_name, credential_type,
                         app_cred_key, cert_paths):
        """The data_injects that plant the looted app's credential into the MI's
        target (parity names with legacy main.tf). Cosmos plants nothing (TF can't
        write Cosmos items)."""
        injects = []
        if target_type == 'key_vault':
            if credential_type == 'certificate':
                injects.append(DataInject(
                    f"{key}_kv_cert", ATTACK_PATH, material="app_certificate",
                    location_type="key_vault_certificate", location_ref=target_name,
                    name=f"mi-certificate-{app_name}", source_ref=app_name,
                    file_path=cert_paths["pfx"], pfx_password=""))
                injects.append(DataInject(
                    f"{key}_kv_certid", ATTACK_PATH, material="app_client_id",
                    location_type="key_vault_secret", location_ref=target_name,
                    name=f"mi-client-id-{app_name}", source_ref=app_name))
            else:
                injects.append(DataInject(
                    f"{key}_kv_secret", ATTACK_PATH, material="app_secret",
                    location_type="key_vault_secret", location_ref=target_name,
                    name=f"mi-client-secret-{app_name}", credential_ref=app_cred_key))
                injects.append(DataInject(
                    f"{key}_kv_id", ATTACK_PATH, material="app_client_id",
                    location_type="key_vault_secret", location_ref=target_name,
                    name=f"mi-client-id-{app_name}", source_ref=app_name))
        elif target_type == 'storage_account':
            if credential_type == 'certificate':
                injects.append(DataInject(
                    f"{key}_sa_pem", ATTACK_PATH, material="app_certificate",
                    location_type="storage_blob", location_ref=target_name,
                    name=f"{app_name}-certificate.pem", source_ref=app_name,
                    file_path=cert_paths["cert"]))
                injects.append(DataInject(
                    f"{key}_sa_key", ATTACK_PATH, material="app_certificate",
                    location_type="storage_blob", location_ref=target_name,
                    name=f"{app_name}-private-key.key", source_ref=app_name,
                    file_path=cert_paths["key"]))
                injects.append(DataInject(
                    f"{key}_sa_id", ATTACK_PATH, material="app_client_id",
                    location_type="storage_blob", location_ref=target_name,
                    name=f"{app_name}-app-id.txt", source_ref=app_name))
            else:
                injects.append(DataInject(
                    f"{key}_sa_id", ATTACK_PATH, material="app_client_id",
                    location_type="storage_blob", location_ref=target_name,
                    name=f"{app_name}-app-id.txt", source_ref=app_name))
                injects.append(DataInject(
                    f"{key}_sa_secret", ATTACK_PATH, material="app_secret",
                    location_type="storage_blob", location_ref=target_name,
                    name=f"{app_name}-secret.txt", credential_ref=app_cred_key))
        # cosmos_db: no inject — TF can't write Cosmos items.
        return injects

    def macro_keyvault_secret_theft(
        self,
        attack_config: Dict,
        applications: Dict,
        keyvaults: Dict,
        users: Dict,
        service_principals: Dict,
        domain: str,
        mode: str = 'random',
        entities: Optional[Dict] = None,
        path_name: Optional[str] = None,
        used_apps: Optional[set] = None
    ) -> Dict:
        """KeyVaultSecretTheft expressed as generic building blocks (Phase 2 macro).

        Returns a flat list of generic primitives (not technique-shaped buckets)
        that the Terraform builder turns into the generic.tf resources. Entity
        selection and the method/entra_role/app_role/random
        resolution are REUSED verbatim from the legacy helpers, so random picks
        and high-priv-role logic stay identical.

        The chain, as building blocks:
          1. AppCredential   — mint a client secret on the target (high-priv) app.
          2. DataInject      — plant that secret in the Key Vault as
                               'client-secret-<app>' (material=app_secret).
          3. AzureRbacAssignment — grant the compromised principal (or its group)
                               'Key Vault Contributor' on the vault.
          4. EntraRoleAssignment / ApiPermission — the privileges the looted app
                               carries (what makes reading its secret an escalation).
          5. GroupMembership / GroupOwnership — for indirect (group-based) access.
          6. AppCredential (no inject) — for service_principal initial access, mint
                               the SP's own secret so the operator can authenticate;
                               surfaced via the generic_app_credentials TF output.

        Returns: {primitives, credentials, groups, summary}.
        """
        identity_type = attack_config.get('initial_access', 'user')
        if identity_type == 'managed_identity':
            raise ValueError(
                "KeyVaultSecretTheft does not support initial_access 'managed_identity'. "
                "Use 'ManagedIdentityTheft' with target_resource_type 'key_vault' instead."
            )

        assignment_type = attack_config.get('assignment_type', 'direct')

        # Attack-path key (same scheme as the legacy method, for output filtering).
        attack_path_id = ''.join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=6))
        if mode == 'targeted' and path_name:
            key = f"attack-path-{path_name}-{attack_path_id}"
        elif mode == 'random' and path_name:
            key = f"{path_name}-{attack_path_id}"
        else:
            key = f"attack-path-{attack_path_id}"

        # Entity selection — reuse the legacy selectors unchanged.
        if mode == 'random':
            app_name, kv_name, principal_name = self._select_random_entities_kv_secret_theft(
                applications, keyvaults, users, service_principals,
                identity_type, used_apps
            )
        else:
            app_name, kv_name, principal_name = self._select_targeted_entities_kv_secret_theft(
                applications, keyvaults, users,
                entities, identity_type, path_name
            )

        primitives = []
        groups = {}
        entry_point = attack_config.get('entry_point', 'compromised_identity')

        # 1. Mint the looted app's client secret + 2. plant it in the vault.
        cred_key = f"{key}_app_secret"
        primitives.append(AppCredential(
            cred_key, ATTACK_PATH, app_ref=app_name, type="password",
            display_name="BadZureClientSecret",
        ))
        primitives.append(DataInject(
            f"{key}_kv_secret", ATTACK_PATH,
            material="app_secret", location_type="key_vault_secret",
            location_ref=kv_name, name=f"client-secret-{app_name}",
            credential_ref=cred_key,
        ))

        # 3. Key Vault Contributor — to the principal directly, or to the group
        #    for indirect (group_member / group_owner) access.
        if assignment_type in ('group_member', 'group_owner'):
            if assignment_type == 'group_owner':
                group_spec = self.entity_generator.generate_attack_path_group(
                    owner_name=principal_name, owner_type=identity_type
                )
            else:
                group_spec = self.entity_generator.generate_attack_path_group()
            group_name = group_spec['display_name']
            groups[group_name] = group_spec

            primitives.append(AzureRbacAssignment(
                f"{key}_kv_access", ATTACK_PATH,
                principal_ref=group_name, principal_type="group",
                role="Key Vault Contributor", scope_type="resource",
                scope_resource_type="key_vault", scope_ref=kv_name,
            ))
            if assignment_type == 'group_member':
                primitives.append(GroupMembership(
                    f"{key}_grp_member", ATTACK_PATH,
                    principal_ref=principal_name, principal_type=identity_type,
                    group_ref=group_name,
                ))
            else:  # group_owner
                primitives.append(GroupOwnership(
                    f"{key}_grp_owner", ATTACK_PATH,
                    principal_ref=principal_name, principal_type=identity_type,
                    group_ref=group_name,
                ))
        else:
            group_name = None
            primitives.append(AzureRbacAssignment(
                f"{key}_kv_access", ATTACK_PATH,
                principal_ref=principal_name, principal_type=identity_type,
                role="Key Vault Contributor", scope_type="resource",
                scope_resource_type="key_vault", scope_ref=kv_name,
            ))

        # 4. The looted app's privileges. Reuse the legacy resolver, then
        #    translate its output into entra_role / api_permission blocks.
        legacy_roles, legacy_perms = {}, {}
        self._assign_app_privileges(attack_config, app_name, key, legacy_roles, legacy_perms)
        entra_role_ids, api_perm_ids, api_type = [], [], None
        if key in legacy_roles:
            entra_role_ids = legacy_roles[key]['role_ids']
            for idx, role_id in enumerate(entra_role_ids):
                primitives.append(EntraRoleAssignment(
                    f"{key}_app_role_{idx}", ATTACK_PATH,
                    principal_ref=app_name, principal_type="service_principal",
                    role=role_id,
                ))
        if key in legacy_perms:
            api_perm_ids = legacy_perms[key]['api_permission_ids']
            api_type = legacy_perms[key].get('api_type', 'graph')
            for idx, perm_id in enumerate(api_perm_ids):
                primitives.append(ApiPermission(
                    f"{key}_app_perm_{idx}", ATTACK_PATH,
                    principal_ref=app_name, permission_id=perm_id, api_type=api_type,
                ))

        # 5. Initial-access credentials for the operator.
        if identity_type == 'user':
            credentials = {
                "initial_access": "user",
                "user_principal_name": f"{principal_name}@{domain}",
                "password": users[principal_name]['password'],
                "entry_point": entry_point,
            }
        else:  # service_principal — mint its own secret, surfaced via TF output.
            sp_cred_key = f"{key}_initial_sp"
            primitives.append(AppCredential(
                sp_cred_key, ATTACK_PATH, app_ref=principal_name, type="password",
                display_name="BadZureInitialAccess",
            ))
            credentials = {
                "initial_access": "service_principal",
                "service_principal_name": principal_name,
                "entry_point": entry_point,
                # Origin-prefixed key the generic_app_credentials output is keyed by.
                "generic_credential_key": f"ap:{sp_cred_key}",
            }

        summary = {
            "path_name": path_name,
            "key": key,
            "technique": "KeyVaultSecretTheft",
            "identity_type": identity_type,
            "principal_name": principal_name,
            "assignment_type": assignment_type,
            "group_name": group_name,
            "key_vault": kv_name,
            "app_name": app_name,
            "entra_role_ids": entra_role_ids,
            "api_perm_ids": api_perm_ids,
            "api_type": api_type,
        }

        return {
            "primitives": primitives,
            "credentials": credentials,
            "groups": groups,
            "summary": summary,
        }

    def macro_storage_certificate_theft(
        self,
        attack_config: Dict,
        applications: Dict,
        storage_accounts: Dict,
        users: Dict,
        service_principals: Dict,
        domain: str,
        mode: str = 'random',
        entities: Optional[Dict] = None,
        path_name: Optional[str] = None,
        used_apps: Optional[set] = None
    ) -> Dict:
        """StorageCertificateTheft expressed as generic building blocks (Phase 4 macro).

        Emits a flat list of generic primitives (not technique-shaped buckets).
        Entity selection and the method/entra_role/app_role/random resolution are REUSED
        verbatim from the legacy helpers, so picks stay identical.

        The chain, as building blocks:
          1. AppCredential(certificate) — mint a cert credential on the looted (high-
                               priv) app, so the stolen cert authenticates as it.
          2. DataInject x3   — plant the .key / .pem / .pfx in the storage account as
                               blobs (material=app_certificate; generic.tf gives each
                               its own private container). Parity blob names with legacy.
          3. AzureRbacAssignment — grant the compromised principal (or its group)
                               'Storage Blob Data Reader' on the storage account.
          4. EntraRoleAssignment / ApiPermission — the looted app's privileges.
          5. GroupMembership / GroupOwnership — for indirect (group-based) access.
          6. AppCredential (no inject) — for service_principal initial access, mint the
                               SP's own secret; surfaced via the generic_app_credentials
                               TF output.

        Returns: {primitives, credentials, groups, summary}.
        """
        identity_type = attack_config.get('initial_access', 'user')
        if identity_type == 'managed_identity':
            raise ValueError(
                "StorageCertificateTheft does not support initial_access 'managed_identity'. "
                "Use 'ManagedIdentityTheft' with target_resource_type 'storage_account' instead."
            )

        assignment_type = attack_config.get('assignment_type', 'direct')

        # Attack-path key (same scheme as the legacy method, for output filtering).
        attack_path_id = ''.join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=6))
        if mode == 'targeted' and path_name:
            key = f"attack-path-{path_name}-{attack_path_id}"
        elif mode == 'random' and path_name:
            key = f"{path_name}-{attack_path_id}"
        else:
            key = f"attack-path-{attack_path_id}"

        # Entity selection — reuse the legacy selectors unchanged.
        if mode == 'random':
            app_name, sa_name, principal_name = self._select_random_entities_storage_cert_theft(
                applications, storage_accounts, users, service_principals,
                identity_type, used_apps
            )
        else:
            app_name, sa_name, principal_name = self._select_targeted_entities_storage_cert_theft(
                applications, storage_accounts, users,
                entities, identity_type, path_name
            )

        primitives = []
        groups = {}
        entry_point = attack_config.get('entry_point', 'compromised_identity')

        # 1. Mint the looted app's certificate credential + 2. plant .key/.pem/.pfx
        #    as blobs. The cert files are generated on disk here (real files the
        #    generic storage_blob inject uploads via file_path).
        cert_path, key_path, pfx_path = generate_certificate_and_key(app_name)
        primitives.append(AppCredential(
            f"{key}_app_certificate", ATTACK_PATH, app_ref=app_name,
            type="certificate", certificate_path=cert_path,
            display_name="BadZureClientCertificate",
        ))
        # Parity blob names with legacy main.tf (app-private-key.key / -certificate.pem / .pfx).
        for sub, blob_name, file_path in (
            ("blob_key", f"{app_name}-private-key.key", key_path),
            ("blob_pem", f"{app_name}-certificate.pem", cert_path),
            ("blob_pfx", f"{app_name}-certificate.pfx", pfx_path),
        ):
            primitives.append(DataInject(
                f"{key}_{sub}", ATTACK_PATH, material="app_certificate",
                location_type="storage_blob", location_ref=sa_name,
                name=blob_name, source_ref=app_name, file_path=file_path,
            ))

        # 3. Storage Blob Data Reader — to the principal directly, or to the group
        #    for indirect (group_member / group_owner) access.
        if assignment_type in ('group_member', 'group_owner'):
            if assignment_type == 'group_owner':
                group_spec = self.entity_generator.generate_attack_path_group(
                    owner_name=principal_name, owner_type=identity_type
                )
            else:
                group_spec = self.entity_generator.generate_attack_path_group()
            group_name = group_spec['display_name']
            groups[group_name] = group_spec

            primitives.append(AzureRbacAssignment(
                f"{key}_sa_access", ATTACK_PATH,
                principal_ref=group_name, principal_type="group",
                role="Storage Blob Data Reader", scope_type="resource",
                scope_resource_type="storage_account", scope_ref=sa_name,
            ))
            if assignment_type == 'group_member':
                primitives.append(GroupMembership(
                    f"{key}_grp_member", ATTACK_PATH,
                    principal_ref=principal_name, principal_type=identity_type,
                    group_ref=group_name,
                ))
            else:  # group_owner
                primitives.append(GroupOwnership(
                    f"{key}_grp_owner", ATTACK_PATH,
                    principal_ref=principal_name, principal_type=identity_type,
                    group_ref=group_name,
                ))
        else:
            group_name = None
            primitives.append(AzureRbacAssignment(
                f"{key}_sa_access", ATTACK_PATH,
                principal_ref=principal_name, principal_type=identity_type,
                role="Storage Blob Data Reader", scope_type="resource",
                scope_resource_type="storage_account", scope_ref=sa_name,
            ))

        # 4. The looted app's privileges. Reuse the legacy resolver, then translate.
        legacy_roles, legacy_perms = {}, {}
        self._assign_app_privileges(attack_config, app_name, key, legacy_roles, legacy_perms)
        entra_role_ids, api_perm_ids, api_type = [], [], None
        if key in legacy_roles:
            entra_role_ids = legacy_roles[key]['role_ids']
            for idx, role_id in enumerate(entra_role_ids):
                primitives.append(EntraRoleAssignment(
                    f"{key}_app_role_{idx}", ATTACK_PATH,
                    principal_ref=app_name, principal_type="service_principal",
                    role=role_id,
                ))
        if key in legacy_perms:
            api_perm_ids = legacy_perms[key]['api_permission_ids']
            api_type = legacy_perms[key].get('api_type', 'graph')
            for idx, perm_id in enumerate(api_perm_ids):
                primitives.append(ApiPermission(
                    f"{key}_app_perm_{idx}", ATTACK_PATH,
                    principal_ref=app_name, permission_id=perm_id, api_type=api_type,
                ))

        # 5. Initial-access credentials for the operator.
        if identity_type == 'user':
            credentials = {
                "initial_access": "user",
                "user_principal_name": f"{principal_name}@{domain}",
                "password": users[principal_name]['password'],
                "entry_point": entry_point,
            }
        else:  # service_principal — mint its own secret, surfaced via TF output.
            sp_cred_key = f"{key}_initial_sp"
            primitives.append(AppCredential(
                sp_cred_key, ATTACK_PATH, app_ref=principal_name, type="password",
                display_name="BadZureInitialAccess",
            ))
            credentials = {
                "initial_access": "service_principal",
                "service_principal_name": principal_name,
                "entry_point": entry_point,
                "generic_credential_key": f"ap:{sp_cred_key}",
            }

        summary = {
            "path_name": path_name,
            "key": key,
            "technique": "StorageCertificateTheft",
            "identity_type": identity_type,
            "principal_name": principal_name,
            "assignment_type": assignment_type,
            "group_name": group_name,
            "storage_account": sa_name,
            "app_name": app_name,
            "entra_role_ids": entra_role_ids,
            "api_perm_ids": api_perm_ids,
            "api_type": api_type,
        }

        return {
            "primitives": primitives,
            "credentials": credentials,
            "groups": groups,
            "summary": summary,
        }

    # Cosmos DB Built-in Data Contributor — a well-known SQL role definition GUID,
    # the same one main.tf hardcodes for the legacy Cosmos data-plane grant.
    COSMOS_DATA_CONTRIBUTOR_ROLE = "00000000-0000-0000-0000-000000000002"

    def macro_cosmosdb_secret_theft(
        self,
        attack_config: Dict,
        applications: Dict,
        cosmos_dbs: Dict,
        users: Dict,
        service_principals: Dict,
        domain: str,
        mode: str = 'random',
        entities: Optional[Dict] = None,
        path_name: Optional[str] = None,
        used_apps: Optional[set] = None
    ) -> Dict:
        """CosmosDBSecretTheft expressed as generic building blocks (Phase 4 macro).

        Emits generic primitives. Unlike KV/Storage there is NO data_inject:
        Terraform can't write items into
        Cosmos, so the looted app's secret is minted but not planted (the operator
        places it). The escalation is the Cosmos DATA-PLANE grant.

        The chain, as building blocks:
          1. AppCredential(password) — mint the looted (high-priv) app's client secret.
          2. AzureRbacAssignment(data_plane=cosmos_sql) — grant the compromised
                               principal (or its group) 'Cosmos DB Built-in Data
                               Contributor' on the Cosmos account.
          3. EntraRoleAssignment / ApiPermission — the looted app's privileges.
          4. GroupMembership / GroupOwnership — for indirect (group-based) access.
          5. AppCredential (no inject) — for service_principal initial access, mint the
                               SP's own secret; surfaced via the generic_app_credentials
                               TF output.

        Returns: {primitives, credentials, groups, summary}.
        """
        identity_type = attack_config.get('initial_access', 'user')
        if identity_type == 'managed_identity':
            raise ValueError(
                "CosmosDBSecretTheft does not support initial_access 'managed_identity'. "
                "Use 'ManagedIdentityTheft' with target_resource_type 'cosmos_db' instead."
            )

        assignment_type = attack_config.get('assignment_type', 'direct')

        # Attack-path key (same scheme as the legacy method, for output filtering).
        attack_path_id = ''.join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=6))
        if mode == 'targeted' and path_name:
            key = f"attack-path-{path_name}-{attack_path_id}"
        elif mode == 'random' and path_name:
            key = f"{path_name}-{attack_path_id}"
        else:
            key = f"attack-path-{attack_path_id}"

        # Entity selection — reuse the legacy selectors unchanged.
        if mode == 'random':
            app_name, cosmos_db_name, principal_name = self._select_random_entities_cosmos_secret_theft(
                applications, cosmos_dbs, users, service_principals,
                identity_type, used_apps
            )
        else:
            app_name, cosmos_db_name, principal_name = self._select_targeted_entities_cosmos_secret_theft(
                applications, cosmos_dbs, users,
                entities, identity_type, path_name
            )

        primitives = []
        groups = {}
        entry_point = attack_config.get('entry_point', 'compromised_identity')

        # 1. Mint the looted app's client secret (NOT planted — no Cosmos inject).
        primitives.append(AppCredential(
            f"{key}_app_secret", ATTACK_PATH, app_ref=app_name, type="password",
            display_name="BadZureClientSecret",
        ))

        # 2. Cosmos DB Built-in Data Contributor (data-plane) — to the principal
        #    directly, or to the group for indirect (group_member / group_owner) access.
        if assignment_type in ('group_member', 'group_owner'):
            if assignment_type == 'group_owner':
                group_spec = self.entity_generator.generate_attack_path_group(
                    owner_name=principal_name, owner_type=identity_type
                )
            else:
                group_spec = self.entity_generator.generate_attack_path_group()
            group_name = group_spec['display_name']
            groups[group_name] = group_spec

            primitives.append(AzureRbacAssignment(
                f"{key}_cosmos_access", ATTACK_PATH,
                principal_ref=group_name, principal_type="group",
                role=self.COSMOS_DATA_CONTRIBUTOR_ROLE, scope_type="resource",
                scope_resource_type="cosmos_db", scope_ref=cosmos_db_name,
                data_plane="cosmos_sql",
            ))
            if assignment_type == 'group_member':
                primitives.append(GroupMembership(
                    f"{key}_grp_member", ATTACK_PATH,
                    principal_ref=principal_name, principal_type=identity_type,
                    group_ref=group_name,
                ))
            else:  # group_owner
                primitives.append(GroupOwnership(
                    f"{key}_grp_owner", ATTACK_PATH,
                    principal_ref=principal_name, principal_type=identity_type,
                    group_ref=group_name,
                ))
        else:
            group_name = None
            primitives.append(AzureRbacAssignment(
                f"{key}_cosmos_access", ATTACK_PATH,
                principal_ref=principal_name, principal_type=identity_type,
                role=self.COSMOS_DATA_CONTRIBUTOR_ROLE, scope_type="resource",
                scope_resource_type="cosmos_db", scope_ref=cosmos_db_name,
                data_plane="cosmos_sql",
            ))

        # 3. The looted app's privileges. Reuse the legacy resolver, then translate.
        legacy_roles, legacy_perms = {}, {}
        self._assign_app_privileges(attack_config, app_name, key, legacy_roles, legacy_perms)
        entra_role_ids, api_perm_ids, api_type = [], [], None
        if key in legacy_roles:
            entra_role_ids = legacy_roles[key]['role_ids']
            for idx, role_id in enumerate(entra_role_ids):
                primitives.append(EntraRoleAssignment(
                    f"{key}_app_role_{idx}", ATTACK_PATH,
                    principal_ref=app_name, principal_type="service_principal",
                    role=role_id,
                ))
        if key in legacy_perms:
            api_perm_ids = legacy_perms[key]['api_permission_ids']
            api_type = legacy_perms[key].get('api_type', 'graph')
            for idx, perm_id in enumerate(api_perm_ids):
                primitives.append(ApiPermission(
                    f"{key}_app_perm_{idx}", ATTACK_PATH,
                    principal_ref=app_name, permission_id=perm_id, api_type=api_type,
                ))

        # 4. Initial-access credentials for the operator.
        if identity_type == 'user':
            credentials = {
                "initial_access": "user",
                "user_principal_name": f"{principal_name}@{domain}",
                "password": users[principal_name]['password'],
                "entry_point": entry_point,
            }
        else:  # service_principal — mint its own secret, surfaced via TF output.
            sp_cred_key = f"{key}_initial_sp"
            primitives.append(AppCredential(
                sp_cred_key, ATTACK_PATH, app_ref=principal_name, type="password",
                display_name="BadZureInitialAccess",
            ))
            credentials = {
                "initial_access": "service_principal",
                "service_principal_name": principal_name,
                "entry_point": entry_point,
                "generic_credential_key": f"ap:{sp_cred_key}",
            }

        summary = {
            "path_name": path_name,
            "key": key,
            "technique": "CosmosDBSecretTheft",
            "identity_type": identity_type,
            "principal_name": principal_name,
            "assignment_type": assignment_type,
            "group_name": group_name,
            "cosmos_db": cosmos_db_name,
            "app_name": app_name,
            "entra_role_ids": entra_role_ids,
            "api_perm_ids": api_perm_ids,
            "api_type": api_type,
        }

        return {
            "primitives": primitives,
            "credentials": credentials,
            "groups": groups,
            "summary": summary,
        }

    # ========================================================================
    # Random Mode Entity Selection
    # ========================================================================

    def _select_random_entities_app_ownership(
        self, users: Dict, applications: Dict, scenario: str, identity_type: str,
        used_apps: set = None, used_users: set = None
    ) -> Tuple[str, str, str]:
        """Select random entities for Application Ownership Abuse.
        
        Args:
            users: Dictionary of users
            applications: Dictionary of applications
            scenario: 'direct' or 'helpdesk'
            identity_type: 'user' or 'service_principal'
            used_apps: Set of already-used application names
            used_users: Set of already-used user/principal names
        
        Returns:
            Tuple of (app_name, principal_name, second_user_name)
        """
        app_keys = list(applications.keys())
        
        # Exclude used applications
        if used_apps:
            available_apps = [app for app in app_keys if app not in used_apps]
            if available_apps:
                app_keys = available_apps
        
        app_name = random.choice(app_keys)
        
        if identity_type == 'user':
            user_keys = list(users.keys())
            
            # Exclude used users
            if used_users:
                available_users = [user for user in user_keys if user not in used_users]
                if available_users:
                    user_keys = available_users
            
            principal_name = random.choice(user_keys)
            second_user_name = random.choice(user_keys) if scenario == "helpdesk" else principal_name
        else:  # service_principal
            # For service principal, select a different application as the owner
            sp_keys = [k for k in applications.keys() if k != app_name]
            if sp_keys:
                principal_name = random.choice(sp_keys)
            else:
                # Fallback to the same app if no other apps available
                principal_name = app_name
            second_user_name = principal_name  # Not used for service_principal
        
        return app_name, principal_name, second_user_name
    
    def _select_random_entities_app_administrator(
        self, users: Dict, applications: Dict, identity_type: str,
        used_apps: set = None, used_users: set = None
    ) -> Tuple[str, str]:
        """Select random entities for Application Administrator Abuse.
        
        Args:
            users: Dictionary of users
            applications: Dictionary of applications
            identity_type: 'user' or 'service_principal'
            used_apps: Set of already-used application names
            used_users: Set of already-used user/principal names
        
        Returns:
            Tuple of (app_name, principal_name)
        """
        app_keys = list(applications.keys())
        
        # Exclude used applications
        if used_apps:
            available_apps = [app for app in app_keys if app not in used_apps]
            if available_apps:
                app_keys = available_apps
        
        app_name = random.choice(app_keys)
        
        if identity_type == 'user':
            user_keys = list(users.keys())
            
            # Exclude used users
            if used_users:
                available_users = [user for user in user_keys if user not in used_users]
                if available_users:
                    user_keys = available_users
            
            principal_name = random.choice(user_keys)
        else:  # service_principal
            # For service principal, select a different application
            sp_keys = [k for k in applications.keys() if k != app_name]
            if sp_keys:
                principal_name = random.choice(sp_keys)
            else:
                # Fallback to the same app if no other apps available
                principal_name = app_name
        
        return app_name, principal_name
    
    def _select_random_entities_kv_secret_theft(
        self, applications: Dict, keyvaults: Dict, users: Dict,
        service_principals: Dict, identity_type: str,
        used_apps: set = None
    ) -> Tuple[str, str, str]:
        """Select random entities for Key Vault Secret Theft."""
        app_keys = list(applications.keys())
        
        # Exclude used applications
        if used_apps:
            available_apps = [app for app in app_keys if app not in used_apps]
            if available_apps:
                app_keys = available_apps
        
        app_name = random.choice(app_keys)
        kv_name = random.choice(list(keyvaults.keys()))
        
        if identity_type == "user":
            principal_name = random.choice(list(users.keys()))
        elif identity_type == "service_principal":
            principal_name = random.choice(list(service_principals.keys()))
        
        return app_name, kv_name, principal_name
    
    def _select_random_entities_storage_cert_theft(
        self, applications: Dict, storage_accounts: Dict, users: Dict,
        service_principals: Dict, identity_type: str,
        used_apps: set = None
    ) -> Tuple[str, str, str]:
        """Select random entities for Storage Certificate Theft."""
        app_keys = list(applications.keys())
        
        # Exclude used applications
        if used_apps:
            available_apps = [app for app in app_keys if app not in used_apps]
            if available_apps:
                app_keys = available_apps
        
        app_name = random.choice(app_keys)
        sa_name = random.choice(list(storage_accounts.keys()))
        
        if identity_type == "user":
            principal_name = random.choice(list(users.keys()))
        elif identity_type == "service_principal":
            principal_name = random.choice(list(service_principals.keys()))
        
        return app_name, sa_name, principal_name

    def _select_random_entities_cosmos_secret_theft(
        self, applications: Dict, cosmos_dbs: Dict, users: Dict,
        service_principals: Dict, identity_type: str,
        used_apps: set = None
    ) -> Tuple[str, str, str]:
        """Select random entities for Cosmos DB Secret Theft."""
        app_keys = list(applications.keys())

        if used_apps:
            available_apps = [app for app in app_keys if app not in used_apps]
            if available_apps:
                app_keys = available_apps

        app_name = random.choice(app_keys)
        cosmos_db_name = random.choice(list(cosmos_dbs.keys()))

        if identity_type == "user":
            principal_name = random.choice(list(users.keys()))
        elif identity_type == "service_principal":
            principal_name = random.choice(list(service_principals.keys()))

        return app_name, cosmos_db_name, principal_name

    def _select_random_entities_mi_theft(
        self, applications: Dict, key_vaults: Dict, storage_accounts: Dict,
        virtual_machines: Dict, logic_apps: Dict, automation_accounts: Dict, function_apps: Dict, users: Dict,
        source_type: str, target_resource_type: str, identity_type: str,
        used_apps: set = None, used_users: set = None,
        cosmos_dbs: Dict = None
    ) -> Tuple[str, str, str, str]:
        """Select random entities for Managed Identity Theft.

        Args:
            applications: Dictionary of applications
            key_vaults: Dictionary of key vaults
            storage_accounts: Dictionary of storage accounts
            virtual_machines: Dictionary of virtual machines
            logic_apps: Dictionary of logic apps
            automation_accounts: Dictionary of automation accounts
            function_apps: Dictionary of function apps
            users: Dictionary of users (used when identity_type is 'user')
            source_type: Type of source resource ('vm', 'logic_app', etc.)
            target_resource_type: Type of target resource ('key_vault', 'storage_account', 'cosmos_db')
            identity_type: Type of initial access identity ('user' or 'service_principal')
            used_apps: Set of already-used application names
            used_users: Set of already-used user names
            cosmos_dbs: Dictionary of Cosmos DB accounts

        Returns:
            Tuple of (app_name, target_name, source_name, principal_name)
        """
        app_keys = list(applications.keys())
        
        # Exclude used applications
        if used_apps:
            available_apps = [app for app in app_keys if app not in used_apps]
            if available_apps:
                app_keys = available_apps
        
        app_name = random.choice(app_keys)
        
        # Select source based on type
        if source_type == 'vm':
            source_name = random.choice(list(virtual_machines.keys()))
        elif source_type == 'logic_app':
            source_name = random.choice(list(logic_apps.keys()))
        elif source_type == 'automation_account':
            source_name = random.choice(list(automation_accounts.keys()))
        elif source_type == 'function_app':
            source_name = random.choice(list(function_apps.keys()))
        else:
            # Default to VM for unknown types
            source_name = random.choice(list(virtual_machines.keys()))
        
        # Select target resource
        if target_resource_type == 'key_vault':
            target_name = random.choice(list(key_vaults.keys()))
        elif target_resource_type == 'storage_account':
            target_name = random.choice(list(storage_accounts.keys()))
        elif target_resource_type == 'cosmos_db' and cosmos_dbs:
            target_name = random.choice(list(cosmos_dbs.keys()))
        else:
            # For future expansion: subscription, resource_group
            target_name = random.choice(list(key_vaults.keys()))
        
        # Select principal for Contributor access based on identity_type
        if identity_type == 'user':
            user_keys = list(users.keys())
            # Exclude used users
            if used_users:
                available_users = [user for user in user_keys if user not in used_users]
                if available_users:
                    user_keys = available_users
            principal_name = random.choice(user_keys)
        elif identity_type == 'service_principal':
            # For service_principal, use a random application (different from target app)
            sp_keys = [k for k in applications.keys() if k != app_name]
            if sp_keys:
                principal_name = random.choice(sp_keys)
            else:
                # Fallback to the same app if no other apps available
                principal_name = app_name
        else:
            # Default to user
            principal_name = random.choice(list(users.keys()))
        
        return app_name, target_name, source_name, principal_name
    
    # ========================================================================
    # Targeted Mode Entity Selection
    # ========================================================================
    
    def _select_targeted_entities_app_ownership(
        self, users: Dict, applications: Dict, entities: Dict,
        scenario: str, identity_type: str, path_name: str
    ) -> Tuple[str, str, str]:
        """Select targeted entities for Application Ownership Abuse.
        
        Args:
            users: Dictionary of users
            applications: Dictionary of applications
            entities: Entity specifications from config
            scenario: 'direct' or 'helpdesk'
            identity_type: 'user' or 'service_principal'
            path_name: Attack path name for error messages
        
        Returns:
            Tuple of (app_name, principal_name, second_user_name)
        """
        # Get application (target app that will be owned)
        app_list = list(entities.get('applications', []))
        if not app_list:
            raise ValueError(f"{path_name}: No applications specified")
        
        app_spec = app_list[0]
        app_name = app_spec.get('name', 'random')
        if app_name == 'random':
            app_name = random.choice(list(applications.keys()))
        
        if identity_type == 'user':
            # Get user as owner
            user_list = list(entities.get('users', []))
            if not user_list:
                raise ValueError(f"{path_name}: identity_type 'user' requires users")
            
            user_spec = user_list[0]
            principal_name = user_spec.get('name', 'random')
            if principal_name == 'random':
                principal_name = random.choice(list(users.keys()))
            
            # Get second user for helpdesk scenario
            if scenario == 'helpdesk':
                if len(user_list) > 1:
                    second_user_spec = user_list[1]
                    second_user_name = second_user_spec.get('name', 'random')
                    if second_user_name == 'random':
                        user_keys = list(users.keys())
                        second_user_name = user_keys[1] if len(user_keys) > 1 else user_keys[0]
                else:
                    logging.warning(f"{path_name}: Helpdesk scenario requires 2 users, only 1 defined. Reusing first user.")
                    second_user_name = principal_name
            else:
                second_user_name = principal_name
        else:  # service_principal
            # Get service principal as owner
            sp_list = list(entities.get('service_principals', []))
            if sp_list:
                sp_spec = sp_list[0]
                principal_name = sp_spec.get('name', 'random')
                if principal_name == 'random':
                    # Use a random application as service principal (different from target)
                    sp_keys = [k for k in applications.keys() if k != app_name]
                    principal_name = random.choice(sp_keys) if sp_keys else app_name
            else:
                # Default to using a different application as service principal
                sp_keys = [k for k in applications.keys() if k != app_name]
                principal_name = random.choice(sp_keys) if sp_keys else app_name
            second_user_name = principal_name  # Not used for service_principal
        
        return app_name, principal_name, second_user_name
    
    def _select_targeted_entities_app_administrator(
        self, users: Dict, applications: Dict, entities: Dict, identity_type: str, path_name: str
    ) -> Tuple[str, str]:
        """Select targeted entities for Application Administrator Abuse.
        
        Args:
            users: Dictionary of users
            applications: Dictionary of applications
            entities: Entity specifications from config
            identity_type: 'user' or 'service_principal'
            path_name: Attack path name for error messages
        
        Returns:
            Tuple of (app_name, principal_name)
        """
        # Get application (target app with privileges)
        app_list = list(entities.get('applications', []))
        if not app_list:
            raise ValueError(f"{path_name}: No applications specified")
        
        app_spec = app_list[0]
        app_name = app_spec.get('name', 'random')
        if app_name == 'random':
            app_name = random.choice(list(applications.keys()))
        
        if identity_type == 'user':
            # Get user with Application Administrator role
            user_list = list(entities.get('users', []))
            if not user_list:
                raise ValueError(f"{path_name}: identity_type 'user' requires users")
            
            user_spec = user_list[0]
            principal_name = user_spec.get('name', 'random')
            if principal_name == 'random':
                principal_name = random.choice(list(users.keys()))
        else:  # service_principal
            # Get service principal with Application Administrator role
            sp_list = list(entities.get('service_principals', []))
            if sp_list:
                sp_spec = sp_list[0]
                principal_name = sp_spec.get('name', 'random')
                if principal_name == 'random':
                    # Use a random application as service principal (different from target)
                    sp_keys = [k for k in applications.keys() if k != app_name]
                    principal_name = random.choice(sp_keys) if sp_keys else app_name
            else:
                # Default to using a different application as service principal
                sp_keys = [k for k in applications.keys() if k != app_name]
                principal_name = random.choice(sp_keys) if sp_keys else app_name
        
        return app_name, principal_name
    
    def _select_targeted_entities_kv_secret_theft(
        self, applications: Dict, keyvaults: Dict, users: Dict,
        entities: Dict, identity_type: str, path_name: str
    ) -> Tuple[str, str, str]:
        """Select targeted entities for Key Vault Secret Theft."""
        # Get application
        app_list = list(entities.get('applications', []))
        if not app_list:
            raise ValueError(f"{path_name}: No applications specified")
        app_spec = app_list[0]
        app_name = app_spec.get('name', 'random')
        if app_name == 'random':
            app_name = random.choice(list(applications.keys()))
        
        # Get key vault
        kv_list = list(entities.get('key_vaults', []))
        if not kv_list:
            raise ValueError(f"{path_name}: No key_vaults specified")
        kv_spec = kv_list[0]
        kv_name = kv_spec.get('name', 'random')
        if kv_name == 'random':
            kv_name = random.choice(list(keyvaults.keys()))
        
        # Get principal based on type
        if identity_type == 'user':
            user_list = list(entities.get('users', []))
            if not user_list:
                raise ValueError(f"{path_name}: identity_type 'user' requires users")
            user_spec = user_list[0]
            principal_name = user_spec.get('name', 'random')
            if principal_name == 'random':
                principal_name = random.choice(list(users.keys()))
        elif identity_type == 'service_principal':
            principal_name = app_name
        
        return app_name, kv_name, principal_name
    
    def _select_targeted_entities_storage_cert_theft(
        self, applications: Dict, storage_accounts: Dict, users: Dict,
        entities: Dict, identity_type: str, path_name: str
    ) -> Tuple[str, str, str]:
        """Select targeted entities for Storage Certificate Theft."""
        # Get application
        app_list = list(entities.get('applications', []))
        if not app_list:
            raise ValueError(f"{path_name}: No applications specified")
        app_spec = app_list[0]
        app_name = app_spec.get('name', 'random')
        if app_name == 'random':
            app_name = random.choice(list(applications.keys()))
        
        # Get storage account
        sa_list = list(entities.get('storage_accounts', []))
        if not sa_list:
            raise ValueError(f"{path_name}: No storage_accounts specified")
        sa_spec = sa_list[0]
        sa_name = sa_spec.get('name', 'random')
        if sa_name == 'random':
            sa_name = random.choice(list(storage_accounts.keys()))
        
        # Get principal based on type
        if identity_type == 'user':
            user_list = list(entities.get('users', []))
            if not user_list:
                raise ValueError(f"{path_name}: identity_type 'user' requires users")
            user_spec = user_list[0]
            principal_name = user_spec.get('name', 'random')
            if principal_name == 'random':
                principal_name = random.choice(list(users.keys()))
        elif identity_type == 'service_principal':
            principal_name = app_name
        
        return app_name, sa_name, principal_name
    
    def _select_targeted_entities_cosmos_secret_theft(
        self, applications: Dict, cosmos_dbs: Dict, users: Dict,
        entities: Dict, identity_type: str, path_name: str
    ) -> Tuple[str, str, str]:
        """Select targeted entities for Cosmos DB Secret Theft."""
        # Get application
        app_list = list(entities.get('applications', []))
        if not app_list:
            raise ValueError(f"{path_name}: No applications specified")
        app_spec = app_list[0]
        app_name = app_spec.get('name', 'random')
        if app_name == 'random':
            app_name = random.choice(list(applications.keys()))

        # Get Cosmos DB account
        cosmos_list = list(entities.get('cosmos_dbs', []))
        if not cosmos_list:
            raise ValueError(f"{path_name}: No cosmos_dbs specified")
        cosmos_spec = cosmos_list[0]
        cosmos_db_name = cosmos_spec.get('name', 'random')
        if cosmos_db_name == 'random':
            cosmos_db_name = random.choice(list(cosmos_dbs.keys()))

        # Get principal based on type
        if identity_type == 'user':
            user_list = list(entities.get('users', []))
            if not user_list:
                raise ValueError(f"{path_name}: identity_type 'user' requires users")
            user_spec = user_list[0]
            principal_name = user_spec.get('name', 'random')
            if principal_name == 'random':
                principal_name = random.choice(list(users.keys()))
        elif identity_type == 'service_principal':
            principal_name = app_name

        return app_name, cosmos_db_name, principal_name

    def _select_targeted_entities_mi_theft(
        self, applications: Dict, key_vaults: Dict, storage_accounts: Dict,
        virtual_machines: Dict, logic_apps: Dict, automation_accounts: Dict, function_apps: Dict, users: Dict,
        entities: Dict, source_type: str, target_resource_type: str, identity_type: str, path_name: str,
        cosmos_dbs: Dict = None
    ) -> Tuple[str, str, str, str]:
        """Select targeted entities for Managed Identity Theft.

        Args:
            applications: Dictionary of applications
            key_vaults: Dictionary of key vaults
            storage_accounts: Dictionary of storage accounts
            virtual_machines: Dictionary of virtual machines
            logic_apps: Dictionary of logic apps
            automation_accounts: Dictionary of automation accounts
            function_apps: Dictionary of function apps
            users: Dictionary of users
            entities: Entity specifications from config
            source_type: Type of source resource ('vm', 'logic_app', etc.)
            target_resource_type: Type of target resource ('key_vault', 'storage_account', 'cosmos_db')
            identity_type: Type of initial access identity ('user' or 'service_principal')
            path_name: Attack path name for error messages
            cosmos_dbs: Dictionary of Cosmos DB accounts

        Returns:
            Tuple of (app_name, target_name, source_name, principal_name)
        """
        # Get application
        app_list = list(entities.get('applications', []))
        if not app_list:
            raise ValueError(f"{path_name}: No applications specified")
        app_spec = app_list[0]
        app_name = app_spec.get('name', 'random')
        if app_name == 'random':
            app_name = random.choice(list(applications.keys()))
        
        # Get source resource
        if source_type == 'vm':
            vm_list = list(entities.get('virtual_machines', []))
            if not vm_list:
                raise ValueError(f"{path_name}: source_type 'vm' requires virtual_machines")
            vm_spec = vm_list[0]
            source_name = vm_spec.get('name', 'random')
            if source_name == 'random':
                source_name = random.choice(list(virtual_machines.keys()))
        elif source_type == 'logic_app':
            la_list = list(entities.get('logic_apps', []))
            if not la_list:
                raise ValueError(f"{path_name}: source_type 'logic_app' requires logic_apps")
            la_spec = la_list[0]
            source_name = la_spec.get('name', 'random')
            if source_name == 'random':
                source_name = random.choice(list(logic_apps.keys()))
        elif source_type == 'automation_account':
            aa_list = list(entities.get('automation_accounts', []))
            if not aa_list:
                raise ValueError(f"{path_name}: source_type 'automation_account' requires automation_accounts")
            aa_spec = aa_list[0]
            source_name = aa_spec.get('name', 'random')
            if source_name == 'random':
                source_name = random.choice(list(automation_accounts.keys()))
        elif source_type == 'function_app':
            fa_list = list(entities.get('function_apps', []))
            if not fa_list:
                raise ValueError(f"{path_name}: source_type 'function_app' requires function_apps")
            fa_spec = fa_list[0]
            source_name = fa_spec.get('name', 'random')
            if source_name == 'random':
                source_name = random.choice(list(function_apps.keys()))
        else:
            # Default to VM for unknown types
            source_name = random.choice(list(virtual_machines.keys()))
        
        # Get target resource
        if target_resource_type == 'key_vault':
            kv_list = list(entities.get('key_vaults', []))
            if not kv_list:
                raise ValueError(f"{path_name}: target_resource_type 'key_vault' requires key_vaults")
            kv_spec = kv_list[0]
            target_name = kv_spec.get('name', 'random')
            if target_name == 'random':
                target_name = random.choice(list(key_vaults.keys()))
        elif target_resource_type == 'storage_account':
            sa_list = list(entities.get('storage_accounts', []))
            if not sa_list:
                raise ValueError(f"{path_name}: target_resource_type 'storage_account' requires storage_accounts")
            sa_spec = sa_list[0]
            target_name = sa_spec.get('name', 'random')
            if target_name == 'random':
                target_name = random.choice(list(storage_accounts.keys()))
        elif target_resource_type == 'cosmos_db' and cosmos_dbs:
            cosmos_list = list(entities.get('cosmos_dbs', []))
            if not cosmos_list:
                raise ValueError(f"{path_name}: target_resource_type 'cosmos_db' requires cosmos_dbs")
            cosmos_spec = cosmos_list[0]
            target_name = cosmos_spec.get('name', 'random')
            if target_name == 'random':
                target_name = random.choice(list(cosmos_dbs.keys()))
        else:
            # For future expansion
            target_name = random.choice(list(key_vaults.keys()))
        
        # Get principal for Contributor access based on identity_type
        if identity_type == 'user':
            user_list = list(entities.get('users', []))
            if not user_list:
                raise ValueError(f"{path_name}: identity_type 'user' requires users")
            user_spec = user_list[0]
            principal_name = user_spec.get('name', 'random')
            if principal_name == 'random':
                principal_name = random.choice(list(users.keys()))
        elif identity_type == 'service_principal':
            # For service_principal, use a specified service principal or the target app
            sp_list = list(entities.get('service_principals', []))
            if sp_list:
                sp_spec = sp_list[0]
                principal_name = sp_spec.get('name', 'random')
                if principal_name == 'random':
                    # Use a random application as service principal
                    sp_keys = [k for k in applications.keys() if k != app_name]
                    principal_name = random.choice(sp_keys) if sp_keys else app_name
            else:
                # Default to using a different application as service principal
                sp_keys = [k for k in applications.keys() if k != app_name]
                principal_name = random.choice(sp_keys) if sp_keys else app_name
        else:
            # Default to user
            user_list = list(entities.get('users', []))
            if user_list:
                user_spec = user_list[0]
                principal_name = user_spec.get('name', 'random')
                if principal_name == 'random':
                    principal_name = random.choice(list(users.keys()))
            else:
                principal_name = random.choice(list(users.keys()))
        
        return app_name, target_name, source_name, principal_name
    
    # ========================================================================
    # Privilege Assignment (Shared Logic)
    # ========================================================================
    
    def _assign_app_privileges(
        self, attack_config: Dict, app_name: str, key: str,
        app_role_assignments: Dict, app_api_permission_assignments: Dict
    ) -> None:
        """Assign privileges to application based on method (shared logic for both modes)."""
        method = attack_config.get('method')
        
        if method == "AzureADRole":
            if isinstance(attack_config['entra_role'], list):
                role_ids = attack_config['entra_role']
            elif attack_config['entra_role'] == 'random':
                role_ids = [random.choice(list(HIGH_PRIVILEGED_ENTRA_ROLES.values()))]
            else:
                role_ids = [attack_config['entra_role']]
            
            app_role_assignments[key] = {
                'app_name': app_name,
                'role_ids': role_ids
            }
        
        elif method == "GraphAPIPermission":
            # Backward compatibility: GraphAPIPermission always uses Microsoft Graph
            if isinstance(attack_config['app_role'], list):
                api_permission_ids = attack_config['app_role']
            elif attack_config['app_role'] != 'random':
                api_permission_ids = [attack_config['app_role']]
            else:
                api_permission_ids = [random.choice(
                    [perm["id"] for perm in HIGH_PRIVILEGED_GRAPH_API_PERMISSIONS.values()]
                )]
            
            app_api_permission_assignments[key] = {
                'app_name': app_name,
                'api_permission_ids': api_permission_ids,
                'api_type': 'graph'  # Always graph for backward compatibility
            }
        
        elif method == "APIPermission":
            # New method supporting multiple API types (graph, exchange, etc.)
            api_type = attack_config.get('api_type', 'graph')
            
            # Validate api_type
            if api_type not in API_REGISTRY:
                logging.warning(f"Invalid api_type '{api_type}', defaulting to 'graph'")
                api_type = 'graph'
            
            if isinstance(attack_config['app_role'], list):
                api_permission_ids = attack_config['app_role']
            elif attack_config['app_role'] != 'random':
                api_permission_ids = [attack_config['app_role']]
            else:
                # Get random permission from the specified API type
                api_permission_ids = [random.choice(
                    [perm["id"] for perm in ALL_HIGH_PRIVILEGED_PERMISSIONS[api_type].values()]
                )]
            
            app_api_permission_assignments[key] = {
                'app_name': app_name,
                'api_permission_ids': api_permission_ids,
                'api_type': api_type
            }