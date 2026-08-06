"""
Attack path management for BadZure.
Handles creation of all attack path types for both random and targeted modes.
"""
import random
import string
import logging
from typing import Dict, List, Tuple, Optional
from src.constants import (
    HIGH_PRIVILEGED_ENTRA_ROLES,
    ALL_HIGH_PRIVILEGED_PERMISSIONS,
    APP_ADMIN_ROLE_ID,
    CLOUD_APP_ADMIN_ROLE_ID,
    RECON_DIRECTORY_READ_ALL_ID,
    RESOURCE_SEED_VECTORS,
    WEBAPP_FOOTHOLD_VECTORS,
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
    InitialAccessVector,
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

    def build_recon_primitives(self, user_creds: Dict) -> List:
        """Recon access for every initial-access identity, as generic primitives:
          - service principals get Directory.Read.All (Graph) for Entra enumeration,
          - every identity gets subscription-scoped Reader for Azure resource enum.
            (Users already have directory read by default in Entra.)

        Returns origin=attack_path primitives (ApiPermission + AzureRbacAssignment)
        to fold into the generic families alongside the macro output. principal_ref
        uses the SAME symbolic keys the macros use (SP = app display_name, user =
        bare UPN local part = the var.users key)."""
        primitives: List = []
        seen_api, seen_reader = set(), set()
        for credentials in user_creds.values():
            identity_type = credentials.get('initial_access')
            if identity_type == 'service_principal':
                name = credentials.get('service_principal_name')
                if not name:
                    continue
                principal_type = 'service_principal'
                if name not in seen_api:
                    seen_api.add(name)
                    primitives.append(ApiPermission(
                        f"recon_{name}", ATTACK_PATH, principal_ref=name,
                        permission_id=RECON_DIRECTORY_READ_ALL_ID, api_type='graph'))
            elif identity_type == 'user':
                upn = credentials.get('user_principal_name', '')
                name = upn.split('@')[0] if '@' in upn else upn
                principal_type = 'user'
                if not name:
                    continue
            else:
                continue
            if name not in seen_reader:
                seen_reader.add(name)
                primitives.append(AzureRbacAssignment(
                    f"recon_reader_{name}", ATTACK_PATH, principal_ref=name,
                    principal_type=principal_type, role='Reader',
                    scope_type='subscription'))
        return primitives

    # ========================================================================
    # Phase 4 macros — identity-based + managed-identity techniques.
    # Each emits generic primitives (like the KV/Storage/Cosmos macros) and
    # reuses the legacy entity selectors + _assign_app_privileges verbatim.
    # ========================================================================
    HELPDESK_ADMIN_ROLE_ID = "729827e3-9c14-49f7-bb1b-9608f156bbb8"

    # ManagedIdentityAbuse role sets (parity with the legacy main.tf blocks).
    SOURCE_CONTRIBUTOR_ROLE = {
        'vm': 'Virtual Machine Contributor', 'logic_app': 'Logic App Contributor',
        'automation_account': 'Automation Contributor', 'function_app': 'Website Contributor',
        'app_service': 'Website Contributor',
    }
    SOURCE_SCOPE_RESOURCE_TYPE = {
        'vm': 'virtual_machine', 'logic_app': 'logic_app',
        'automation_account': 'automation_account', 'function_app': 'function_app',
        'app_service': 'app_service',
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
        """Emit the looted app's entitlements (the `objective:` section) as primitives
        on the app's service principal.
        Returns (primitives, entra_role_ids, api_perm_ids, api_type)."""
        objective = attack_config.get('objective') or {}
        return self._objective_primitives(
            objective, key, principal_ref=app_name, principal_type='service_principal')

    def _objective_primitives(self, objective: Dict, key: str, principal_ref: str,
                              principal_type: str, mi_source_type: Optional[str] = None):
        """Emit the typed `objective:` entitlement keys as generic primitives on the
        given terminal principal. Several keys may be present at once (the principal
        holds the union):
          - entra_role:     GUID | [GUIDs] | 'random'                  -> EntraRoleAssignment(s)
          - api_permission: {graph|exchange: GUID|[GUIDs]|'random'}    -> ApiPermission(s)
          - azure_role:     [{role, scope, scope_ref?, scope_resource_type?}] -> AzureRbacAssignment(s)
        Returns (primitives, entra_role_ids, api_perm_ids, api_type); the id/type
        fields feed the macro summary and the output formatter."""
        prims: List = []
        entra_role_ids: List = []
        api_perm_ids: List = []
        api_type = None

        er = objective.get('entra_role')
        if er is not None:
            entra_role_ids = self._resolve_entra_role_ids(er)
            for idx, role_id in enumerate(entra_role_ids):
                prims.append(EntraRoleAssignment(
                    f"{key}_app_role_{idx}", ATTACK_PATH,
                    principal_ref=principal_ref, principal_type=principal_type, role=role_id,
                ))

        ap = objective.get('api_permission')
        if ap is not None:
            for a_type in ('graph', 'exchange'):
                if a_type not in ap:
                    continue
                ids = self._resolve_api_perm_ids(ap[a_type], a_type)
                api_perm_ids.extend(ids)
                api_type = api_type or a_type
                for idx, perm_id in enumerate(ids):
                    prims.append(ApiPermission(
                        f"{key}_app_perm_{a_type}_{idx}", ATTACK_PATH,
                        principal_ref=principal_ref, permission_id=perm_id, api_type=a_type,
                    ))

        az = objective.get('azure_role')
        if az is not None:
            for idx, entry in enumerate(az):
                role = entry['role'] if isinstance(entry, dict) else entry
                scope = entry.get('scope', 'subscription') if isinstance(entry, dict) else 'subscription'
                scope_ref = entry.get('scope_ref') if isinstance(entry, dict) else None
                scope_rtype = entry.get('scope_resource_type') if isinstance(entry, dict) else None
                prims.append(AzureRbacAssignment(
                    f"{key}_app_rbac_{idx}", ATTACK_PATH,
                    principal_ref=principal_ref, principal_type=principal_type, role=role,
                    scope_type=scope, scope_ref=scope_ref, scope_resource_type=scope_rtype,
                    mi_source_type=mi_source_type if principal_type == 'managed_identity' else None,
                ))

        return prims, entra_role_ids, api_perm_ids, api_type

    @staticmethod
    def _resolve_entra_role_ids(val):
        """An `entra_role` value -> a list of role GUIDs (list as-is; 'random' -> one
        high-privileged role; a single GUID -> a one-element list)."""
        if isinstance(val, list):
            return list(val)
        if val == 'random':
            return [random.choice(list(HIGH_PRIVILEGED_ENTRA_ROLES.values()))]
        return [val]

    @staticmethod
    def _resolve_api_perm_ids(val, api_type):
        """An `api_permission.<api>` value -> a list of permission GUIDs (list as-is;
        'random' -> one high-privileged permission of that API; a single GUID -> a list)."""
        if isinstance(val, list):
            return list(val)
        if val == 'random':
            catalog = ALL_HIGH_PRIVILEGED_PERMISSIONS.get(api_type, {})
            return [random.choice([perm["id"] for perm in catalog.values()])]
        return [val]

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

    @staticmethod
    def _foothold_credentials(vector, source_name, source_type):
        """Operator artifact for an exposed-host foothold: the VM the attacker lands
        on. The public IP + admin credentials are filled in after apply from the
        vm_foothold_access Terraform output (keyed by foothold_resource), since the
        IP is only allocated at apply time. `foothold_resource` is also the
        reachability seed (see scenario_loader._seed_from_credentials)."""
        return {
            "initial_access": vector,          # e.g. exposed_rdp / exposed_ssh
            "foothold_resource": source_name,  # the VM ref (seed + output key)
            "foothold_type": source_type,
            "entry_point": vector,
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

    # ---- ManagedIdentityAbuse ----------------------------------------------
    def macro_managed_identity_abuse(
        self, attack_config: Dict, applications: Dict, key_vaults: Dict,
        storage_accounts: Dict, users: Dict, domain: str, virtual_machines: Dict,
        logic_apps: Dict, automation_accounts: Dict, function_apps: Dict,
        mode: str = 'random', entities: Optional[Dict] = None, path_name: Optional[str] = None,
        used_apps: Optional[set] = None, used_users: Optional[set] = None,
        cosmos_dbs: Optional[Dict] = None, used_sources: Optional[set] = None,
        app_services: Optional[Dict] = None
    ) -> Dict:
        """ManagedIdentityAbuse as generic building blocks (Phase 4 macro).

        The attacker holds Contributor on a SOURCE compute resource (VM/Logic App/
        Automation/Function/App Service) -> runs code -> steals the source's managed identity
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
        app_services = app_services or {}
        source_type = attack_config.get('source_type', 'vm')
        target_resource_type = attack_config.get('target_resource_type')
        entry_point = attack_config.get('entry_point', 'compromised_identity')
        ia_vector = attack_config.get('initial_access', 'user')
        # Exposed-host foothold (exposed_rdp/exposed_ssh) OR vulnerable-web-app
        # foothold (vulnerable_web_app): the attacker is dropped onto the source
        # resource directly (code execution), so there is no compromised identity
        # and no source-Contributor grant. identity_type only steers the (then unused)
        # principal pick during selection, so 'user' is a harmless placeholder there.
        is_foothold = ia_vector in RESOURCE_SEED_VECTORS
        identity_type = 'user' if is_foothold else ia_vector
        credential_type = attack_config.get('credential_type', 'secret')
        assignment_type = attack_config.get('assignment_type', 'direct')
        # Flavor: 'stored_credential' (courier — the MI loots an app credential from a
        # target data resource) or 'managed_identity' (direct — the MI itself holds the
        # objective, typically Azure RBAC; no target, no looted app).
        privilege_source = attack_config.get('privilege_source', 'stored_credential')
        direct = privilege_source == 'managed_identity'

        key = self._attack_path_key(mode, path_name)
        if direct:
            # Direct over-privileged identity: the MI itself holds the objective. No
            # looted app, no target data resource — select only the source compute (and
            # the compromised principal, for the credential vectors).
            app_name, target_name = None, None
            source_name, principal_name = self._select_mi_direct_entities(
                source_type, virtual_machines, logic_apps, automation_accounts,
                function_apps, app_services, users, applications, identity_type,
                is_foothold, mode, entities, used_users, used_sources, path_name)
        elif mode == 'random':
            app_name, target_name, source_name, principal_name = self._select_random_entities_mi_theft(
                applications, key_vaults, storage_accounts, virtual_machines, logic_apps,
                automation_accounts, function_apps, users, source_type, target_resource_type,
                identity_type, used_apps, used_users, cosmos_dbs=cosmos_dbs,
                used_sources=used_sources, app_services=app_services)
        else:
            app_name, target_name, source_name, principal_name = self._select_targeted_entities_mi_theft(
                applications, key_vaults, storage_accounts, virtual_machines, logic_apps,
                automation_accounts, function_apps, users, entities, source_type,
                target_resource_type, identity_type, path_name, cosmos_dbs=cosmos_dbs,
                app_services=app_services)

        primitives, groups = [], {}

        # 1. Initial access onto the source resource.
        src_role = self.SOURCE_CONTRIBUTOR_ROLE.get(source_type, 'Contributor')
        src_scope_rtype = self.SOURCE_SCOPE_RESOURCE_TYPE.get(source_type, 'virtual_machine')
        if is_foothold:
            # Foothold: drop straight onto the source resource (code execution).
            # The reachability seed becomes that resource, and controlling it already
            # implies controlling its managed identity — so steps 2+ continue
            # unchanged. A web-app foothold lands on the App Service (target_type
            # app_service + the vuln variant); the exposed-host footholds on a VM.
            group_name = None
            principal_name = None
            if ia_vector in WEBAPP_FOOTHOLD_VECTORS:
                primitives.append(InitialAccessVector(
                    f"{key}_foothold", ATTACK_PATH, method=ia_vector,
                    target_ref=source_name, target_type='app_service',
                    grants='code_execution',
                    variant=attack_config.get('variant'),
                    expose_to_internet=bool(attack_config.get('expose_to_internet', False))))
            else:
                primitives.append(InitialAccessVector(
                    f"{key}_foothold", ATTACK_PATH, method=ia_vector,
                    target_ref=source_name, target_type='virtual_machine',
                    grants='code_execution',
                    expose_to_internet=bool(attack_config.get('expose_to_internet', False)),
                    credential=attack_config.get('credential', 'known')))
        elif assignment_type in ('group_member', 'group_owner'):
            # Source-specific Contributor to the initial-access principal's group.
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
            # Source-specific Contributor to the compromised principal directly.
            group_name = None
            primitives.append(AzureRbacAssignment(
                f"{key}_src_contrib", ATTACK_PATH, principal_ref=principal_name,
                principal_type=identity_type, role=src_role, scope_type='resource',
                scope_resource_type=src_scope_rtype, scope_ref=source_name))

        # 2.-5. Courier flavor: the MI loots an app credential from a target data
        # resource. Direct flavor: the MI itself holds the objective (azure_role).
        if direct:
            priv_prims, entra_role_ids, api_perm_ids, api_type = self._objective_primitives(
                attack_config.get('objective') or {}, key, source_name,
                'managed_identity', mi_source_type=source_type)
            primitives.extend(priv_prims)
        else:
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

            # 5. The looted app's privileges (the objective: entitlements).
            priv_prims, entra_role_ids, api_perm_ids, api_type = self._app_privilege_primitives(
                attack_config, app_name, key)
            primitives.extend(priv_prims)

        # 6/7. initial-access credentials.
        if is_foothold:
            credentials = self._foothold_credentials(ia_vector, source_name, source_type)
            foothold_kind = ("vulnerable-web-app foothold"
                             if ia_vector in WEBAPP_FOOTHOLD_VECTORS
                             else "exposed-host foothold")
            source_line = (f"Source Resource: {source_type} - {source_name} "
                           f"({foothold_kind} via {ia_vector})")
        else:
            credentials = self._initial_access_credentials(
                identity_type, principal_name, users, domain, entry_point, key, primitives)
            source_line = f"Source Resource: {source_type} - {source_name} (with {src_role})"

        access_lines = [source_line]
        if direct:
            access_lines.append("Managed Identity is itself over-privileged (objective on the MI)")
        else:
            access_lines.append(
                f"Managed Identity → Target: {target_resource_type} - {target_name}")
        summary = {
            "path_name": path_name, "key": key, "technique": "ManagedIdentityAbuse",
            "identity_type": identity_type, "principal_name": principal_name,
            "assignment_type": assignment_type, "group_name": group_name, "app_name": app_name,
            "source_type": source_type, "source_name": source_name,
            "privilege_source": privilege_source,
            "target_resource_type": target_resource_type, "target_name": target_name,
            "initial_access_vector": ia_vector if is_foothold else None,
            "access_lines": access_lines,
            "show_target_app": not direct,
            "entra_role_ids": entra_role_ids, "api_perm_ids": api_perm_ids, "api_type": api_type,
        }
        return {"primitives": primitives, "credentials": credentials, "groups": groups, "summary": summary}

    def _select_mi_direct_entities(self, source_type, virtual_machines, logic_apps,
                                   automation_accounts, function_apps, app_services, users,
                                   applications, identity_type, is_foothold, mode, entities,
                                   used_users, used_sources, path_name):
        """Pick the source compute (and, for the credential vectors, the compromised
        principal) for a DIRECT ManagedIdentityAbuse path — no app/target involved."""
        source_pool = {
            'vm': virtual_machines, 'logic_app': logic_apps,
            'automation_account': automation_accounts, 'function_app': function_apps,
            'app_service': app_services or {},
        }.get(source_type, virtual_machines)
        if mode == 'targeted' and entities:
            inline = entities.get({
                'vm': 'virtual_machines', 'logic_app': 'logic_apps',
                'automation_account': 'automation_accounts', 'function_app': 'function_apps',
                'app_service': 'app_services',
            }.get(source_type, 'virtual_machines')) or []
            source_keys = [s['name'] for s in inline] or list(source_pool.keys())
        else:
            source_keys = list(source_pool.keys())
        if not source_keys:
            raise ValueError(
                f"{path_name}: ManagedIdentityAbuse source_type '{source_type}' requires "
                f"a {source_type} in the baseline.")
        if mode == 'targeted':
            source_name = source_keys[0]
        else:
            avail = [s for s in source_keys if not used_sources or s not in used_sources]
            source_name = random.choice(avail or source_keys)

        principal_name = None
        if not is_foothold:
            if identity_type == 'user':
                ukeys = list(users.keys())
                if mode == 'random' and used_users:
                    ukeys = [u for u in ukeys if u not in used_users] or ukeys
                principal_name = random.choice(ukeys)
            else:  # service_principal
                principal_name = random.choice(list(applications.keys()))
        return source_name, principal_name

    def _mi_data_injects(self, key, target_type, target_name, app_name, credential_type,
                         app_cred_key, cert_paths):
        """The data_injects that plant the looted app's credential into the MI's
        target (parity names with legacy main.tf). Cosmos plants the credential as
        documents in the container via the Python post-apply data-plane phase
        (location_type=cosmos_document is data-plane-only — not a Terraform resource)."""
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
        elif target_type == 'cosmos_db':
            # Planted as documents in the container by the Python data-plane phase.
            if credential_type == 'certificate':
                injects.append(DataInject(
                    f"{key}_cosmos_cert", ATTACK_PATH, material="app_certificate",
                    location_type="cosmos_document", location_ref=target_name,
                    name=f"mi-certificate-{app_name}", source_ref=app_name,
                    file_path=cert_paths["cert"]))
            else:
                injects.append(DataInject(
                    f"{key}_cosmos_secret", ATTACK_PATH, material="app_secret",
                    location_type="cosmos_document", location_ref=target_name,
                    name=f"mi-client-secret-{app_name}", credential_ref=app_cred_key))
            injects.append(DataInject(
                f"{key}_cosmos_id", ATTACK_PATH, material="app_client_id",
                location_type="cosmos_document", location_ref=target_name,
                name=f"mi-client-id-{app_name}", source_ref=app_name))
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
                "Use 'ManagedIdentityAbuse' with target_resource_type 'key_vault' instead."
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

        # 4. The looted app's privileges (the objective: entitlements).
        priv_prims, entra_role_ids, api_perm_ids, api_type = self._app_privilege_primitives(
            attack_config, app_name, key)
        primitives.extend(priv_prims)

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
                "Use 'ManagedIdentityAbuse' with target_resource_type 'storage_account' instead."
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

        # 4. The looted app's privileges (the objective: entitlements).
        priv_prims, entra_role_ids, api_perm_ids, api_type = self._app_privilege_primitives(
            attack_config, app_name, key)
        primitives.extend(priv_prims)

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

        Emits generic primitives. The looted app's client secret is planted as a
        document in the Cosmos container (location_type=cosmos_document), so the
        attacker who reaches the data plane can query it — parity with KV/Storage.
        The document is written by the Python post-apply data-plane phase
        (location_type=cosmos_document is data-plane-only, not a Terraform resource).

        The chain, as building blocks:
          1. AppCredential(password) — mint the looted (high-priv) app's client secret.
          2. DataInject      — plant that secret as a Cosmos document named
                               'client-secret-<app>' (material=app_secret).
          3. AzureRbacAssignment(data_plane=cosmos_sql) — grant the compromised
                               principal (or its group) 'Cosmos DB Built-in Data
                               Contributor' on the Cosmos account.
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
                "CosmosDBSecretTheft does not support initial_access 'managed_identity'. "
                "Use 'ManagedIdentityAbuse' with target_resource_type 'cosmos_db' instead."
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

        # 1. Mint the looted app's client secret + 2. plant it as a Cosmos document.
        cred_key = f"{key}_app_secret"
        primitives.append(AppCredential(
            cred_key, ATTACK_PATH, app_ref=app_name, type="password",
            display_name="BadZureClientSecret",
        ))
        primitives.append(DataInject(
            f"{key}_cosmos_doc", ATTACK_PATH,
            material="app_secret", location_type="cosmos_document",
            location_ref=cosmos_db_name, name=f"client-secret-{app_name}",
            credential_ref=cred_key,
        ))

        # 3. Cosmos DB Built-in Data Contributor (data-plane) — to the principal
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

        # 4. The looted app's privileges (the objective: entitlements).
        priv_prims, entra_role_ids, api_perm_ids, api_type = self._app_privilege_primitives(
            attack_config, app_name, key)
        primitives.extend(priv_prims)

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
            # The initial-access SP must differ from the looted app, or there is no
            # escalation (you'd already BE the privileged app). Fall back to it only
            # if it's the sole application available.
            sp_keys = [k for k in service_principals.keys() if k != app_name]
            principal_name = random.choice(sp_keys) if sp_keys else app_name
        
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
            # The initial-access SP must differ from the looted app, or there is no
            # escalation (you'd already BE the privileged app). Fall back to it only
            # if it's the sole application available.
            sp_keys = [k for k in service_principals.keys() if k != app_name]
            principal_name = random.choice(sp_keys) if sp_keys else app_name
        
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
            # The initial-access SP must differ from the looted app, or there is no
            # escalation (you'd already BE the privileged app). Fall back to it only
            # if it's the sole application available.
            sp_keys = [k for k in service_principals.keys() if k != app_name]
            principal_name = random.choice(sp_keys) if sp_keys else app_name

        return app_name, cosmos_db_name, principal_name

    def _select_random_entities_mi_theft(
        self, applications: Dict, key_vaults: Dict, storage_accounts: Dict,
        virtual_machines: Dict, logic_apps: Dict, automation_accounts: Dict, function_apps: Dict, users: Dict,
        source_type: str, target_resource_type: str, identity_type: str,
        used_apps: set = None, used_users: set = None,
        cosmos_dbs: Dict = None, used_sources: set = None, app_services: Dict = None
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

        # Select source based on type. Exclude sources already taken by another MI
        # path: two paths sharing a source grant its managed identity the same roles
        # on the same target -> identical Azure role assignments -> 409 on apply. Fall
        # back to the full pool when exhausted (the loader then fails with a clear
        # "not enough distinct sources" message instead of colliding).
        source_pool = {
            'vm': virtual_machines, 'logic_app': logic_apps,
            'automation_account': automation_accounts, 'function_app': function_apps,
            'app_service': app_services or {},
        }.get(source_type, virtual_machines)
        source_keys = list(source_pool.keys())
        if used_sources:
            available_sources = [s for s in source_keys if s not in used_sources]
            if available_sources:
                source_keys = available_sources
        source_name = random.choice(source_keys)
        
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
        cosmos_dbs: Dict = None, app_services: Dict = None
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
        elif source_type == 'app_service':
            as_list = list(entities.get('app_services', []))
            if not as_list:
                raise ValueError(f"{path_name}: source_type 'app_service' requires app_services")
            as_spec = as_list[0]
            source_name = as_spec.get('name', 'random')
            if source_name == 'random':
                source_name = random.choice(list((app_services or {}).keys()))
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
