"""
Output formatting for BadZure.
Handles formatting and writing of attack path details and user files.
"""
import logging
from typing import Dict
from src.constants import API_REGISTRY


class OutputFormatter:
    """Formats and writes output for BadZure."""
    
    # Per-technique "<principal> gains <access> on <resource>" line for the generic
    # macro printout. Each entry: (summary key holding the resource, access label).
    _GENERIC_ACCESS = {
        "KeyVaultSecretTheft": ("key_vault", "Key Vault Access", "Key Vault Contributor"),
        "StorageCertificateTheft": ("storage_account", "Storage Account Access",
                                    "Storage Blob Data Reader"),
        "CosmosDBSecretTheft": ("cosmos_db", "Cosmos DB Access", "Cosmos DB Data Contributor"),
    }

    def format_generic_paths(self, summaries, user_creds: Dict, domain: str) -> None:
        """Minimal printout for macro-based techniques built via the generic layer
        (Phase 2/4). The legacy per-technique dicts are empty for these paths, so we
        report the essentials from each macro summary. The rich, graph-derived
        narrative is the declarative path's job (`format_declarative_paths`).

        Each macro summary may carry its own `access_lines` (technique-specific
        narrative) + `show_target_app`; resource-theft techniques fall back to the
        `_GENERIC_ACCESS` table.
        """
        if not summaries:
            return
        for summary in summaries:
            technique = summary.get('technique', 'KeyVaultSecretTheft')
            path_name = summary.get('path_name')
            logging.info(f"Attack Path: {path_name} ({technique})")
            logging.info(f"Attack Path ID: {summary.get('key')}")

            identity_type = summary.get('identity_type')
            principal_name = summary.get('principal_name')
            creds = user_creds.get(path_name, {})
            if identity_type == 'user':
                logging.info(f"Initial Access Identity: User - {principal_name}@{domain}")
                if 'password' in creds:
                    logging.info(f"Password: {creds['password']}")
            else:
                logging.info(f"Initial Access Identity: Service Principal - {principal_name}")
                if 'client_id' in creds:
                    logging.info(f"Client ID: {creds['client_id']}")
                if 'client_secret' in creds:
                    logging.info(f"Client Secret: {creds['client_secret']}")

            assignment_type = summary.get('assignment_type', 'direct')
            if assignment_type in ('group_member', 'group_owner'):
                label = 'Group Member (indirect)' if assignment_type == 'group_member' else 'Group Owner (indirect)'
                logging.info(f"Assignment Type: {label}")
                logging.info(f"Group: {summary.get('group_name')}")

            # Technique-specific access narrative: macro-provided, else the table.
            access_lines = summary.get('access_lines')
            if access_lines is None:
                resource_key, access_label, role_label = self._GENERIC_ACCESS.get(
                    technique, ("key_vault", "Resource Access", "access"))
                via = " via Group" if assignment_type in ('group_member', 'group_owner') else ""
                access_lines = [f"{access_label}: {summary.get(resource_key)} ({role_label}{via})"]
            for line in access_lines:
                logging.info(line)

            if summary.get('show_target_app', True):
                logging.info(f"Target Application: {summary.get('app_name')}")
            if summary.get('entra_role_ids'):
                logging.info(f"Application Privileges: Entra Role(s) - {', '.join(summary['entra_role_ids'])}")
            elif summary.get('api_perm_ids'):
                api_type = summary.get('api_type', 'graph')
                api_display = API_REGISTRY.get(api_type, {}).get('display_name', api_type)
                logging.info(f"Application Privileges: {api_display} - {', '.join(summary['api_perm_ids'])}")
            logging.info("")

    def format_declarative_paths(self, overlays, user_creds: Dict, domain: str) -> None:
        """Rich printout for Phase-3 declarative attack paths (Slice 5): the
        objective + capability, the reachability verdict, scenario metadata, the
        initial-access credentials, and the ordered attack steps (authored or
        graph-derived) with their MITRE / detection annotations."""
        if not overlays:
            return
        logging.info("=" * 70)
        logging.info("ATTACK PATH DETAILS")
        logging.info("=" * 70)
        for overlay in overlays:
            logging.info(f"*** {overlay.name} ***")
            self._declarative_objective(overlay)
            self._declarative_reachability(overlay)
            self._declarative_metadata(overlay.metadata or {})
            self._declarative_initial_access(user_creds.get(overlay.name, {}))
            self._declarative_steps(overlay.steps or [])
            logging.info("")

    @staticmethod
    def _declarative_objective(overlay) -> None:
        objective = overlay.objective or {}
        if objective.get('name'):
            impact = objective.get('impact')
            impact_str = f" (impact: {impact})" if impact else ""
            logging.info(f"Objective: {objective['name']}{impact_str}")
        cap = objective.get('capability')
        if cap:
            target = objective.get('role') or objective.get('target_ref')
            logging.info(f"Goal: {cap}" + (f" -> {target}" if target else ""))
        if objective.get('description'):
            logging.info(f"Description: {objective['description']}")

    @staticmethod
    def _declarative_reachability(overlay) -> None:
        reach = overlay.reachability or {}
        status = reach.get('status')
        if not status:
            return
        marker = {'reached': '[reachable]', 'unverified': '[unverified]',
                  'blocked': '[UNREACHABLE]', 'invalid': '[INVALID]'}.get(status, status)
        logging.info(f"Reachability: {marker} {reach.get('reason', '')}".rstrip())

    @staticmethod
    def _declarative_metadata(metadata: Dict) -> None:
        if metadata.get('complexity'):
            logging.info(f"Complexity: {metadata['complexity']}")
        if metadata.get('tags'):
            logging.info(f"Tags: {', '.join(metadata['tags'])}")
        if metadata.get('mitre'):
            logging.info(f"MITRE: {', '.join(metadata['mitre'])}")

    @staticmethod
    def _declarative_initial_access(creds: Dict) -> None:
        identity_type = creds.get('initial_access')
        if identity_type == 'user':
            logging.info(f"Initial Access Identity: User - {creds.get('user_principal_name', 'N/A')}")
            if 'password' in creds:
                logging.info(f"Password: {creds['password']}")
        elif identity_type == 'service_principal':
            logging.info(f"Initial Access Identity: Service Principal - {creds.get('service_principal_name', 'N/A')}")
            if 'client_id' in creds:
                logging.info(f"Client ID: {creds['client_id']}")
            if 'client_secret' in creds:
                logging.info(f"Client Secret: {creds['client_secret']}")

    @staticmethod
    def _declarative_steps(steps) -> None:
        if not steps:
            return
        derived = any(s.get('derived') for s in steps)
        label = "Attack Steps (derived from graph)" if derived else "Attack Steps"
        logging.info(f"{label}:")
        for i, step in enumerate(steps, 1):
            target = step.get('target_ref')
            arrow = f" -> {target}" if target else ""
            action = step.get('action')
            action_str = f" [{action}]" if action else ""
            logging.info(f"  {i}. {step.get('name', 'step')}{arrow}{action_str}")
            mitre = step.get('mitre')
            if mitre:
                logging.info(f"     MITRE: {mitre if isinstance(mitre, str) else ', '.join(mitre)}")
            if step.get('uses'):
                logging.info(f"     Uses: {', '.join(step['uses'])}")
            if step.get('reads'):
                logging.info(f"     Reads: {', '.join(step['reads'])}")
            if step.get('gains'):
                logging.info(f"     Gains: {', '.join(step['gains'])}")
            if step.get('detection'):
                det = step['detection']
                logging.info(f"     Detection: {det if isinstance(det, str) else ', '.join(det)}")

    def write_users_file(self, users: Dict, domain: str, file_path: str = 'users.txt') -> None:
        """
        Write users to a file.
        
        Args:
            users: Dictionary of users
            domain: Domain name
            file_path: Path to output file
        """
        with open(file_path, 'w') as file:
            for user in users.values():
                file.write(f"{user['user_principal_name']}@{domain}\n")
        logging.info(f"Created {file_path} file")
