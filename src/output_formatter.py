"""
Output formatting for BadZure.
Handles formatting and writing of attack path details and user files.
"""
import logging
from typing import Dict, Optional
from src.constants import API_REGISTRY
from src.name_resolver import NameResolver


class OutputFormatter:
    """Formats and writes output for BadZure."""

    def __init__(self, name_resolver: Optional[NameResolver] = None):
        # Resolves privilege GUIDs -> human names for the attack-path payoff line.
        self.resolver = name_resolver or NameResolver()

    # Per-technique "<principal> gains <access> on <resource>" line for the generic
    # macro printout. Each entry: (summary key holding the resource, access label).
    _GENERIC_ACCESS = {
        "KeyVaultSecretTheft": ("key_vault", "Key Vault Access", "Key Vault Contributor"),
        "StorageCertificateTheft": ("storage_account", "Storage Account Access",
                                    "Storage Blob Data Reader"),
        "CosmosDBSecretTheft": ("cosmos_db", "Cosmos DB Access", "Cosmos DB Data Contributor"),
    }

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
            self._declarative_group_access(overlay)
            self._declarative_payoff(overlay)
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
    def _declarative_group_access(overlay) -> None:
        """When the path grants its access through a security group (group_member /
        group_owner), name the group and the identity's relationship to it, so the
        operator sees the group hop without having to read the step graph."""
        summary = getattr(overlay, "summary", None) or {}
        group_name = summary.get("group_name")
        if not group_name:
            return
        rel = {"group_member": "a MEMBER", "group_owner": "an OWNER"}.get(
            summary.get("assignment_type"), "linked to")
        principal = summary.get("principal_name", "the compromised identity")
        logging.info(
            f"Group-Based Access: {principal} is {rel} of group '{group_name}' "
            f"(the group holds the privileged role granting the attack)")

    def _declarative_payoff(self, overlay) -> None:
        """Name the attack's payoff: the looted/controlled high-priv application and
        the privilege it carries (the Entra role or API permission that makes the
        chain an escalation), with GUIDs resolved to human names. Driven by the macro
        `summary`; explicit-graph paths carry no `app_name` and print nothing."""
        summary = getattr(overlay, "summary", None) or {}
        app_name = summary.get("app_name")
        if not app_name:
            return

        logging.info(f"Looted Application: {app_name}")

        entra_ids = summary.get("entra_role_ids") or []
        api_ids = summary.get("api_perm_ids") or []
        if entra_ids:
            names = ", ".join(self.resolver.entra_role_name(g) for g in entra_ids)
            logging.info(f"Application Privileges: Entra Role(s) - {names}")
        elif api_ids:
            api_type = summary.get("api_type", "graph")
            api_display = API_REGISTRY.get(api_type, {}).get("display_name", api_type)
            names = ", ".join(self.resolver.api_permission_name(g, api_type)
                              for g in api_ids)
            logging.info(f"Application Privileges: {api_display} - {names}")

        # For resource-theft techniques, name the resource + the access role the
        # attacker (or its group) holds on it (reusing the legacy access table).
        access = self._GENERIC_ACCESS.get(summary.get("technique"))
        if access:
            resource_key, _label, role_label = access
            resource = summary.get(resource_key)
            if resource:
                logging.info(f"Resource Access: {resource} via {role_label}")

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
