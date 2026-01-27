"""
Assignment management for BadZure.
Handles creation of random assignments between entities.
"""
import random
import logging
from typing import Dict
from src.constants import ENTRA_ROLES, GRAPH_API_PERMISSIONS


class AssignmentManager:
    """Manages creation of random assignments between entities."""
    
    def create_random_assignments(
        self,
        users: Dict,
        groups: Dict,
        administrative_units: Dict,
        applications: Dict,
        show_warnings: bool = True,
        attack_path_groups: set = None
    ) -> tuple:
        """
        Create random assignments between entities.
        
        Args:
            users: Dictionary of users
            groups: Dictionary of groups
            administrative_units: Dictionary of administrative units
            applications: Dictionary of applications
            show_warnings: If False, suppress warnings about missing entities
            attack_path_groups: Set of group names reserved for attack paths.
                               These groups will NOT receive random user assignments.
        
        Returns:
            Tuple of (user_group_assignments, user_au_assignments,
                     user_role_assignments, app_role_assignments,
                     app_api_permission_assignments)
        """
        user_group_assignments = {}
        user_au_assignments = {}
        user_role_assignments = {}
        app_role_assignments = {}
        app_api_permission_assignments = {}
        
        # Initialize attack_path_groups if not provided
        attack_path_groups = attack_path_groups or set()
        
        user_keys = list(users.keys())
        # Filter out attack path groups from random assignment
        available_groups = {k: v for k, v in groups.items() if k not in attack_path_groups}
        group_keys = list(available_groups.keys())
        au_keys = list(administrative_units.keys())
        app_keys = list(applications.keys())
        
        # Calculate subset size as one-third of the total users
        # Set to 0 if no users exist to prevent sampling from empty list
        user_subset_size = max(1, len(user_keys) // 3) if user_keys else 0
        
        # User to group assignments (only to non-attack-path groups)
        if group_keys and user_keys:
            group_assigned_users = random.sample(user_keys, user_subset_size)
            for user in group_assigned_users:
                group = random.choice(group_keys)
                assignment_key = f"{user}-{group}"
                user_group_assignments[assignment_key] = {
                    'user_name': user,
                    'group_name': group
                }
        elif groups and not group_keys and user_keys and show_warnings:
            # All groups are attack path groups - no random assignment possible
            logging.info(
                f"All {len(groups)} group(s) are reserved for attack paths. "
                f"No random user-to-group assignments will be created."
            )
        elif groups and not user_keys and show_warnings:
            logging.warning(
                f"Cannot assign users to {len(available_groups)} group(s): No users available. "
                f"Set 'users' to at least 1 in tenant configuration."
            )
        
        # User to administrative unit assignments
        if administrative_units and user_keys:
            au_assigned_users = random.sample(user_keys, user_subset_size)
            for user in au_assigned_users:
                au = random.choice(au_keys)
                assignment_key = f"{user}-{au}"
                user_au_assignments[assignment_key] = {
                    'user_name': user,
                    'administrative_unit_name': au
                }
        elif administrative_units and not user_keys and show_warnings:
            logging.warning(
                f"Cannot assign users to {len(administrative_units)} administrative unit(s): No users available. "
                f"Set 'users' to at least 1 in tenant configuration."
            )
        
        # User role assignments
        if ENTRA_ROLES and user_keys:
            role_assigned_users = random.sample(user_keys, user_subset_size)
            for user in role_assigned_users:
                role_name = random.choice(list(ENTRA_ROLES.keys()))
                role_id = ENTRA_ROLES[role_name]
                assignment_key = f"{user}-{role_name}"
                user_role_assignments[assignment_key] = {
                    'user_name': user,
                    'role_definition_id': role_id
                }
        elif ENTRA_ROLES and not user_keys and show_warnings:
            logging.warning(
                "Cannot assign Entra ID roles to users: No users available. "
                "Set 'users' to at least 1 in tenant configuration."
            )
        
        # Application role assignments
        # Set to 0 if no applications exist to prevent sampling from empty list
        app_subset_size = max(1, len(app_keys) // 2) if app_keys else 0
        if ENTRA_ROLES and app_keys:
            role_assigned_apps = random.sample(app_keys, app_subset_size)
            for app in role_assigned_apps:
                role_name = random.choice(list(ENTRA_ROLES.keys()))
                role_id = ENTRA_ROLES[role_name]
                assignment_key = f"{app}-{role_name}"
                app_role_assignments[assignment_key] = {
                    'app_name': app,
                    'role_id': role_id
                }
        elif ENTRA_ROLES and not app_keys and show_warnings:
            logging.warning(
                "Cannot assign Entra ID roles to applications: No applications available. "
                "Set 'applications' to at least 1 in tenant configuration."
            )
        
        # Application API permission assignments
        if GRAPH_API_PERMISSIONS and app_keys:
            api_assigned_apps = random.sample(app_keys, app_subset_size)
            for app in api_assigned_apps:
                api_name = random.choice(list(GRAPH_API_PERMISSIONS.keys()))
                api_permission_id = GRAPH_API_PERMISSIONS[api_name]['id']
                assignment_key = f"{app}-{api_name}"
                app_api_permission_assignments[assignment_key] = {
                    'app_name': app,
                    'api_permission_id': api_permission_id,
                }
        elif GRAPH_API_PERMISSIONS and not app_keys and show_warnings:
            logging.warning(
                "Cannot assign Graph API permissions to applications: No applications available. "
                "Set 'applications' to at least 1 in tenant configuration."
            )
        
        return (
            user_group_assignments,
            user_au_assignments,
            user_role_assignments,
            app_role_assignments,
            app_api_permission_assignments
        )