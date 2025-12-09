"""
Assignment management for BadZure.
Handles creation of random assignments between entities.
"""
import random
from typing import Dict
from src.constants import ENTRA_ROLES, GRAPH_API_PERMISSIONS


class AssignmentManager:
    """Manages creation of random assignments between entities."""
    
    def create_random_assignments(
        self,
        users: Dict,
        groups: Dict,
        administrative_units: Dict,
        applications: Dict
    ) -> tuple:
        """
        Create random assignments between entities.
        
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
        
        user_keys = list(users.keys())
        group_keys = list(groups.keys())
        au_keys = list(administrative_units.keys())
        app_keys = list(applications.keys())
        
        # Calculate subset size as one-third of the total users
        user_subset_size = max(1, len(user_keys) // 3)
        
        # User to group assignments
        if groups:
            group_assigned_users = random.sample(user_keys, user_subset_size)
            for user in group_assigned_users:
                group = random.choice(group_keys)
                assignment_key = f"{user}-{group}"
                user_group_assignments[assignment_key] = {
                    'user_name': user,
                    'group_name': group
                }
        
        # User to administrative unit assignments
        if administrative_units:
            au_assigned_users = random.sample(user_keys, user_subset_size)
            for user in au_assigned_users:
                au = random.choice(au_keys)
                assignment_key = f"{user}-{au}"
                user_au_assignments[assignment_key] = {
                    'user_name': user,
                    'administrative_unit_name': au
                }
        
        # User role assignments
        if ENTRA_ROLES:
            role_assigned_users = random.sample(user_keys, user_subset_size)
            for user in role_assigned_users:
                role_name = random.choice(list(ENTRA_ROLES.keys()))
                role_id = ENTRA_ROLES[role_name]
                assignment_key = f"{user}-{role_name}"
                user_role_assignments[assignment_key] = {
                    'user_name': user,
                    'role_definition_id': role_id
                }
        
        # Application role assignments
        app_subset_size = max(1, len(app_keys) // 2)
        if ENTRA_ROLES:
            role_assigned_apps = random.sample(app_keys, app_subset_size)
            for app in role_assigned_apps:
                role_name = random.choice(list(ENTRA_ROLES.keys()))
                role_id = ENTRA_ROLES[role_name]
                assignment_key = f"{app}-{role_name}"
                app_role_assignments[assignment_key] = {
                    'app_name': app,
                    'role_id': role_id
                }
        
        # Application API permission assignments
        if GRAPH_API_PERMISSIONS:
            api_assigned_apps = random.sample(app_keys, app_subset_size)
            for app in api_assigned_apps:
                api_name = random.choice(list(GRAPH_API_PERMISSIONS.keys()))
                api_permission_id = GRAPH_API_PERMISSIONS[api_name]['id']
                assignment_key = f"{app}-{api_name}"
                app_api_permission_assignments[assignment_key] = {
                    'app_name': app,
                    'api_permission_id': api_permission_id,
                }
        
        return (
            user_group_assignments,
            user_au_assignments,
            user_role_assignments,
            app_role_assignments,
            app_api_permission_assignments
        )