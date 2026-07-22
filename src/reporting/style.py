"""Shared visual vocabulary for all report panels."""

DEFAULT_NODE_COLOR = "#64748b"
SENSITIVE_BORDER_COLOR = "#ef4444"
BACKGROUND_COLOR = "#1a1f2e"

EDGE_STYLES = {
    "normal": {"color": "#94a3b8", "width": 2, "line_style": "solid"},
    "spine": {"color": "#ef4444", "width": 5, "line_style": "solid"},
    "offspine": {"color": "#64748b", "width": 2, "line_style": "dashed"},
    "inferred": {"color": "#38bdf8", "width": 3, "line_style": "dashed"},
}

# Colors are keyed by ontology type, never by panel, so the same entity reads
# consistently when it appears in inventory, posture, and attack views.
NODE_PALETTE = {
    "AssignmentCatalog": "#1565c0",
    "AssignmentFamily": "#ff6d00",
    "Role": "#9b6bd6",
    "Permission": "#1e88e5",
    "Relationship": "#2dd4bf",
    "PrincipalSummary": "#64748b",
    "Organization": "#1e88e5",
    "SecurityPrincipalCatalog": "#2563eb",
    "AdministrativeUnitCatalog": "#0891b2",
    "IdentityCategory": "#1565c0",
    "IdentitySummary": "#64748b",
    "AdministrativeUnit": "#22d3ee",
    "User": "#4c86d6",
    "UserSummary": "#4c86d6",
    "Identity": "#4c86d6",
    "Group": "#2dd4bf",
    "GroupSummary": "#2dd4bf",
    "ServicePrincipal": "#9b6bd6",
    "ServicePrincipalSummary": "#9b6bd6",
    "ManagedIdentity": "#a78bfa",
    "Application": "#8b5cf6",
    "Subscription": "#1565c0",
    "ResourceGroup": "#06b6d4",
    "UnplacedResources": "#ff6d00",
    "AzureResource": "#e0a83b",
    "KeyVault": "#f59e0b",
    "KeyVaultSummary": "#f59e0b",
    "StorageAccount": "#eab308",
    "StorageAccountSummary": "#eab308",
    "VirtualMachine": "#10b981",
    "VirtualMachineSummary": "#10b981",
    "LogicApp": "#ec4899",
    "LogicAppSummary": "#ec4899",
    "AutomationAccount": "#14b8a6",
    "AutomationAccountSummary": "#14b8a6",
    "FunctionApp": "#f97316",
    "FunctionAppSummary": "#f97316",
    "AppService": "#fb7185",
    "AppServiceSummary": "#fb7185",
    "CosmosDB": "#84cc16",
    "CosmosDBSummary": "#84cc16",
    "MicrosoftGraph": "#2563eb",
    "ExchangeOnline": "#0284c7",
    "EntraRole": "#c084fc",
    "Credential": "#f43f5e",
    "Internet": "#64748b",
    "Attacker": "#dc2626",
    "ComputeResource": "#10b981",
    "DataResource": "#eab308",
    "Session": "#f97316",
    "Objective": "#ef4444",
}


def color_for(node_type: str) -> str:
    return NODE_PALETTE.get(node_type, DEFAULT_NODE_COLOR)
