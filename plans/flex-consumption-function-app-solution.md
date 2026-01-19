# Flex Consumption Function App Solution - Using azurerm Provider

## Discovery

The azurerm provider HAS native support for Flex Consumption Function Apps via:
- `azurerm_function_app_flex_consumption` resource
- Documentation: https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/function_app_flex_consumption

## Solution

Replace the current `azurerm_linux_function_app` and `azurerm_windows_function_app` resources with `azurerm_function_app_flex_consumption`.

### Key Differences

**Current (doesn't work with FC1):**
```hcl
resource "azurerm_linux_function_app" "function_apps_linux" {
  name                = each.value.name
  service_plan_id     = azurerm_service_plan.function_plan_linux[each.key].id
  storage_account_name = ...
  
  site_config {
    application_stack {
      python_version = "3.11"
    }
  }
}
```

**New (works with FC1):**
```hcl
resource "azurerm_function_app_flex_consumption" "function_apps" {
  name                = each.value.name
  resource_group_name = each.value.resource_group_name
  location            = each.value.location
  
  storage_account_name       = azurerm_storage_account.function_storage[each.key].name
  storage_account_access_key = azurerm_storage_account.function_storage[each.key].primary_access_key
  
  site_config {
    application_stack {
      # For Linux Python
      python_version = each.value.os_type == "linux" ? "3.11" : null
      
      # For Windows .NET
      dotnet_version              = each.value.os_type == "windows" ? "8.0" : null
      use_dotnet_isolated_runtime = each.value.os_type == "windows" ? true : null
    }
  }
  
  identity {
    type = "SystemAssigned"
  }
}
```

## Implementation Plan

### Step 1: Remove Separate App Service Plans
- Flex Consumption doesn't need explicit App Service Plans
- The resource creates them automatically

### Step 2: Replace Function App Resources
- Remove `azurerm_linux_function_app` and `azurerm_windows_function_app`
- Add single `azurerm_function_app_flex_consumption` resource
- Handle both Linux and Windows via conditional `application_stack`

### Step 3: Update Role Assignment References
- Change from separate Linux/Windows resources to single resource
- Update principal_id references

### Step 4: Update Terraform Variables
- Keep `os_type` field in variables
- Use it to conditionally set runtime in application_stack

## Benefits

✅ Uses native azurerm provider (no new providers needed)
✅ Supports Flex Consumption (FC1) natively
✅ No quota required
✅ Simpler than separate Linux/Windows resources
✅ Matches Azure Portal behavior

## Next Steps

1. Update `terraform/main.tf` to use `azurerm_function_app_flex_consumption`
2. Remove separate App Service Plan resources
3. Update role assignment references
4. Test deployment

This is the correct solution!
