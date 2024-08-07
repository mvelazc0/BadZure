# https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference

# Roles used by BadZure for attack paths

HIGH_PRIVILEGED_ENTRA_ROLES = {

    "Privileged Role Administrator":   "e8611ab8-c189-46e8-94e1-60213ab1f814",    
    "Privileged Authentication Administrator":   "7be44c8a-adaf-4e2a-84d6-ab2649e08a13",    
    "Global Administrator":   "62e90394-69f5-4237-9190-012177145e10",    
}

# Roles tagged by Microsoft as privileged

PRIVILEGED_ENTRA_ROLES = {

    "Application Administrator":   "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3",
    "Application Developer":   "cf1c38e5-3621-4004-a7cb-879624dced7c",
    "Authentication Administrator":   "c4e39bd9-1100-46d3-8c65-fb160da0071f",    
    "Authentication Extensibility Administrator":   "25a516ed-2fa0-40ea-a2d0-12923a21473a",
    "B2C IEF Keyset Administrator":   "aaf43236-0c0d-4d5f-883a-6955382ac081",
    "Cloud Application Administrator":   "158c047a-c907-4556-b7ef-446551a6b5f7",   
    "Cloud Device Administrator":   "7698a772-787b-4ac8-901f-60d6b08affd2",
    "Compliance Administrator":   "17315797-102d-40b4-93e0-432062caca18",
    "Conditional Access Administrator":   "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9",
    "Directory Synchronization Accounts":   "d29b2b05-8046-44ba-8758-1e26182fcf32",
    "Directory Writers":   "9360feb5-f418-4baa-8175-e2a00bac4301",
    "Domain Name Administrator":   "8329153b-31d0-4727-b945-745eb3bc5f31",
    "External Identity Provider Administrator":   "be2f45a1-457d-42af-a067-6ec1fa63bc45",
#    "Global Administrator":   "62e90394-69f5-4237-9190-012177145e10",
    "Global Reader":   "f2ef992c-3afb-46b9-b7cf-a126ee74c451",
    "Helpdesk Administrator":   "729827e3-9c14-49f7-bb1b-9608f156bbb8",
    "Hybrid Identity Administrator":   "8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2",
    "Intune Administrator":   "3a2c62db-5318-420d-8d74-23affee5d9d5",
    "Lifecycle Workflows Administrator":   "59d46f88-662b-457b-bceb-5c3809e5908f",    
    "Partner Tier1 Support":   "4ba39ca4-527c-499a-b93d-d9b492c50246",
    "Partner Tier2 Support":   "e00e864a-17c5-4a4b-9c06-f5b95a8d5bd8",
    "Password Administrator":   "966707d0-3269-4727-9be2-8c3a10f19b9d",
#    "Privileged Authentication Administrator":   "7be44c8a-adaf-4e2a-84d6-ab2649e08a13",
#    "Privileged Role Administrator":   "e8611ab8-c189-46e8-94e1-60213ab1f814",
    "Security Administrator":   "194ae4cb-b126-40b2-bd5b-6091b380977d",
    "Security Operator":   "5f2222b1-57c3-48ba-8ad5-d4759f1fde6f",
    "Security Reader":   "5d6b6bb7-de71-4623-b4af-96380a352509",
    "User Administrator":   "fe930be7-5e62-47db-91af-98c3a49a38b1"
}

ENTRA_ROLES = {
    
    "Knowledge Manager":   "744ec460-397e-42ad-a462-8b3f9747a02c",
    "Teams Communications Support Engineer":   "f70938a0-fc10-4177-9e90-2178f8765737",
    "Windows 365 Administrator":   "11451d60-acb2-45eb-a7d6-43d0f0125c13",
    "Printer Technician":   "e8cef6f1-e4bd-4ea8-bc07-4b8d950f4477",
    "Microsoft Hardware Warranty Specialist":   "281fe777-fb20-4fbb-b7a3-ccebce5b0d96",
    "Device Join":   "9c094953-4995-41c8-84c8-3ebb9b32c93f",
    "Dynamics 365 Business Central Administrator":   "963797fb-eb3b-4cde-8ce3-5878b3f32a3f",
    "SharePoint Embedded Administrator":   "1a7d78b6-429f-476b-b8eb-35fb715fffd4",
    "Usage Summary Reports Reader":   "75934031-6c7e-415a-99d7-48dbd49e875e",
    "Guest Inviter":   "95e79109-95c0-4d8e-aee3-d01accf2d47b",
    "Insights Analyst":   "25df335f-86eb-4119-b717-0ff02de207e9",
    "Attribute Assignment Administrator":   "58a13ea3-c632-46ae-9ee0-9c0d43cd7f3d",
    "Extended Directory User Administrator":   "dd13091a-6207-4fc0-82ba-3641e056ab95",
    "Printer Administrator":   "644ef478-e28f-4e28-b9dc-3fdde9aa0b1f",
    "Organizational Messages Writer":   "507f53e4-4e52-4077-abd3-d2e1558b6ea2",
    "Azure Information Protection Administrator":   "7495fdc4-34c4-4d15-a289-98788ce399fd",
    "Organizational Branding Administrator":   "92ed04bf-c94a-4b82-9729-b799a7a4c178",
    "Attribute Assignment Reader":   "ffd52fa5-98dc-465c-991d-fc073eb59f8f",
    "Teams Administrator":   "69091246-20e8-4a56-aa4d-066075b2a7a8",
    "Network Administrator":   "d37c8bed-0711-4417-ba38-b4abe66ce4c2",
    "External ID User Flow Administrator":   "6e591065-9bad-43ed-90f3-e9424366d2f0",
    "Groups Administrator":   "fdd7a751-b60b-444a-984c-02652fe8fa1c",
    "Attack Simulation Administrator":   "c430b396-e693-46cc-96f3-db01bf8bb62a",
    "Attribute Log Reader":   "9c99539d-8186-4804-835f-fd51ef9e2dcd",
    "Yammer Administrator":   "810a2642-a034-447f-a5e8-41beaa378541",
    "Teams Communications Administrator":   "baf37b3a-610e-45da-9e62-d9d1e5e8914b",
    "Knowledge Administrator":   "b5a8dcf3-09d5-43a9-a639-8e29ef291470",
    "Service Support Administrator":   "f023fd81-a637-4b56-95fd-791ac0226033",
    "Compliance Data Administrator":   "e6d1a23a-da11-4be4-9570-befc86d067a7",
    "External ID User Flow Attribute Administrator":   "0f971eea-41eb-4569-a71e-57bb8a3eff1e",
    "Dynamics 365 Administrator":   "44367163-eba1-44c3-98af-f5787879f96a",
    "Exchange Administrator":   "29232cdf-9323-42fd-ade2-1d097af3e4de",
    "Message Center Privacy Reader":   "ac16e43d-7b2d-40e0-ac05-243ff356ab5b",
    "Organizational Messages Approver":   "e48398e2-f4bb-4074-8f31-4586725e205b",
    "Insights Administrator":   "eb1f4a8d-243a-41f0-9fbd-c7cdf6c5ef7c",
    "Workplace Device Join":   "c34f683f-4d5a-4403-affd-6615e00e3a7f",
    #"Guest User":   "10dae51f-b6af-4016-8d66-8c2a99b929b3", # removing implicit roles to avoid errors
    "Edge Administrator":   "3f1acade-1e04-4fbc-9b69-f0302cd84aef",
    "Insights Business Leader":   "31e939ad-9672-4796-9c2e-873181342d2d",
    "Teams Communications Support Specialist":   "fcf91098-03e3-41a9-b5ba-6f0ec8188a12",
    "Global Secure Access Administrator":   "ac434307-12b9-4fa1-a708-88bf58caabc1",
    "Fabric Administrator":   "a9ea8996-122f-4c74-9520-8edcd192826c",
    "Viva Pulse Administrator":   "87761b17-1ed2-4af3-9acd-92a150038160",
    "Billing Administrator":   "b0f54661-2d74-4c50-afa3-1ec803f12efe",
    "Office Apps Administrator":   "2b745bdf-0803-4d80-aa65-822c4493daac",
    "Attribute Definition Reader":   "1d336d2c-4ae8-42ef-9711-b3604ce3fc2c",
    "Directory Readers":   "88d8e3e3-8f55-4a1e-953a-9b9898b8876b",
    "Kaizala Administrator":   "74ef975b-6605-40af-a5d2-b9539d836353",
    "Tenant Creator":   "112ca1a2-15ad-4102-995e-45b0bc479a6a",
    "Permissions Management Administrator":   "af78dc32-cf4d-46f9-ba4e-4428526346b5",
    "Power Platform Administrator":   "11648597-926c-4cf3-9c36-bcebb0ba8dcc",
    "Attribute Definition Administrator":   "8424c6f0-a189-499e-bbd0-26c1753c96d4",
    "Search Editor":   "8835291a-918c-4fd7-a9ce-faa49f0cf7d9",
    "Viva Goals Administrator":   "92b086b3-e367-4ef2-b869-1de128fb986e",
    "Customer LockBox Access Approver":   "5c4f9dcd-47dc-4cf7-8c9a-9e4207cbfc91",
    #"Restricted Guest User":   "2af84b1e-32c8-42b7-82bc-daa82404023b", # removing implicit roles to avoid errors
    "Azure AD Joined Device Local Administrator":   "9f06204d-73c1-4d4c-880a-6edb90606fd8",
    "B2C IEF Policy Administrator":   "3edaf663-341e-4475-9f94-5c398ef6c070",
    "Teams Telephony Administrator":   "aa38014f-0993-46e9-9b45-30501a20909d",
    "Device Users":   "d405c6df-0af8-4e3b-95e4-4d06e542189e",
    "Azure DevOps Administrator":   "e3973bdf-4987-49ae-837a-ba8e231c7286",
    "Reports Reader":   "4a5d8f65-41da-4de4-8968-e035b65339cf",
    "Skype for Business Administrator":   "75941009-915a-4869-abe7-691bff18279e",
    "Microsoft Hardware Warranty Administrator":   "1501b917-7653-4ff9-a4b5-203eaf33784f",
    "Desktop Analytics Administrator":   "38a96431-2bdf-4b4c-8b6e-5d3d8abac1a4",
    "User Experience Success Manager":   "27460883-1df1-4691-b032-3b79643e5e63",
    "Virtual Visits Administrator":   "e300d9e7-4a2b-4295-9eff-f1c78b36cc98",
    "Device Managers":   "2b499bcd-da44-4968-8aec-78e1674fa64d",
    "Message Center Reader":   "790c1fb9-7f7d-4f88-86a1-ef1f95c05c1b",
    "Authentication Policy Administrator":   "0526716b-113d-4c15-b2c8-68e3c22b9f80",
    "Identity Governance Administrator":   "45d8d3c5-c802-45c6-b32a-1d70b5e1e86e",
    "Attribute Log Administrator":   "5b784334-f94b-471a-a387-e7219fc49ca2",
    "Attack Payload Author":   "9c6df0f2-1e7c-4dc3-b195-66dfbd24aa8f",
    "On Premises Directory Sync Account":   "a92aed5d-d78a-4d16-b381-09adb37eb3b0",
    "Teams Devices Administrator":   "3d762c5a-1b6c-493f-843e-55a3b42923d4",
    "License Administrator":   "4d6ac14f-3453-41d0-bef9-a3e0c569773a",
    "Microsoft 365 Migration Administrator":   "8c8b803f-96e1-4129-9349-20738d9f9652",
    #"User":   "a0b1b346-4d3e-4e8b-98f8-753987be4970", # removing implicit roles to avoid errors
    "SharePoint Administrator":   "f28a1f50-f6e7-4571-818b-6a12f2af6b6c",
    "Search Administrator":   "0964bb5e-9bdb-4d7b-ac29-58e794862a40",
    "Windows Update Deployment Administrator":   "32696413-001a-46ae-978c-ce0f6b3620d2",
    "Exchange Recipient Administrator":   "31392ffb-586c-42d1-9346-e59415a2cc4e",
    "Cloud App Security Administrator":   "892c5842-a9a6-463a-8041-72aa08ca3cf6"
}

HIGH_PRIVILEGED_GRAPH_API_PERMISSIONS = {

    "RoleManagement.ReadWrite.Directory": {
        "allowedMemberTypes": ["Application"],
        "id": "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8",
        "origin": "Application",
    },    

    "AppRoleAssignment.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "06b708a9-e830-4db3-a914-8e69da51d44f",
        "origin": "Application",
    },

    "RoleManagement.ReadWrite.Directory": {
        "allowedMemberTypes": ["Application"],
        "id": "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8",
        "origin": "Application",
    }
    
}

GRAPH_API_PERMISSIONS = {
    
    "PrintJob.ReadWriteBasic.All": {
        "allowedMemberTypes": ["Application"],
        "id": "57878358-37f4-4d3a-8c20-4816e0d457b1",
        "origin": "Application",
    },
    "CallRecord-PstnCalls.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "a2611786-80b3-417e-adaa-707d4261a5f0",
        "origin": "Application",
    },
    "AuditLogsQuery-CRM.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "20e6f8e4-ffac-4cf7-82f7-70ddb7564318",
        "origin": "Application",
    },
    "DeviceManagementApps.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "7a6ee1e7-141e-4cec-ae74-d9db155731ff",
        "origin": "Application",
    },
    "Team.ReadBasic.All": {
        "allowedMemberTypes": ["Application"],
        "id": "2280dda6-0bfd-44ee-a2f4-cb867cfc4c1e",
        "origin": "Application",
    },
    "IdentityProvider.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "90db2b9a-d928-4d33-a4dd-8442ae3d41e4",
        "origin": "Application",
    },
    "SearchConfiguration.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "ada977a5-b8b1-493b-9a91-66c206d76ecf",
        "origin": "Application",
    },
    "IndustryData-InboundFlow.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "305f6ba2-049a-4b1b-88bb-fe7e08758a00",
        "origin": "Application",
    },
    "OnPremisesPublishingProfiles.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "0b57845e-aa49-4e6f-8109-ce654fffa618",
        "origin": "Application",
    },
    "ProgramControl.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "eedb7fdd-7539-4345-a38b-4839e4a84cbd",
        "origin": "Application",
    },
    "PartnerBilling.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "7c3e1994-38ff-4412-a99b-9369f6bb7706",
        "origin": "Application",
    },
    "ChannelMessage.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "7b2449af-6ccd-4f4d-9f78-e550c193f0d1",
        "origin": "Application",
    },
    "PrivilegedAccess.Read.AzureAD": {
        "allowedMemberTypes": ["Application"],
        "id": "4cdc2547-9148-4295-8d11-be0db1391d6b",
        "origin": "Application",
    },
    "UserTeamwork.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "fbcd7ef1-df0d-4e05-bb28-93424a89c6df",
        "origin": "Application",
    },
    "PrivilegedAccess.ReadWrite.AzureResources": {
        "allowedMemberTypes": ["Application"],
        "id": "6f9d5abc-2db6-400b-a267-7de22a40fb87",
        "origin": "Application",
    },
    "UserShiftPreferences.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "de023814-96df-4f53-9376-1e2891ef5a18",
        "origin": "Application",
    },
    "TeamsAppInstallation.ReadWriteForUser.All": {
        "allowedMemberTypes": ["Application"],
        "id": "74ef0291-ca83-4d02-8c7e-d2391e6a444f",
        "origin": "Application",
    },
    "OnlineMeetingArtifact.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "df01ed3b-eb61-4eca-9965-6b3d789751b2",
        "origin": "Application",
    },
    "SecurityIncident.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "34bf0e97-1971-4929-b999-9e2442d941d7",
        "origin": "Application",
    },
    "ProfilePhoto.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "e24d31aa-e1ab-4c80-85fe-23018690335d",
        "origin": "Application",
    },
    "Schedule-WorkingTime.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "0b21c159-dbf4-4dbb-a6f6-490e412c716e",
        "origin": "Application",
    },
    "Policy.ReadWrite.CrossTenantAccess": {
        "allowedMemberTypes": ["Application"],
        "id": "338163d7-f101-4c92-94ba-ca46fe52447c",
        "origin": "Application",
    },
    "OnPremDirectorySynchronization.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "bb70e231-92dc-4729-aff5-697b3f04be95",
        "origin": "Application",
    },
    "PrintJob.ReadBasic.All": {
        "allowedMemberTypes": ["Application"],
        "id": "fbf67eee-e074-4ef7-b965-ab5ce1c1f689",
        "origin": "Application",
    },
    "DeviceManagementConfiguration.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "dc377aa6-52d8-4e23-b271-2a7ae04cedf3",
        "origin": "Application",
    },
    "Printer.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "9709bb33-4549-49d4-8ed9-a8f65e45bb0f",
        "origin": "Application",
    },
    "SecurityIdentitiesHealth.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "ab03ddd5-7ae4-4f2e-8af8-86654f7e0a27",
        "origin": "Application",
    },
    "IndustryData-InboundFlow.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "e688c61f-d4c6-4d64-a197-3bcf6ba1d6ad",
        "origin": "Application",
    },
    "AccessReview.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "d07a8cc0-3d51-4b77-b3b0-32704d1f69fa",
        "origin": "Application",
    },
    "LearningSelfInitiatedCourse.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "467524fc-ed22-4356-a910-af61191e3503",
        "origin": "Application",
    },
    "Chat.ReadBasic.All": {
        "allowedMemberTypes": ["Application"],
        "id": "b2e060da-3baf-4687-9611-f4ebc0f0cbde",
        "origin": "Application",
    },
    "Synchronization.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "9b50c33d-700f-43b1-b2eb-87e89b703581",
        "origin": "Application",
    },
    "SecurityIdentitiesSensors.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "5f0ffea2-f474-4cf2-9834-61cda2bcea5c",
        "origin": "Application",
    },
    "Organization.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "292d869f-3427-49a8-9dab-8c70152b74e9",
        "origin": "Application",
    },
    "OrgSettings-Microsoft365Install.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "6cdf1fb1-b46f-424f-9493-07247caa22e2",
        "origin": "Application",
    },
    "TeamworkAppSettings.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "475ebe88-f071-4bd7-af2b-642952bd4986",
        "origin": "Application",
    },
    "ExternalUserProfile.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "1987d7a0-d602-4262-ab90-cfdd43b37545",
        "origin": "Application",
    },
    "TeamsTab.ReadWriteForUser.All": {
        "allowedMemberTypes": ["Application"],
        "id": "425b4b59-d5af-45c8-832f-bb0b7402348a",
        "origin": "Application",
    },
    "People.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "b528084d-ad10-4598-8b93-929746b4d7d6",
        "origin": "Application",
    },
    "Calendars.ReadBasic.All": {
        "allowedMemberTypes": ["Application"],
        "id": "8ba4a692-bc31-4128-9094-475872af8a53",
        "origin": "Application",
    },
    "AuditLog.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "b0afded3-3588-46d8-8b3d-9842eff778da",
        "origin": "Application",
    },
    "Application.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "9a5d68dd-52b0-4cc2-bd40-abcf44ac3a30",
        "origin": "Application",
    },
    "IndustryData-ReferenceDefinition.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "6ee891c3-74a4-4148-8463-0c834375dfaf",
        "origin": "Application",
    },
    "ReportSettings.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "2a60023f-3219-47ad-baa4-40e17cd02a1d",
        "origin": "Application",
    },
    "Community.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "407f0cce-3212-441f-9f55-3bc91342cf86",
        "origin": "Application",
    },
    "IdentityRiskEvent.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "6e472fd1-ad78-48da-a0f0-97ab2c6b769e",
        "origin": "Application",
    },
    "AppCatalog.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "dc149144-f292-421e-b185-5953f2e98d7f",
        "origin": "Application",
    },
    "TeamworkTag.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "a3371ca5-911d-46d6-901c-42c8c7a937d8",
        "origin": "Application",
    },
    "TeamsTab.ReadWriteForTeam.All": {
        "allowedMemberTypes": ["Application"],
        "id": "6163d4f4-fbf8-43da-a7b4-060fe85ed148",
        "origin": "Application",
    },
    "Policy.ReadWrite.ExternalIdentities": {
        "allowedMemberTypes": ["Application"],
        "id": "03cc4f92-788e-4ede-b93f-199424d144a5",
        "origin": "Application",
    },
    "PrivilegedAssignmentSchedule.Read.AzureADGroup": {
        "allowedMemberTypes": ["Application"],
        "id": "cd4161cb-f098-48f8-a884-1eda9a42434c",
        "origin": "Application",
    },
    "SchedulePermissions.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "7239b71d-b402-4150-b13d-78ecfe8df441",
        "origin": "Application",
    },
    "TeamMember.ReadWriteNonOwnerRole.All": {
        "allowedMemberTypes": ["Application"],
        "id": "4437522e-9a86-4a41-a7da-e380edd4a97d",
        "origin": "Application",
    },
    "eDiscovery.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "b2620db1-3bf7-4c5b-9cb9-576d29eac736",
        "origin": "Application",
    },
    "HealthMonitoringAlert.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "5183ed5d-b7f8-4e9a-915e-dafb46b9cb62",
        "origin": "Application",
    },
    "Lists.SelectedOperations.Selected": {
        "allowedMemberTypes": ["Application"],
        "id": "23c5a9bd-d900-4ecf-be26-a0689755d9e5",
        "origin": "Application",
    },
    "IndustryData-ReferenceDefinition.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "bda16293-63d3-45b7-b16b-833841d27d56",
        "origin": "Application",
    },
    "DirectoryRecommendations.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "ae73097b-cb2a-4447-b064-5d80f6093921",
        "origin": "Application",
    },
    "Notes.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "3aeca27b-ee3a-4c2b-8ded-80376e2134a4",
        "origin": "Application",
    },
    "CustomSecAttributeAuditLogs.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "2a4f026d-e829-4e84-bdbf-d981a2703059",
        "origin": "Application",
    },
    "RoleManagement.Read.Exchange": {
        "allowedMemberTypes": ["Application"],
        "id": "c769435f-f061-4d0b-8ff1-3d39870e5f85",
        "origin": "Application",
    },
    "SecurityAlert.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "ed4fca05-be46-441f-9803-1873825f8fdb",
        "origin": "Application",
    },
    "User.Export.All": {
        "allowedMemberTypes": ["Application"],
        "id": "405a51b5-8d8d-430b-9842-8be4b0e9f324",
        "origin": "Application",
    },
    "OrganizationalBranding.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "d2ebfbc1-a5f8-424b-83a6-56ab5927a73c",
        "origin": "Application",
    },
    "ServicePrincipalEndpoint.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "5256681e-b7f6-40c0-8447-2d9db68797a0",
        "origin": "Application",
    },
    "TeamsTab.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "a96d855f-016b-47d7-b51c-1218a98d791c",
        "origin": "Application",
    },
    "PrivilegedAccess.ReadWrite.AzureAD": {
        "allowedMemberTypes": ["Application"],
        "id": "854d9ab1-6657-4ec8-be45-823027bcd009",
        "origin": "Application",
    },
    "VirtualAppointment.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "bf46a256-f47d-448f-ab78-f226fff08d40",
        "origin": "Application",
    },
    "ConsentRequest.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "1260ad83-98fb-4785-abbb-d6cc1806fd41",
        "origin": "Application",
    },
    "SharePointTenantSettings.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "19b94e34-907c-4f43-bde9-38b1909ed408",
        "origin": "Application",
    },
    "Policy.Read.IdentityProtection": {
        "allowedMemberTypes": ["Application"],
        "id": "b21b72f6-4e6a-4533-9112-47eea9f97b28",
        "origin": "Application",
    },
    "Policy.Read.ConditionalAccess": {
        "allowedMemberTypes": ["Application"],
        "id": "37730810-e9ba-4e46-b07e-8ca78d182097",
        "origin": "Application",
    },
    "Mail.Send": {
        "allowedMemberTypes": ["Application"],
        "id": "b633e1c5-b582-4048-a93e-9f11b44c7e96",
        "origin": "Application",
    },
    "AttackSimulation.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "93283d0a-6322-4fa8-966b-8c121624760d",
        "origin": "Application",
    },
    "PrintJob.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "5114b07b-2898-4de7-a541-53b0004e2e13",
        "origin": "Application",
    },
    "Files.ReadWrite.AppFolder": {
        "allowedMemberTypes": ["Application"],
        "id": "b47b160b-1054-4efd-9ca0-e2f614696086",
        "origin": "Application",
    },
    #"RoleManagement.ReadWrite.Directory": {
    #    "allowedMemberTypes": ["Application"],
    #    "id": "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8",
    #    "origin": "Application",
    #},
    "CloudPC.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "a9e09520-8ed4-4cde-838e-4fdea192c227",
        "origin": "Application",
    },
    "Application.ReadWrite.OwnedBy": {
        "allowedMemberTypes": ["Application"],
        "id": "18a4783c-866b-4cc7-a460-3d5e5662c884",
        "origin": "Application",
    },
    "DeviceManagementManagedDevices.PrivilegedOperations.All": {
        "allowedMemberTypes": ["Application"],
        "id": "5b07b0dd-2377-4e44-a38d-703f09a0dc3c",
        "origin": "Application",
    },
    "EntitlementManagement.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "9acd699f-1e81-4958-b001-93b1d2506e19",
        "origin": "Application",
    },
    "CallRecords.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "45bbb07e-7321-4fd7-a8f6-3ff27e6a81c8",
        "origin": "Application",
    },
    "HealthMonitoringAlertConfig.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "432e76f0-8af6-4315-a853-66ab9538f480",
        "origin": "Application",
    },
    "SynchronizationData-User.Upload": {
        "allowedMemberTypes": ["Application"],
        "id": "db31e92a-b9ea-4d87-bf6a-75a37a9ca35a",
        "origin": "Application",
    },
    "TeamsAppInstallation.ReadWriteForTeam.All": {
        "allowedMemberTypes": ["Application"],
        "id": "5dad17ba-f6cc-4954-a5a2-a0dcc95154f0",
        "origin": "Application",
    },
    "Directory.Write.Restricted": {
        "allowedMemberTypes": ["Application"],
        "id": "f20584af-9290-4153-9280-ff8bb2c0ea7f",
        "origin": "Application",
    },
    "AuditLogsQuery-Entra.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "7276d950-48fc-4269-8348-f22f2bb296d0",
        "origin": "Application",
    },
    "PrivilegedAssignmentSchedule.ReadWrite.AzureADGroup": {
        "allowedMemberTypes": ["Application"],
        "id": "41202f2c-f7ab-45be-b001-85c9728b9d69",
        "origin": "Application",
    },
    "ChannelSettings.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "243cded2-bd16-4fd6-a953-ff8177894c3d",
        "origin": "Application",
    },
    "PeopleSettings.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "b6890674-9dd5-4e42-bb15-5af07f541ae1",
        "origin": "Application",
    },
    "FileStorageContainer.Selected": {
        "allowedMemberTypes": ["Application"],
        "id": "40dc41bc-0f7e-42ff-89bd-d9516947e474",
        "origin": "Application",
    },
    "Policy.Read.PermissionGrant": {
        "allowedMemberTypes": ["Application"],
        "id": "9e640839-a198-48fb-8b9a-013fd6f6cbcd",
        "origin": "Application",
    },
    "OrgSettings-Microsoft365Install.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "83f7232f-763c-47b2-a097-e35d2cbe1da5",
        "origin": "Application",
    },
    "TeamworkDevice.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "79c02f5b-bd4f-4713-bc2c-a8a4a66e127b",
        "origin": "Application",
    },
    "Place.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "913b9306-0ce1-42b8-9137-6a7df690a760",
        "origin": "Application",
    },
    "EduAssignments.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "4c37e1b6-35a1-43bf-926a-6f30f2cdf585",
        "origin": "Application",
    },
    "DeviceManagementConfiguration.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "9241abd9-d0e6-425a-bd4f-47ba86e767a4",
        "origin": "Application",
    },
    "IndustryData-SourceSystem.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "7d866958-e06e-4dd6-91c6-a086b3f5cfeb",
        "origin": "Application",
    },
    "TeamsAppInstallation.ReadWriteSelfForTeam.All": {
        "allowedMemberTypes": ["Application"],
        "id": "9f67436c-5415-4e7f-8ac1-3014a7132630",
        "origin": "Application",
    },
    "ServicePrincipalEndpoint.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "89c8469c-83ad-45f7-8ff2-6e3d4285709e",
        "origin": "Application",
    },
    "AuditLogsQuery-Exchange.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "6b0d2622-d34e-4470-935b-b96550e5ca8d",
        "origin": "Application",
    },
    "InformationProtectionContent.Sign.All": {
        "allowedMemberTypes": ["Application"],
        "id": "cbe6c7e4-09aa-4b8d-b3c3-2dbb59af4b54",
        "origin": "Application",
    },
    "TeamsAppInstallation.ReadForTeam.All": {
        "allowedMemberTypes": ["Application"],
        "id": "1f615aea-6bf9-4b05-84bd-46388e138537",
        "origin": "Application",
    },
    "Presence.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "83cded22-8297-4ff6-a7fa-e97e9545a259",
        "origin": "Application",
    },
    "Policy.ReadWrite.Authorization": {
        "allowedMemberTypes": ["Application"],
        "id": "fb221be6-99f2-473f-bd32-01c6a0e9ca3b",
        "origin": "Application",
    },
    "SpiffeTrustDomain.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "dcdfc277-41fd-4d68-ad0c-c3057235bd8e",
        "origin": "Application",
    },
    "CustomDetection.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "673a007a-9e0f-4c97-b066-3c0164486909",
        "origin": "Application",
    },
    "TeamsActivity.Send": {
        "allowedMemberTypes": ["Application"],
        "id": "a267235f-af13-44dc-8385-c1dc93023186",
        "origin": "Application",
    },
    "SearchConfiguration.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "0e778b85-fefa-466d-9eec-750569d92122",
        "origin": "Application",
    },
    "CrossTenantUserProfileSharing.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "8b919d44-6192-4f3d-8a3b-f86f8069ae3c",
        "origin": "Application",
    },
    "Policy.ReadWrite.IdentityProtection": {
        "allowedMemberTypes": ["Application"],
        "id": "2dcf8603-09eb-4078-b1ec-d30a1a76b873",
        "origin": "Application",
    },
    "IndustryData-OutboundFlow.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "61d0354c-5d88-483c-b974-a37ec3395a2c",
        "origin": "Application",
    },
    "Bookings.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "6e98f277-b046-4193-a4f2-6bf6a78cd491",
        "origin": "Application",
    },
    "ChannelSettings.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "c97b873f-f59f-49aa-8a0e-52b32d762124",
        "origin": "Application",
    },
    "ServiceActivity-Teams.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "4dfee10b-fa4a-41b5-b34d-ccf54cc0c394",
        "origin": "Application",
    },
    "TeamworkTag.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "b74fd6c4-4bde-488e-9695-eeb100e4907f",
        "origin": "Application",
    },
    "BackupRestore-Configuration.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "5fbb5982-3230-4882-93c0-2167523ce0c2",
        "origin": "Application",
    },
    "OnlineMeetingRecording.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "a4a08342-c95d-476b-b943-97e100569c8d",
        "origin": "Application",
    },
    "ChatMember.ReadWrite.WhereInstalled": {
        "allowedMemberTypes": ["Application"],
        "id": "e32c2cd9-0124-4e44-88fc-772cd98afbdb",
        "origin": "Application",
    },
    "AppCatalog.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "e12dae10-5a57-4817-b79d-dfbec5348930",
        "origin": "Application",
    },
    "EduCurricula.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "6cdb464c-3a03-40f8-900b-4cb7ea1da9c0",
        "origin": "Application",
    },
    "ConsentRequest.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "9f1b81a7-0223-4428-bfa4-0bcb5535f27d",
        "origin": "Application",
    },
    "Mail.ReadBasic": {
        "allowedMemberTypes": ["Application"],
        "id": "6be147d2-ea4f-4b5a-a3fa-3eab6f3c140a",
        "origin": "Application",
    },
    "CallEvents.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "1abb026f-7572-49f6-9ddd-ad61cbba181e",
        "origin": "Application",
    },
    "APIConnectors.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "b86848a7-d5b1-41eb-a9b4-54a4e6306e97",
        "origin": "Application",
    },
    "AuthenticationContext.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "381f742f-e1f8-4309-b4ab-e3d91ae4c5c1",
        "origin": "Application",
    },
    "CustomSecAttributeDefinition.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "b185aa14-d8d2-42c1-a685-0f5596613624",
        "origin": "Application",
    },
    "CustomTags.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "2f503208-e509-4e39-974c-8cc16e5785c9",
        "origin": "Application",
    },
    "MultiTenantOrganization.ReadBasic.All": {
        "allowedMemberTypes": ["Application"],
        "id": "f9c2b2a7-3895-4b2e-80f6-c924b456e50b",
        "origin": "Application",
    },
    "Policy.ReadWrite.AuthenticationMethod": {
        "allowedMemberTypes": ["Application"],
        "id": "29c18626-4985-4dcd-85c0-193eef327366",
        "origin": "Application",
    },
    "DelegatedAdminRelationship.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "cc13eba4-8cd8-44c6-b4d4-f93237adce58",
        "origin": "Application",
    },
    "MultiTenantOrganization.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "920def01-ca61-4d2d-b3df-105b46046a70",
        "origin": "Application",
    },
    "Policy.ReadWrite.ApplicationConfiguration": {
        "allowedMemberTypes": ["Application"],
        "id": "be74164b-cff1-491c-8741-e671cb536e13",
        "origin": "Application",
    },
    "Chat.ManageDeletion.All": {
        "allowedMemberTypes": ["Application"],
        "id": "9c7abde0-eacd-4319-bf9e-35994b1a1717",
        "origin": "Application",
    },
    "Schedule.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "7b2ebf90-d836-437f-b90d-7b62722c4456",
        "origin": "Application",
    },
    "ChannelMember.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "35930dcf-aceb-4bd1-b99a-8ffed403c974",
        "origin": "Application",
    },
    "TeamTemplates.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "6323133e-1f6e-46d4-9372-ac33a0870636",
        "origin": "Application",
    },
    "Chat.ReadBasic.WhereInstalled": {
        "allowedMemberTypes": ["Application"],
        "id": "818ba5bd-5b3e-4fe0-bbe6-aa4686669073",
        "origin": "Application",
    },
    "InformationProtectionPolicy.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "19da66cb-0fb0-4390-b071-ebc76a349482",
        "origin": "Application",
    },
    "SecurityIdentitiesSensors.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "d4dcee6d-0774-412a-b06c-aeabbd99e816",
        "origin": "Application",
    },
    "PrivilegedAccess.Read.AzureADGroup": {
        "allowedMemberTypes": ["Application"],
        "id": "01e37dc9-c035-40bd-b438-b2879c4870a6",
        "origin": "Application",
    },
    "RoleAssignmentSchedule.ReadWrite.Directory": {
        "allowedMemberTypes": ["Application"],
        "id": "dd199f4a-f148-40a4-a2ec-f0069cc799ec",
        "origin": "Application",
    },
    "PublicKeyInfrastructure.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "214fda0c-514a-4650-b037-b562b1a66124",
        "origin": "Application",
    },
    "TeamsAppInstallation.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "0fdf35a5-82f8-41ff-9ded-0b761cc73512",
        "origin": "Application",
    },
    "EduReports-Reflect.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "c5debf73-bdc8-473d-bf07-f4074ad05f71",
        "origin": "Application",
    },
    "NetworkAccessBranch.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "39ae4a24-1ef0-49e8-9d63-2a66f5c39edd",
        "origin": "Application",
    },
    "TeamsTab.ReadWriteSelfForChat.All": {
        "allowedMemberTypes": ["Application"],
        "id": "9f62e4a2-a2d6-4350-b28b-d244728c4f86",
        "origin": "Application",
    },
    "DeviceManagementRBAC.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "58ca0d9a-1575-47e1-a3cb-007ef2e4583b",
        "origin": "Application",
    },
    "ChannelMessage.UpdatePolicyViolation.All": {
        "allowedMemberTypes": ["Application"],
        "id": "4d02b0cc-d90b-441f-8d82-4fb55c34d6bb",
        "origin": "Application",
    },
    "IndustryData-DataConnector.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "7ab52c2f-a2ee-4d98-9ebc-725e3934aae2",
        "origin": "Application",
    },
    "Policy.ReadWrite.SecurityDefaults": {
        "allowedMemberTypes": ["Application"],
        "id": "1c6e93a6-28e2-4cbb-9f64-1a46a821124d",
        "origin": "Application",
    },
    "Teamwork.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "75bcfbce-a647-4fba-ad51-b63d73b210f4",
        "origin": "Application",
    },
    "OrgSettings-Todo.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "e4d9cd09-d858-4363-9410-abb96737f0cf",
        "origin": "Application",
    },
    "ShortNotes.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "0c7d31ec-31ca-4f58-b6ec-9950b6b0de69",
        "origin": "Application",
    },
    "Policy.ReadWrite.ConditionalAccess": {
        "allowedMemberTypes": ["Application"],
        "id": "01c0a623-fc9b-48e9-b794-0756f8e8f067",
        "origin": "Application",
    },
    "CrossTenantUserProfileSharing.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "306785c5-c09b-4ba0-a4ee-023f3da165cb",
        "origin": "Application",
    },
    "OnlineMeetingTranscript.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "a4a80d8d-d283-4bd8-8504-555ec3870630",
        "origin": "Application",
    },
    "ThreatSubmissionPolicy.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "926a6798-b100-4a20-a22f-a4918f13951d",
        "origin": "Application",
    },
    "RoleManagement.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "c7fbd983-d9aa-4fa7-84b8-17382c103bc4",
        "origin": "Application",
    },
    "EduReports-Reading.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "ad248c30-1919-40c8-b3d2-304481894e88",
        "origin": "Application",
    },
    "Agreement.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "c9090d00-6101-42f0-a729-c41074260d47",
        "origin": "Application",
    },
    "VirtualAppointment.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "d4f67ec2-59b5-4bdc-b4af-d78f6f9c1954",
        "origin": "Application",
    },
    "VirtualAppointmentNotification.Send": {
        "allowedMemberTypes": ["Application"],
        "id": "97e45b36-1250-48e4-bd70-2df6dab7e94a",
        "origin": "Application",
    },
    "SubjectRightsRequest.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "8387eaa4-1a3c-41f5-b261-f888138e6041",
        "origin": "Application",
    },
    "Community.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "35d59e32-eab5-4553-9345-abb62b4c703c",
        "origin": "Application",
    },
    "Chat.ReadWrite.WhereInstalled": {
        "allowedMemberTypes": ["Application"],
        "id": "ad73ce80-f3cd-40ce-b325-df12c33df713",
        "origin": "Application",
    },
    "DirectoryRecommendations.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "0e9eea12-4f01-45f6-9b8d-3ea4c8144158",
        "origin": "Application",
    },
    "TeamsUserConfiguration.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "a91eadaf-2c3c-4362-908b-fb172d208fc6",
        "origin": "Application",
    },
    "IdentityRiskyServicePrincipal.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "cb8d6980-6bcb-4507-afec-ed6de3a2d798",
        "origin": "Application",
    },
    "Calls.Initiate.All": {
        "allowedMemberTypes": ["Application"],
        "id": "284383ee-7f6e-4e40-a2a8-e85dcb029101",
        "origin": "Application",
    },
    "Policy.ReadWrite.TrustFramework": {
        "allowedMemberTypes": ["Application"],
        "id": "79a677f7-b79d-40d0-a36a-3e6f8688dd7a",
        "origin": "Application",
    },
    "InformationProtectionConfig.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "14f49b9f-4bf2-4d24-b80e-b27ec58409bd",
        "origin": "Application",
    },
    "LearningAssignedCourse.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "236c1cbd-1187-427f-b0f5-b1852454973b",
        "origin": "Application",
    },
    "EduAdministration.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "9bc431c3-b8bc-4a8d-a219-40f10f92eff6",
        "origin": "Application",
    },
    "Schedule.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "b7760610-0545-4e8a-9ec3-cce9e63db01c",
        "origin": "Application",
    },
    "User.EnableDisableAccount.All": {
        "allowedMemberTypes": ["Application"],
        "id": "3011c876-62b7-4ada-afa2-506cbbecc68c",
        "origin": "Application",
    },
    "EduRoster.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "e0ac9e1b-cb65-4fc5-87c5-1a8bc181f648",
        "origin": "Application",
    },
    "Team.Create": {
        "allowedMemberTypes": ["Application"],
        "id": "23fc2474-f741-46ce-8465-674744c5c361",
        "origin": "Application",
    },
    "TeamSettings.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "bdd80a03-d9bc-451d-b7c4-ce7c63fe3c8f",
        "origin": "Application",
    },
    "NetworkAccessPolicy.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "8a3d36bf-cb46-4bcc-bec9-8d92829dab84",
        "origin": "Application",
    },
    "TeamsAppInstallation.ReadForUser.All": {
        "allowedMemberTypes": ["Application"],
        "id": "9ce09611-f4f7-4abd-a629-a05450422a97",
        "origin": "Application",
    },
    "QnA.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "ee49e170-1dd1-4030-b44c-61ad6e98f743",
        "origin": "Application",
    },
    "IndustryData-DataConnector.Upload": {
        "allowedMemberTypes": ["Application"],
        "id": "9334c44b-a7c6-4350-8036-6bf8e02b4c1f",
        "origin": "Application",
    },
    "RoleManagementAlert.ReadWrite.Directory": {
        "allowedMemberTypes": ["Application"],
        "id": "11059518-d6a6-4851-98ed-509268489c4a",
        "origin": "Application",
    },
    "ExternalConnection.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "34c37bc0-2b40-4d5e-85e1-2365cd256d79",
        "origin": "Application",
    },
    "TeamsAppInstallation.ReadWriteAndConsentSelfForTeam.All": {
        "allowedMemberTypes": ["Application"],
        "id": "1e4be56c-312e-42b8-a2c9-009600d732c0",
        "origin": "Application",
    },
    "IndustryData-DataConnector.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "eda0971c-482e-4345-b28f-69c309cb8a34",
        "origin": "Application",
    },
    #"Application.ReadWrite.All": {
    #    "allowedMemberTypes": ["Application"],
    #    "id": "1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9",
    #    "origin": "Application",
    #},
    "Sites.Selected": {
        "allowedMemberTypes": ["Application"],
        "id": "883ea226-0bf2-4a8f-9f9d-92c9162a727d",
        "origin": "Application",
    },
    "OrgSettings-Forms.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "434d7c66-07c6-4b1f-ab21-417cf2cdaaca",
        "origin": "Application",
    },
    "CustomTags.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "ab8a5872-7c88-47a6-8141-7becce939190",
        "origin": "Application",
    },
    "User.ManageIdentities.All": {
        "allowedMemberTypes": ["Application"],
        "id": "c529cfca-c91b-489c-af2b-d92990b66ce6",
        "origin": "Application",
    },
    "UserNotification.ReadWrite.CreatedByApp": {
        "allowedMemberTypes": ["Application"],
        "id": "4e774092-a092-48d1-90bd-baad67c7eb47",
        "origin": "Application",
    },
    "TeamsTab.Create": {
        "allowedMemberTypes": ["Application"],
        "id": "49981c42-fd7b-4530-be03-e77b21aed25e",
        "origin": "Application",
    },
    "ChatMessage.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "b9bb2381-47a4-46cd-aafb-00cb12f68504",
        "origin": "Application",
    },
    "PrintJob.Manage.All": {
        "allowedMemberTypes": ["Application"],
        "id": "58a52f47-9e36-4b17-9ebe-ce4ef7f3e6c8",
        "origin": "Application",
    },
    "OnlineMeetings.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "b8bb2037-6e08-44ac-a4ea-4674e010e2a4",
        "origin": "Application",
    },
    "DeviceManagementApps.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "78145de6-330d-4800-a6ce-494ff2d33d07",
        "origin": "Application",
    },
    "EntitlementManagement.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "c74fd47d-ed3c-45c3-9a9e-b8676de685d2",
        "origin": "Application",
    },
    "LearningContent.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "8740813e-d8aa-4204-860e-2a0f8f84dbc8",
        "origin": "Application",
    },
    "CustomAuthenticationExtension.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "c2667967-7050-4e7e-b059-4cbbb3811d03",
        "origin": "Application",
    },
    "PublicKeyInfrastructure.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "a2b63618-5350-462d-b1b3-ba6eb3684e26",
        "origin": "Application",
    },
    "DeviceManagementManagedDevices.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "2f51be20-0bb4-4fed-bf7b-db946066c75e",
        "origin": "Application",
    },
    "PlaceDevice.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "8b724a84-ceac-4fd9-897e-e31ba8f2d7a3",
        "origin": "Application",
    },
    "Policy.ReadWrite.FeatureRollout": {
        "allowedMemberTypes": ["Application"],
        "id": "2044e4f1-e56c-435b-925c-44cd8f6ba89a",
        "origin": "Application",
    },
    "GroupMember.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "dbaae8cf-10b5-4b86-a4a1-f871c94c6695",
        "origin": "Application",
    },
    "AccessReview.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "ef5f7d5c-338f-44b0-86c3-351f46c8bb5f",
        "origin": "Application",
    },
    "Tasks.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "44e666d1-d276-445b-a5fc-8815eeb81d55",
        "origin": "Application",
    },
    "SecurityAlert.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "472e4a4d-bb4a-4026-98d1-0b0d74cb74a5",
        "origin": "Application",
    },
    "APIConnectors.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "1dfe531a-24a6-4f1b-80f4-7a0dc5a0a171",
        "origin": "Application",
    },
    "ChatMember.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "57257249-34ce-4810-a8a2-a03adf0c5693",
        "origin": "Application",
    },
    "Calls.JoinGroupCall.All": {
        "allowedMemberTypes": ["Application"],
        "id": "f6b49018-60ab-4f81-83bd-22caeabfed2d",
        "origin": "Application",
    },
    "Organization.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "498476ce-e0fe-48b0-b801-37ba7e2685c6",
        "origin": "Application",
    },
    "TeamworkDevice.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "0591bafd-7c1c-4c30-a2a5-2b9aacb1dfe8",
        "origin": "Application",
    },
    "Chat.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "294ce7c9-31ba-490a-ad7d-97a7d075e4ed",
        "origin": "Application",
    },
    "CustomSecAttributeDefinition.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "12338004-21f4-4896-bf5e-b75dfaf1016d",
        "origin": "Application",
    },
    "RoleManagement.ReadWrite.Exchange": {
        "allowedMemberTypes": ["Application"],
        "id": "025d3225-3f02-4882-b4c0-cd5b541a4e80",
        "origin": "Application",
    },
    "SecurityAnalyzedMessage.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "b48f7ac2-044d-4281-b02f-75db744d6f5f",
        "origin": "Application",
    },
    "IndustryData-TimePeriod.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "7afa7744-a782-4a32-b8c2-e3db637e8de7",
        "origin": "Application",
    },
    "LifecycleWorkflows.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "5c505cf4-8424-4b8e-aa14-ee06e3bb23e3",
        "origin": "Application",
    },
    "CustomSecAttributeAssignment.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "de89b5e4-5b8f-48eb-8925-29c2b33bd8bd",
        "origin": "Application",
    },
    "BillingConfiguration.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "9e8be751-7eee-4c09-bcfd-d64f6b087fd8",
        "origin": "Application",
    },
    "Notes.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "0c458cef-11f3-48c2-a568-c66751c238c0",
        "origin": "Application",
    },
    "TeamsAppInstallation.ReadWriteForChat.All": {
        "allowedMemberTypes": ["Application"],
        "id": "9e19bae1-2623-4c4f-ab6e-2664615ff9a0",
        "origin": "Application",
    },
    "Application-RemoteDesktopConfig.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "3be0012a-cc4e-426b-895b-f9c836bf6381",
        "origin": "Application",
    },
    "User.Invite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "09850681-111b-4a89-9bed-3f2cae46d706",
        "origin": "Application",
    },
    "BrowserSiteLists.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "c5ee1f21-fc7f-4937-9af0-c91648ff9597",
        "origin": "Application",
    },
    "AuditLogsQuery-SharePoint.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "91c64a47-a524-4fce-9bf3-3d569a344ecf",
        "origin": "Application",
    },
    "TeamsTab.ReadWriteSelfForTeam.All": {
        "allowedMemberTypes": ["Application"],
        "id": "91c32b81-0ef0-453f-a5c7-4ce2e562f449",
        "origin": "Application",
    },
    "ExternalConnection.ReadWrite.OwnedBy": {
        "allowedMemberTypes": ["Application"],
        "id": "f431331c-49a6-499f-be1c-62af19c34a9d",
        "origin": "Application",
    },
    "DeviceLocalCredential.ReadBasic.All": {
        "allowedMemberTypes": ["Application"],
        "id": "db51be59-e728-414b-b800-e0f010df1a79",
        "origin": "Application",
    },
    "BusinessScenarioConfig.ReadWrite.OwnedBy": {
        "allowedMemberTypes": ["Application"],
        "id": "bbea195a-4c47-4a4f-bff2-cba399e11698",
        "origin": "Application",
    },
    "Calls.AccessMedia.All": {
        "allowedMemberTypes": ["Application"],
        "id": "a7a681dc-756e-4909-b988-f160edc6655f",
        "origin": "Application",
    },
    "SubjectRightsRequest.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "ee1460f0-368b-4153-870a-4e1ca7e72c42",
        "origin": "Application",
    },
    "MailboxSettings.ReadWrite": {
        "allowedMemberTypes": ["Application"],
        "id": "6931bccd-447a-43d1-b442-00a195474933",
        "origin": "Application",
    },
    "ExternalConnection.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "1914711b-a1cb-4793-b019-c2ce0ed21b8c",
        "origin": "Application",
    },
    "EventListener.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "b7f6385c-6ce6-4639-a480-e23c42ed9784",
        "origin": "Application",
    },
    "AuditLogsQuery.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "5e1e9171-754d-478c-812c-f1755a9a4c2d",
        "origin": "Application",
    },
    "IndustryData-SourceSystem.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "bc167a60-39fe-4865-8b44-78400fc6ed03",
        "origin": "Application",
    },
    "PlaceDeviceTelemetry.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "27fc435f-44e2-4b30-bf3c-e0ce74aed618",
        "origin": "Application",
    },
    "OrgSettings-AppsAndServices.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "56c84fa9-ea1f-4a15-90f2-90ef41ece2c9",
        "origin": "Application",
    },
    "PlaceDevice.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "2d510721-5c4e-43cd-bfdb-ac0f8819fb92",
        "origin": "Application",
    },
    "IdentityRiskyUser.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "656f6061-f9fe-4807-9708-6a2e0934df76",
        "origin": "Application",
    },
    "ReportSettings.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "ee353f83-55ef-4b78-82da-555bfa2b4b95",
        "origin": "Application",
    },
    "Insights-UserMetric.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "34cbd96c-d824-4755-90d3-1008ef47efc1",
        "origin": "Application",
    },
    "EduAssignments.ReadWriteBasic.All": {
        "allowedMemberTypes": ["Application"],
        "id": "f431cc63-a2de-48c4-8054-a34bc093af84",
        "origin": "Application",
    },
    "Bookmark.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "be95e614-8ef3-49eb-8464-1c9503433b86",
        "origin": "Application",
    },
    "Policy.ReadWrite.AuthenticationFlows": {
        "allowedMemberTypes": ["Application"],
        "id": "25f85f3c-f66c-4205-8cd5-de92dd7f0cec",
        "origin": "Application",
    },
    "TeamMember.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "0121dc95-1b9f-4aed-8bac-58c5ac466691",
        "origin": "Application",
    },
    "ChatMember.Read.WhereInstalled": {
        "allowedMemberTypes": ["Application"],
        "id": "93e7c9e4-54c5-4a41-b796-f2a5adaacda7",
        "origin": "Application",
    },
    "OrgSettings-Todo.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "5febc9da-e0d0-4576-bd13-ae70b2179a39",
        "origin": "Application",
    },
    "TeamSettings.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "242607bd-1d2c-432c-82eb-bdb27baa23ab",
        "origin": "Application",
    },
    "VirtualEvent.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "1dccb351-c4e4-4e09-a8d1-7a9ecbf027cc",
        "origin": "Application",
    },
    "TrustFrameworkKeySet.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "4a771c9a-1cf2-4609-b88e-3d3e02d539cd",
        "origin": "Application",
    },
    "NetworkAccess-Reports.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "40049381-3cc1-42af-94ec-5ce755db4b0d",
        "origin": "Application",
    },
    "MultiTenantOrganization.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "4f994bc0-31bb-44bb-b480-7a7c1be8c02e",
        "origin": "Application",
    },
    "Channel.ReadBasic.All": {
        "allowedMemberTypes": ["Application"],
        "id": "59a6b24b-4225-4393-8165-ebaec5f55d7a",
        "origin": "Application",
    },
    "TeamsActivity.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "70dec828-f620-4914-aa83-a29117306807",
        "origin": "Application",
    },
    "TeamsTab.ReadWriteSelfForUser.All": {
        "allowedMemberTypes": ["Application"],
        "id": "3c42dec6-49e8-4a0a-b469-36cff0d9da93",
        "origin": "Application",
    },
    "EduAssignments.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "0d22204b-6cad-4dd0-8362-3e3f2ae699d9",
        "origin": "Application",
    },
    "Calls.InitiateGroupCall.All": {
        "allowedMemberTypes": ["Application"],
        "id": "4c277553-8a09-487b-8023-29ee378d8324",
        "origin": "Application",
    },
    "IndustryData-OutboundFlow.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "24a65b4a-e501-47e2-8849-d679517887f0",
        "origin": "Application",
    },
    "BackupRestore-Monitor.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "ecae8511-f2d7-4be4-bdbf-91f244d45986",
        "origin": "Application",
    },
    "SecurityEvents.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "bf394140-e372-4bf9-a898-299cfc7564e5",
        "origin": "Application",
    },
    "BackupRestore-Search.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "f6135c51-c766-4be1-9638-ed90c2ed2443",
        "origin": "Application",
    },
    "Group.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "62a82d76-70ea-41e2-9197-370581804d09",
        "origin": "Application",
    },
    "RoleManagement.Read.Directory": {
        "allowedMemberTypes": ["Application"],
        "id": "483bed4a-2ad3-4361-a73b-c83ccdbdc53c",
        "origin": "Application",
    },
    "OrgSettings-DynamicsVoice.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "c3f1cc32-8bbd-4ab6-bd33-f270e0d9e041",
        "origin": "Application",
    },
    "PrivilegedAccess.Read.AzureResources": {
        "allowedMemberTypes": ["Application"],
        "id": "5df6fe86-1be0-44eb-b916-7bd443a71236",
        "origin": "Application",
    },
    "TeamsAppInstallation.ReadWriteAndConsentSelfForUser.All": {
        "allowedMemberTypes": ["Application"],
        "id": "a87076cf-6abd-4e56-8559-4dbdf41bef96",
        "origin": "Application",
    },
    "NetworkAccess.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "b10642fc-a6cf-4c46-87f9-e1f96c2a18aa",
        "origin": "Application",
    },
    "ThreatIndicators.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "197ee4e9-b993-4066-898f-d6aecc55125b",
        "origin": "Application",
    },
    "SecurityActions.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "f2bf083f-0179-402a-bedb-b2784de8a49b",
        "origin": "Application",
    },
    "RoleAssignmentSchedule.Read.Directory": {
        "allowedMemberTypes": ["Application"],
        "id": "d5fe8ce8-684c-4c83-a52c-46e882ce4be1",
        "origin": "Application",
    },
    "SharePointTenantSettings.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "83d4163d-a2d8-4d3b-9695-4ae3ca98f888",
        "origin": "Application",
    },
    "Group.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "5b567255-7703-4780-807c-7be8301ae99b",
        "origin": "Application",
    },
    "LicenseAssignment.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "5facf0c1-8979-4e95-abcf-ff3d079771c0",
        "origin": "Application",
    },
    "User-LifeCycleInfo.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "925f1248-0f97-47b9-8ec8-538c54e01325",
        "origin": "Application",
    },
    "NetworkAccessPolicy.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "f0c341be-8348-4989-8e43-660324294538",
        "origin": "Application",
    },
    "TeamsAppInstallation.ReadWriteSelfForChat.All": {
        "allowedMemberTypes": ["Application"],
        "id": "73a45059-f39c-4baf-9182-4954ac0e55cf",
        "origin": "Application",
    },
    "TeamsAppInstallation.ReadWriteAndConsentForUser.All": {
        "allowedMemberTypes": ["Application"],
        "id": "32ca478f-f89e-41d0-aaf8-101deb7da510",
        "origin": "Application",
    },
    "Policy.ReadWrite.ConsentRequest": {
        "allowedMemberTypes": ["Application"],
        "id": "999f8c63-0a38-4f1b-91fd-ed1947bdd1a9",
        "origin": "Application",
    },
    "Domain.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "dbb9058a-0e50-45d7-ae91-66909b5d4664",
        "origin": "Application",
    },
    "Reports.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "230c1aed-a721-4c5d-9cb4-a90514e508ef",
        "origin": "Application",
    },
    "Policy.ReadWrite.PermissionGrant": {
        "allowedMemberTypes": ["Application"],
        "id": "a402ca1c-2696-4531-972d-6e5ee4aa11ea",
        "origin": "Application",
    },
    "PrivilegedAccess.ReadWrite.AzureADGroup": {
        "allowedMemberTypes": ["Application"],
        "id": "2f6817f8-7b12-4f0f-bc18-eeaf60705a9e",
        "origin": "Application",
    },
    "PrintTaskDefinition.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "456b71a7-0ee0-4588-9842-c123fcc8f664",
        "origin": "Application",
    },
    "TeamsAppInstallation.ReadWriteAndConsentForTeam.All": {
        "allowedMemberTypes": ["Application"],
        "id": "b0c13be0-8e20-4bc5-8c55-963c23a39ce9",
        "origin": "Application",
    },
    "LearningSelfInitiatedCourse.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "7654ed61-8965-4025-846a-0856ec02b5b0",
        "origin": "Application",
    },
    "OrgSettings-Forms.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "2cb92fee-97a3-4034-8702-24a6f5d0d1e9",
        "origin": "Application",
    },
    "SecurityIncident.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "45cc0394-e837-488b-a098-1918f48d186c",
        "origin": "Application",
    },
    "Group.Create": {
        "allowedMemberTypes": ["Application"],
        "id": "bf7b1a76-6e77-406b-b258-bf5c7720e98f",
        "origin": "Application",
    },
    "WorkforceIntegration.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "202bf709-e8e6-478e-bcfd-5d63c50b68e3",
        "origin": "Application",
    },
    "Mail.ReadBasic.All": {
        "allowedMemberTypes": ["Application"],
        "id": "693c5e45-0940-467d-9b8a-1022fb9d42ef",
        "origin": "Application",
    },
    "ProgramControl.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "60a901ed-09f7-4aa5-a16e-7dd3d6f9de36",
        "origin": "Application",
    },
    "Calendars.Read": {
        "allowedMemberTypes": ["Application"],
        "id": "798ee544-9d2d-430c-a058-570e29e34338",
        "origin": "Application",
    },
    "TeamsTab.ReadWriteForChat.All": {
        "allowedMemberTypes": ["Application"],
        "id": "fd9ce730-a250-40dc-bd44-8dc8d20f39ea",
        "origin": "Application",
    },
    "PrintSettings.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "b5991872-94cf-4652-9765-29535087c6d8",
        "origin": "Application",
    },
    "Agreement.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "2f3e6f8c-093b-4c57-a58b-ba5ce494a169",
        "origin": "Application",
    },
    "NetworkAccessBranch.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "8137102d-ec16-4191-aaf8-7aeda8026183",
        "origin": "Application",
    },
    "ThreatIntelligence.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "e0b77adb-e790-44a3-b0a0-257d06303687",
        "origin": "Application",
    },
    "AccessReview.ReadWrite.Membership": {
        "allowedMemberTypes": ["Application"],
        "id": "18228521-a591-40f1-b215-5fad4488c117",
        "origin": "Application",
    },
    "Domain.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "7e05723c-0bb0-42da-be95-ae9f08a6e53c",
        "origin": "Application",
    },
    "EduReports-Reflect.ReadAnonymous.All": {
        "allowedMemberTypes": ["Application"],
        "id": "f5d05dba-7ef0-46fc-b62c-a7282555f428",
        "origin": "Application",
    },
    "BookingsAppointment.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "9769393e-5a9f-4302-9e3d-7e018ecb64a7",
        "origin": "Application",
    },
    "RoleEligibilitySchedule.ReadWrite.Directory": {
        "allowedMemberTypes": ["Application"],
        "id": "fee28b28-e1f3-4841-818e-2704dc62245f",
        "origin": "Application",
    },
    "User.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "741f803b-c850-494e-b5df-cde7c675a1ca",
        "origin": "Application",
    },
    "TermStore.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "f12eb8d6-28e3-46e6-b2c0-b7e4dc69fc95",
        "origin": "Application",
    },
    "DelegatedAdminRelationship.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "f6e9e124-4586-492f-adc0-c6f96e4823fd",
        "origin": "Application",
    },
    "eDiscovery.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "50180013-6191-4d1e-a373-e590ff4e66af",
        "origin": "Application",
    },
    "TeamsAppInstallation.ReadForChat.All": {
        "allowedMemberTypes": ["Application"],
        "id": "cc7e7635-2586-41d6-adaa-a8d3bcad5ee5",
        "origin": "Application",
    },
    "TeamsAppInstallation.ReadWriteAndConsentSelfForChat.All": {
        "allowedMemberTypes": ["Application"],
        "id": "ba1ba90b-2d8f-487e-9f16-80728d85bb5c",
        "origin": "Application",
    },
    "SecurityAnalyzedMessage.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "04c55753-2244-4c25-87fc-704ab82a4f69",
        "origin": "Application",
    },
    "BackupRestore-Configuration.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "18133149-5489-40ac-80f0-4b6fa85f6cdc",
        "origin": "Application",
    },
    "Acronym.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "8c0aed2c-0c61-433d-b63c-6370ddc73248",
        "origin": "Application",
    },
    "IdentityRiskyUser.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "dc5007c0-2d7d-4c42-879c-2dab87571379",
        "origin": "Application",
    },
    "ExternalItem.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "38c3d6ee-69ee-422f-b954-e17819665354",
        "origin": "Application",
    },
    "Synchronization.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "5ba43d2f-fa88-4db2-bd1c-a67c5f0fb1ce",
        "origin": "Application",
    },
    "NetworkAccess.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "e30060de-caa5-4331-99d3-6ac6c966a9a4",
        "origin": "Application",
    },
    "Contacts.ReadWrite": {
        "allowedMemberTypes": ["Application"],
        "id": "6918b873-d17a-4dc1-b314-35f528134491",
        "origin": "Application",
    },
    "ThreatIndicators.ReadWrite.OwnedBy": {
        "allowedMemberTypes": ["Application"],
        "id": "21792b6c-c986-4ffc-85de-df9da54b52fa",
        "origin": "Application",
    },
    "Device.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "1138cb37-bd11-4084-a2b7-9f71582aeddb",
        "origin": "Application",
    },
    "TeamMember.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "660b7406-55f1-41ca-a0ed-0b035e182f3e",
        "origin": "Application",
    },
    "Calls.JoinGroupCallAsGuest.All": {
        "allowedMemberTypes": ["Application"],
        "id": "fd7ccf6b-3d28-418b-9701-cd10f5cd2fd4",
        "origin": "Application",
    },
    "IdentityUserFlow.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "65319a09-a2be-469d-8782-f6b07debf789",
        "origin": "Application",
    },
    "ServiceActivity-OneDrive.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "57b4f899-b8c5-47c7-bdd3-c410c55602b7",
        "origin": "Application",
    },
    "CustomAuthenticationExtension.Receive.Payload": {
        "allowedMemberTypes": ["Application"],
        "id": "214e810f-fda8-4fd7-a475-29461495eb00",
        "origin": "Application",
    },
    "IndustryData.ReadBasic.All": {
        "allowedMemberTypes": ["Application"],
        "id": "4f5ac95f-62fd-472c-b60f-125d24ca0bc5",
        "origin": "Application",
    },
    "Tasks.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "f10e1f91-74ed-437f-a6fd-d6ae88e26c1f",
        "origin": "Application",
    },
    "EduCurricula.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "6a0c2318-d59d-4c7d-bf2e-5f3902dc2593",
        "origin": "Application",
    },
    "UserShiftPreferences.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "d1eec298-80f3-49b0-9efb-d90e224798ac",
        "origin": "Application",
    },
    "AttackSimulation.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "e125258e-8c8a-42a8-8f55-ab502afa52f3",
        "origin": "Application",
    },
    "ThreatSubmission.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "86632667-cd15-4845-ad89-48a88e8412e1",
        "origin": "Application",
    },
    "SecurityActions.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "5e0edab9-c148-49d0-b423-ac253e121825",
        "origin": "Application",
    },
    "IndustryData-Run.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "f6f5d10b-3024-4d1d-b674-aae4df4a1a73",
        "origin": "Application",
    },
    "TeamsAppInstallation.ReadWriteAndConsentForChat.All": {
        "allowedMemberTypes": ["Application"],
        "id": "6e74eff9-4a21-45d6-bc03-3a20f61f8281",
        "origin": "Application",
    },
    "AuditLogsQuery-OneDrive.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "8a169a81-841c-45fd-ad43-96aede8801a0",
        "origin": "Application",
    },
    "PendingExternalUserProfile.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "8363c2b8-6ff7-420b-9966-c5884c2d48bc",
        "origin": "Application",
    },
    "RoleManagement.ReadWrite.CloudPC": {
        "allowedMemberTypes": ["Application"],
        "id": "274d0592-d1b6-44bd-af1d-26d259bcb43a",
        "origin": "Application",
    },
    "EduRoster.ReadBasic.All": {
        "allowedMemberTypes": ["Application"],
        "id": "0d412a8c-a06c-439f-b3ec-8abcf54d2f96",
        "origin": "Application",
    },
    "CloudApp-Discovery.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "64a59178-dad3-4673-89db-84fdcd622fec",
        "origin": "Application",
    },
    "HealthMonitoringAlert.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "ac29eb50-f2f9-4518-a117-4bef18e84c7d",
        "origin": "Application",
    },
    "EduReports-Reading.ReadAnonymous.All": {
        "allowedMemberTypes": ["Application"],
        "id": "040330d7-be7e-4130-b349-a6eb3a56e2f8",
        "origin": "Application",
    },
    "Sites.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "9492366f-7969-46a4-8d15-ed1a20078fff",
        "origin": "Application",
    },
    "DeviceLocalCredential.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "884b599e-4d48-43a5-ba94-15c414d00588",
        "origin": "Application",
    },
    "RecordsManagement.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "eb158f57-df43-4751-8b21-b8932adb3d34",
        "origin": "Application",
    },
    "Chat.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "6b7d71aa-70aa-4810-a8d9-5d9fb2830017",
        "origin": "Application",
    },
    "DeviceManagementRBAC.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "e330c4f0-4170-414e-a55a-2f022ec2b57b",
        "origin": "Application",
    },
    "Calendars.ReadWrite": {
        "allowedMemberTypes": ["Application"],
        "id": "ef54d2bf-783f-4e0f-bca1-3210c0444d99",
        "origin": "Application",
    },
    "PrivilegedEligibilitySchedule.Read.AzureADGroup": {
        "allowedMemberTypes": ["Application"],
        "id": "edb419d6-7edc-42a3-9345-509bfdf5d87c",
        "origin": "Application",
    },
    "ExternalUserProfile.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "761327c9-d819-4c08-9a5f-874cd2826608",
        "origin": "Application",
    },
    "ServiceActivity-Exchange.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "2b655018-450a-4845-81e7-d603b1ebffdb",
        "origin": "Application",
    },
    "IndustryData-TimePeriod.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "7c55c952-b095-4c23-a522-022bce4cc1e3",
        "origin": "Application",
    },
    "ExternalItem.ReadWrite.OwnedBy": {
        "allowedMemberTypes": ["Application"],
        "id": "8116ae0f-55c2-452d-9944-d18420f5b2c8",
        "origin": "Application",
    },
    "TermStore.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "ea047cc2-df29-4f3e-83a3-205de61501ca",
        "origin": "Application",
    },
    "Directory.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "7ab1d382-f21e-4acd-a863-ba3e13f7da61",
        "origin": "Application",
    },
    "Sites.FullControl.All": {
        "allowedMemberTypes": ["Application"],
        "id": "a82116e5-55eb-4c41-a434-62fe8a61c773",
        "origin": "Application",
    },
    "PartnerSecurity.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "21ffa320-2e7f-47d3-a466-7ff04d2dd68d",
        "origin": "Application",
    },
    "RoleEligibilitySchedule.Read.Directory": {
        "allowedMemberTypes": ["Application"],
        "id": "ff278e11-4a33-4d0c-83d2-d01dc58929a5",
        "origin": "Application",
    },
    "SecurityIdentitiesHealth.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "f8dcd971-5d83-4e1e-aa95-ef44611ad351",
        "origin": "Application",
    },
    "CloudPC.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "3b4349e1-8cf5-45a3-95b7-69d1751d3e6a",
        "origin": "Application",
    },
    #"AppRoleAssignment.ReadWrite.All": {
    #    "allowedMemberTypes": ["Application"],
    #    "id": "06b708a9-e830-4db3-a914-8e69da51d44f",
    #    "origin": "Application",
    #},
    "Contacts.Read": {
        "allowedMemberTypes": ["Application"],
        "id": "089fe4d0-434a-44c5-8827-41ba8a0b17f5",
        "origin": "Application",
    },
    "HealthMonitoringAlertConfig.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "bb424d73-e898-4c97-9d42-688c32810003",
        "origin": "Application",
    },
    "PeopleSettings.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "ef02f2e7-e22d-4c77-8614-8f765683b86e",
        "origin": "Application",
    },
    "AuditLogsQuery-Endpoint.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "0bc85aed-7b0b-437a-bac8-3b29a1b84c99",
        "origin": "Application",
    },
    "OrgSettings-AppsAndServices.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "4a8e4191-c1c8-45f8-b801-f9a1a5ee6ad3",
        "origin": "Application",
    },
    "Policy.ReadWrite.AccessReview": {
        "allowedMemberTypes": ["Application"],
        "id": "77c863fd-06c0-47ce-a7eb-49773e89d319",
        "origin": "Application",
    },
    "BrowserSiteLists.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "8349ca94-3061-44d5-9bfb-33774ea5e4f9",
        "origin": "Application",
    },
    "EduAssignments.ReadBasic.All": {
        "allowedMemberTypes": ["Application"],
        "id": "6e0a958b-b7fc-4348-b7c4-a6ab9fd3dd0e",
        "origin": "Application",
    },
    "Files.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "01d4889c-1287-42c6-ac1f-5d1e02578ef6",
        "origin": "Application",
    },
    "RoleManagementPolicy.ReadWrite.AzureADGroup": {
        "allowedMemberTypes": ["Application"],
        "id": "b38dcc4d-a239-4ed6-aa84-6c65b284f97c",
        "origin": "Application",
    },
    "ThreatAssessment.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "f8f035bb-2cce-47fb-8bf5-7baf3ecbee48",
        "origin": "Application",
    },
    "IdentityUserFlow.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "1b0c317f-dd31-4305-9932-259a8b6e8099",
        "origin": "Application",
    },
    "TrustFrameworkKeySet.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "fff194f1-7dce-4428-8301-1badb5518201",
        "origin": "Application",
    },
    "Printer.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "f5b3f73d-6247-44df-a74c-866173fddab0",
        "origin": "Application",
    },
    "ResourceSpecificPermissionGrant.ReadForUser.All": {
        "allowedMemberTypes": ["Application"],
        "id": "acfca4d5-f49f-40ed-9648-84068b474c73",
        "origin": "Application",
    },
    "RoleManagementPolicy.Read.Directory": {
        "allowedMemberTypes": ["Application"],
        "id": "fdc4c997-9942-4479-bfcb-75a36d1138df",
        "origin": "Application",
    },
    "IdentityRiskyServicePrincipal.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "607c7344-0eed-41e5-823a-9695ebe1b7b0",
        "origin": "Application",
    },
    "OrgContact.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "e1a88a34-94c4-4418-be12-c87b00e26bea",
        "origin": "Application",
    },
    "DelegatedPermissionGrant.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "81b4724a-58aa-41c1-8a55-84ef97466587",
        "origin": "Application",
    },
    "EventListener.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "0edf5e9e-4ce8-468a-8432-d08631d18c43",
        "origin": "Application",
    },
    "RoleManagementAlert.Read.Directory": {
        "allowedMemberTypes": ["Application"],
        "id": "ef31918f-2d50-4755-8943-b8638c0a077e",
        "origin": "Application",
    },
    "LifecycleWorkflows.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "7c67316a-232a-4b84-be22-cea2c0906404",
        "origin": "Application",
    },
    "ExternalItem.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "7a7cffad-37d2-4f48-afa4-c6ab129adcc2",
        "origin": "Application",
    },
    "BackupRestore-Restore.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "bebd0841-a3d8-4313-a51d-731112c8ee41",
        "origin": "Application",
    },
    "Channel.Create": {
        "allowedMemberTypes": ["Application"],
        "id": "f3a65bd4-b703-46df-8f7e-0174fea562aa",
        "origin": "Application",
    },
    "SpiffeTrustDomain.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "17b78cfd-eeff-447d-8bab-2795af00055a",
        "origin": "Application",
    },
    "ChatMember.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "a3410be2-8e48-4f32-8454-c29a7465209d",
        "origin": "Application",
    },
    "Policy.ReadWrite.FedTokenValidation": {
        "allowedMemberTypes": ["Application"],
        "id": "90bbca0b-227c-4cdc-8083-1c6cfb95bac6",
        "origin": "Application",
    },
    "User-LifeCycleInfo.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "8556a004-db57-4d7a-8b82-97a13428e96f",
        "origin": "Application",
    },
    "Files.SelectedOperations.Selected": {
        "allowedMemberTypes": ["Application"],
        "id": "bd61925e-3bf4-4d62-bc0b-06b06c96d95c",
        "origin": "Application",
    },
    "Mail.Read": {
        "allowedMemberTypes": ["Application"],
        "id": "810c84a8-4a9e-49e6-bf7d-12d183f40d01",
        "origin": "Application",
    },
    "CustomSecAttributeAssignment.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "3b37c5a4-1226-493d-bec3-5d6c6b866f3f",
        "origin": "Application",
    },
    "Files.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "75359482-378d-4052-8f01-80520e7db3cd",
        "origin": "Application",
    },
    "BusinessScenarioData.ReadWrite.OwnedBy": {
        "allowedMemberTypes": ["Application"],
        "id": "f2d21f22-5d80-499e-91cc-0a8a4ce16f54",
        "origin": "Application",
    },
    "PrivilegedEligibilitySchedule.ReadWrite.AzureADGroup": {
        "allowedMemberTypes": ["Application"],
        "id": "618b6020-bca8-4de6-99f6-ef445fa4d857",
        "origin": "Application",
    },
    "ThreatSubmission.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "d72bdbf4-a59b-405c-8b04-5995895819ac",
        "origin": "Application",
    },
    "VirtualEventRegistration-Anon.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "23211fc1-f9d1-4e8e-8e9e-08a5d0a109bb",
        "origin": "Application",
    },
    "EduRoster.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "d1808e82-ce13-47af-ae0d-f9b254e6d58a",
        "origin": "Application",
    },
    "User.ReadBasic.All": {
        "allowedMemberTypes": ["Application"],
        "id": "97235f07-e226-4f63-ace3-39588e11d3a1",
        "origin": "Application",
    },
    "RoleManagementPolicy.Read.AzureADGroup": {
        "allowedMemberTypes": ["Application"],
        "id": "69e67828-780e-47fd-b28c-7b27d14864e6",
        "origin": "Application",
    },
    "ThreatHunting.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "dd98c7f5-2d42-42d3-a0e4-633161547251",
        "origin": "Application",
    },
    "UserAuthenticationMethod.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "38d9df27-64da-44fd-b7c5-a6fbac20248f",
        "origin": "Application",
    },
    "ServiceActivity-Microsoft365Web.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "c766cb16-acc4-4663-ba09-6eedef5876c5",
        "origin": "Application",
    },
    "PartnerSecurity.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "04a2c935-5b4b-474a-be42-11f53111f271",
        "origin": "Application",
    },
    "BusinessScenarioData.Read.OwnedBy": {
        "allowedMemberTypes": ["Application"],
        "id": "6c0257fd-cffe-415b-8239-2d0d70fdaa9c",
        "origin": "Application",
    },
    "LearningContent.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "444d6fcb-b738-41e5-b103-ac4f2a2628a3",
        "origin": "Application",
    },
    "DeviceManagementServiceConfig.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "06a5fe6d-c49d-46a7-b082-56b1b14103c7",
        "origin": "Application",
    },
    "Chat.UpdatePolicyViolation.All": {
        "allowedMemberTypes": ["Application"],
        "id": "7e847308-e030-4183-9899-5235d7270f58",
        "origin": "Application",
    },
    "IdentityProvider.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "e321f0bb-e7f7-481e-bb28-e3b0b32d4bd0",
        "origin": "Application",
    },
    "Directory.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "19dbc75e-c2e2-444c-a770-ec69d8559fc7",
        "origin": "Application",
    },
    "DeviceManagementManagedDevices.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "243333ab-4d21-40cb-a475-36241daa0842",
        "origin": "Application",
    },
    "SecurityEvents.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "d903a879-88e0-4c09-b0c9-82f6a1333f84",
        "origin": "Application",
    },
    "LearningAssignedCourse.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "535e6066-2894-49ef-ab33-e2c6d064bb81",
        "origin": "Application",
    },
    "Sites.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "332a536c-c7ef-4017-ab91-336970924f0d",
        "origin": "Application",
    },
    "ProfilePhoto.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "27baa7f6-5dfb-4ba8-b1d3-1e812c143013",
        "origin": "Application",
    },
    "AdministrativeUnit.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "134fd756-38ce-4afd-ba33-e9623dbe66c2",
        "origin": "Application",
    },
    "DelegatedPermissionGrant.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "8e8e4742-1d95-4f68-9d56-6ee75648c72a",
        "origin": "Application",
    },
    "RecordsManagement.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "ac3a2b8e-03a3-4da9-9ce0-cbe28bf1accd",
        "origin": "Application",
    },
    "Teamwork.Migrate.All": {
        "allowedMemberTypes": ["Application"],
        "id": "dfb0dd15-61de-45b2-be36-d6a69fba3c79",
        "origin": "Application",
    },
    "AuthenticationContext.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "a88eef72-fed0-4bf7-a2a9-f19df33f8b83",
        "origin": "Application",
    },
    "ListItems.SelectedOperations.Selected": {
        "allowedMemberTypes": ["Application"],
        "id": "de4e4161-a10a-4dfd-809c-e328d89aefeb",
        "origin": "Application",
    },
    "OrgSettings-DynamicsVoice.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "c18ae2dc-d9f3-4495-a93f-18980a0e159f",
        "origin": "Application",
    },
    "GroupMember.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "98830695-27a2-44f7-8c18-0c3ebc9698f6",
        "origin": "Application",
    },
    "ServiceHealth.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "79c261e0-fe76-4144-aad5-bdc68fbe4037",
        "origin": "Application",
    },
    "PendingExternalUserProfile.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "bdfb26d9-bb36-49be-9b4c-b8cbf4b05808",
        "origin": "Application",
    },
    "OnPremDirectorySynchronization.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "c22a92cc-79bf-4bb1-8b6c-e0a05d3d80ce",
        "origin": "Application",
    },
    "Device.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "7438b122-aefc-4978-80ed-43db9fcc7715",
        "origin": "Application",
    },
    "MailboxSettings.Read": {
        "allowedMemberTypes": ["Application"],
        "id": "40f97065-369a-49f4-947c-6a255697ae91",
        "origin": "Application",
    },
    "ServiceMessage.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "1b620472-6534-4fe6-9df2-4680e8aa28ec",
        "origin": "Application",
    },
    "InformationProtectionContent.Write.All": {
        "allowedMemberTypes": ["Application"],
        "id": "287bd98c-e865-4e8c-bade-1a85523195b9",
        "origin": "Application",
    },
    "Policy.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "246dd0d5-5bd0-4def-940b-0421030a5b68",
        "origin": "Application",
    },
    "DeviceManagementServiceConfig.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "5ac13192-7ace-4fcf-b828-1a26f28068ee",
        "origin": "Application",
    },
    "Member.Read.Hidden": {
        "allowedMemberTypes": ["Application"],
        "id": "658aa5d8-239f-45c4-aa12-864f4fc7e490",
        "origin": "Application",
    },
    "RoleManagement.Read.CloudPC": {
        "allowedMemberTypes": ["Application"],
        "id": "031a549a-bb80-49b6-8032-2068448c6a3c",
        "origin": "Application",
    },
    "Presence.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "a70e0c2d-e793-494c-94c4-118fa0a67f42",
        "origin": "Application",
    },
    "TeamsAppInstallation.ReadWriteSelfForUser.All": {
        "allowedMemberTypes": ["Application"],
        "id": "908de74d-f8b2-4d6b-a9ed-2a17b3b78179",
        "origin": "Application",
    },
    "RoleManagementPolicy.ReadWrite.Directory": {
        "allowedMemberTypes": ["Application"],
        "id": "31e08e0a-d3f7-4ca2-ac39-7343fb83e8ad",
        "origin": "Application",
    },
    "Mail.ReadWrite": {
        "allowedMemberTypes": ["Application"],
        "id": "e2a3a72e-5f79-4c64-b1b1-878b674786c9",
        "origin": "Application",
    },
    "Chat.Create": {
        "allowedMemberTypes": ["Application"],
        "id": "d9c48af6-9ad9-47ad-82c3-63757137b9af",
        "origin": "Application",
    },
    "AgreementAcceptance.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "d8e4ec18-f6c0-4620-8122-c8b1f2bf400e",
        "origin": "Application",
    },
    "PrintJob.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "ac6f956c-edea-44e4-bd06-64b1b4b9aec9",
        "origin": "Application",
    },
    "User-ConvertToInternal.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "9d952b72-f741-4b40-9185-8c53076c2339",
        "origin": "Application",
    },
    "TeamworkAppSettings.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "ab5b445e-8f10-45f4-9c79-dd3f8062cc4e",
        "origin": "Application",
    },
    "Channel.Delete.All": {
        "allowedMemberTypes": ["Application"],
        "id": "6a118a39-1227-45d4-af0c-ea7b40d210bc",
        "origin": "Application",
    },
    "BusinessScenarioConfig.Read.OwnedBy": {
        "allowedMemberTypes": ["Application"],
        "id": "acc0fc4d-2cd6-4194-8700-1768d8423d86",
        "origin": "Application",
    },
    "ShortNotes.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "842c284c-763d-4a97-838d-79787d129bab",
        "origin": "Application",
    },
    "TeamsTab.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "46890524-499a-4bb2-ad64-1476b4f3e1cf",
        "origin": "Application",
    },
    "CrossTenantInformation.ReadBasic.All": {
        "allowedMemberTypes": ["Application"],
        "id": "cac88765-0581-4025-9725-5ebc13f729ee",
        "origin": "Application",
    },
    "OrganizationalBranding.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "eb76ac34-0d62-4454-b97c-185e4250dc20",
        "origin": "Application",
    },
    "User.RevokeSessions.All": {
        "allowedMemberTypes": ["Application"],
        "id": "77f3a031-c388-4f99-b373-dc68676a979e",
        "origin": "Application",
    },
    "EduAdministration.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "7c9db06a-ec2d-4e7b-a592-5a1e30992566",
        "origin": "Application",
    },
    "Chat.Read.WhereInstalled": {
        "allowedMemberTypes": ["Application"],
        "id": "1c1b4c8e-3cc7-4c58-8470-9b92c9d5848b",
        "origin": "Application",
    },
    "AdministrativeUnit.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "5eb59dd3-1da2-4329-8733-9dabdc435916",
        "origin": "Application",
    },
    "User.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "df021288-bdef-4463-88db-98f22de89214",
        "origin": "Application",
    },
    "IdentityRiskEvent.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "db06fb33-1953-4b7b-a2ac-f1e2c854f7ae",
        "origin": "Application",
    },
    "WindowsUpdates.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "7dd1be58-6e76-4401-bf8d-31d1e8180d5b",
        "origin": "Application",
    },
    "CustomDetection.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "e0fd9c8d-a12e-4cc9-9827-20c8c3cd6fb8",
        "origin": "Application",
    },
    "CustomAuthenticationExtension.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "88bb2658-5d9e-454f-aacd-a3933e079526",
        "origin": "Application",
    },
    "Sites.Manage.All": {
        "allowedMemberTypes": ["Application"],
        "id": "0c0bf378-bf22-4481-8f81-9e89a9b4960a",
        "origin": "Application",
    },
    "OnlineMeetings.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "c1684f21-1984-47fa-9d61-2dc8c296bb70",
        "origin": "Application",
    },
    "ChannelMember.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "3b55498e-47ec-484f-8136-9013221c06a9",
        "origin": "Application",
    },
    "BackupRestore-Restore.Read.All": {
        "allowedMemberTypes": ["Application"],
        "id": "87853aa5-0372-4710-b34b-cef27bb7156e",
        "origin": "Application",
    },
    "UserAuthenticationMethod.ReadWrite.All": {
        "allowedMemberTypes": ["Application"],
        "id": "50483e42-d915-4231-9639-7fdb7fd190e5",
        "origin": "Application",
    },
}
