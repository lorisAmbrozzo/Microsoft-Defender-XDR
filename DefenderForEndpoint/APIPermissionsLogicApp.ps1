<#
.DESCRIPTION
    Assign graph permissions to a managed identity to use API calls in a logic application (playbook) in Microsoft Sentinel
.INPUTS
    None. 
.OUTPUTS
    None
.NOTES
    Author: Loris Ambrozzo
    Version: 1.0
    Date: 18.07.2023
.ROLE
   Privileged Role Administrator or Global Administrator
#>
#Connect to Microsoft Graph
Connect-MGGraph -Scopes "Application.Read.All", "AppRoleAssignment.ReadWrite.All" 

$GraphApp = Get-MgServicePrincipal -Filter "AppId eq 'INSERT API ID'" #Application ID of WindowsDefenderATP
$Role1 = $GraphApp.AppRoles | Where-Object {$_.Value -eq  'Ti.Read.All'}
$Role2 = $GraphApp.AppRoles | Where-Object {$_.Value -eq  'Ti.ReadWrite.All'}
$Role3 = $GraphApp.AppRoles | Where-Object {$_.Value -eq  'Machine.Isolate'}
$Role4 = $GraphApp.AppRoles | Where-Object {$_.Value -eq  'Machine.ReadWrite.All'}

#Assign permissions to User assigned managed identity
$appRoleIds = @($Role1, $Role2, $Role3, $Role4)

foreach ($role in $appRoleIds) {
	$params = @{
		PrincipalId = "INSERT OBJECT ID" #Object ID User-Assigned Managed Identity
		ResourceId = "INSERT OBJECT ID" #Object ID of WindowsDefenderATP
		AppRoleId = $role.id
	}
	New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $params.PrincipalId -BodyParameter $params
}
Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $params.PrincipalId
