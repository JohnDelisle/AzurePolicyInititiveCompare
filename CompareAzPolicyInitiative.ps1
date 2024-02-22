[CmdletBinding()]
param (
    [Parameter()][string[]]$InititiveIDs = @(
        "/providers/Microsoft.Authorization/policySetDefinitions/e95f5a9f-57ad-4d03-bb0b-b1d16db93693",
        "/providers/Microsoft.Authorization/policySetDefinitions/4c4a5f27-de81-430b-b4e5-9cbd50595a87",
        "/providers/Microsoft.Authorization/policySetDefinitions/cf25b9c1-bd23-4eb6-bd2c-f4f3ac644a5f",
        "/providers/Microsoft.Authorization/policySetDefinitions/179d1daa-458f-4e47-8086-2a68d0d6c38f",
        "/providers/Microsoft.Authorization/policySetDefinitions/1f3afdf9-d0c9-4c3d-847f-89da613e70a8",
        "/providers/Microsoft.Authorization/policySetDefinitions/03055927-78bd-4236-86c0-f36125a10dc9"
    )
)

# FedRAMP Moderate - /providers/Microsoft.Authorization/policySetDefinitions/e95f5a9f-57ad-4d03-bb0b-b1d16db93693
# Canada Federal PBMM - /providers/Microsoft.Authorization/policySetDefinitions/4c4a5f27-de81-430b-b4e5-9cbd50595a87
# NIST SP 800-53 Rev. 4 - /providers/Microsoft.Authorization/policySetDefinitions/cf25b9c1-bd23-4eb6-bd2c-f4f3ac644a5f
# NIST SP 800-53 Rev. 5 - /providers/Microsoft.Authorization/policySetDefinitions/179d1daa-458f-4e47-8086-2a68d0d6c38f
# NIST SP 800-171 Rev. 2 - /providers/Microsoft.Authorization/policySetDefinitions/03055927-78bd-4236-86c0-f36125a10dc9
# Azure Security Benchmark - /providers/Microsoft.Authorization/policySetDefinitions/1f3afdf9-d0c9-4c3d-847f-89da613e70a8

$ErrorActionPreference = 'inquire'
$policyDefinitionCache = @{}
$policySetDefinitionCache = @{}

# make sure we've got Az module
if (!(Get-Module -ListAvailable Az)) {
    # need Az module.. 
    Install-Module -Name Az -Scope CurrentUser -Repository PSGallery -Force
    Import-Module Az
}

function Get-CachedPolicyDefinition ($id) {
    # cache the policy definitions to speed up execution and to be considerate towards the Azure API
    if ($policyDefinitionCache.ContainsKey($id)) {
        return $policyDefinitionCache[$id]
    }

    $policyDefinitionCache[$id] = Get-AzPolicyDefinition -Id $id

    if (!$policyDefinitionCache[$id]) {
        Write-Error "Failed to retrieve policy definition for $id"
    }

    return $policyDefinitionCache[$id]
}

function Get-CachedPolicySetDefinition ($id) {
    # cache the policy set definitions to speed up execution and to be considerate towards the Azure API
    if ($policySetDefinitionCache.ContainsKey($id)) {
        return $policySetDefinitionCache[$id]
    }

    $policySetDefinitionCache[$id] = Get-AzPolicySetDefinition -Id $id

    if (!$policySetDefinitionCache[$id]) {
        Write-Error "Failed to retrieve policy set definition for $id"
    }

    return $policySetDefinitionCache[$id]
}

function Get-Policies {
    param (
        [Parameter(Mandatory = $true)][hashtable]$PolicyIDs,
        [Parameter(Mandatory = $true)][string[]]$InititiveID
    )
    # using a hashtable for these to handle uniqueness for me

    Write-Debug "Examining Initiative ID $InitiativeId"
    $Initiative = Get-CachedPolicySetDefinition -Id $InitiativeID
    
    $Initiative.Properties.PolicyDefinitions.policyDefinitionId | ForEach-Object {

        # shorter and tidier
        $policyGuid = ($_).split('/')[-1]

        # do we have this policy in our list yet? 
        if ($PolicyIDs.ContainsKey($policyGuid)) {
            # If so, just mark it as being needed by this initiative
            $PolicyIDs[$policyGuid].$($Initiative.Properties.DisplayName) = $true
        } else {
            # parse and clean-up allowed effect values
            $tmpValues = (Get-CachedPolicyDefinition -Id $_).Properties.Parameters.effect.allowedValues
            if ($tmpValues) {
                $tmpCleanValues = ($tmpValues.ToLower() | ForEach-Object {
                    (Get-Culture).TextInfo.ToTitleCase($_) | Sort-Object -Unique
                } | Sort-Object -Unique) -join ", "
            }
            
            # If not, add the policy to our list, and  mark it as being needed by this initiative
            $PolicyIDs[$policyGuid] = [Policy]@{
                $Initiative.Properties.DisplayName = $true
                PolicyID = $_
                DefaultEffectValue = (Get-CachedPolicyDefinition -Id $_).Properties.Parameters.effect.defaultValue
                # this mess takes shitty Az Policy available actions like @("Foo Bar", "foo bar", "bleh") and gives us "Foo Bar, Bleh" as a result
                AvailableEffectValues = $tmpCleanValues
                PolicyDisplayName = (Get-CachedPolicyDefinition -Id $_).Properties.DisplayName
            }
        }
    }

    Return $PolicyIDs
}

# get the names of the initiatives, so we can create our custom class using them. These become "column headings" in the CSV output
$InitiativeNames = @()
foreach ($InitiativeID in $InititiveIDs) {
    $InitiativeNames += (Get-CachedPolicySetDefinition -Id $InitiativeID).Properties.DisplayName
}

Invoke-Expression @"
Class Policy {
  [string] `$PolicyID
  [string] `$PolicyDisplayName
  [string] `$DefaultEffectValue
  [string] `$AvailableEffectValues
  $(foreach ($InitiativeName in $InitiativeNames) {
    "[bool] `${$($InitiativeName)}`n"
  }
  )
}
"@

# get the Az Policies that are associated with each of the Az Policy Initiatives
$PolicyIDs = @{}
foreach ($InitiativeID in $InititiveIDs) {
    $PolicyIDs = Get-Policies -PolicyIDs $PolicyIDs -InititiveID $InitiativeID
}

# take the PolicyIDs hashtable and convert it into an array - hashtable ensured uniqueness, but it's ugly to output
$results = @()
$PolicyIDs.Keys | ForEach-Object {
    $results += $PolicyIDs.$_
}

# dump results
$results | ConvertTo-Json -Depth 99 | Out-File c:\temp\PolicyComparison.json
$results | ConvertTo-Csv -NoTypeInformation | Out-File c:\temp\PolicyComparison.csv
