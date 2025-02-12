param(
    [Parameter(Mandatory=$true)]
    [string]$ResourceGroupName,
    
    [Parameter(Mandatory=$true)]
    [string]$PolicyName,
    
    [Parameter(Mandatory=$true)]
    [string]$Subdomain,
    
    [Parameter(Mandatory=$true)]
    [string]$IpListFile
)

# Function to validate IP address format
function Test-IPAddress {
    param([string]$IP)
    
    $ipPattern = "^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$"
    if ($IP -match $ipPattern) {
        $octets = $IP.Split('/')[0].Split('.')
        foreach ($octet in $octets) {
            if ([int]$octet -gt 255) {
                return $false
            }
        }
        return $true
    }
    return $false
}

# Check if IP list file exists
if (-not (Test-Path $IpListFile)) {
    Write-Error "IP list file not found: $IpListFile"
    exit 1
}

# Check if Azure PowerShell module is installed
if (-not (Get-Module -ListAvailable Az.Network)) {
    Write-Error "Azure PowerShell module not found. Please install it using: Install-Module -Name Az"
    exit 1
}

# Get WAF policy
try {
    $wafPolicy = Get-AzApplicationGatewayFirewallPolicy -ResourceGroupName $ResourceGroupName -Name $PolicyName
    Write-Host "Found WAF policy: $PolicyName"
}
catch {
    Write-Error "Failed to get WAF policy: $_"
    exit 1
}

# Initialize valid IPs array
$validIPs = @()

# Read and validate IP addresses
Get-Content $IpListFile | ForEach-Object {
    $ip = $_.Trim()
    
    # Skip empty lines and comments
    if ($ip -and -not $ip.StartsWith("#")) {
        # Validate IP format
        if (Test-IPAddress $ip) {
            $validIPs += $ip
        }
        else {
            Write-Warning "Invalid IP format: $ip (skipping)"
        }
    }
}

# If we have valid IPs, create rules in groups of 99
if ($validIPs.Count -gt 0) {
    # Calculate number of groups needed (99 IPs per group)
    $groupSize = 99
    $groupCount = [math]::Ceiling($validIPs.Count / $groupSize)
    
    Write-Host "Creating $groupCount rules for $($validIPs.Count) IPs on subdomain: $Subdomain"
    
    for ($groupIndex = 0; $groupIndex -lt $groupCount; $groupIndex++) {
        # Get IPs for this group
        $startIndex = $groupIndex * $groupSize
        $groupIPs = $validIPs[$startIndex..([Math]::Min($startIndex + $groupSize - 1, $validIPs.Count - 1))]
        
        $ruleName = "BlockIPsGroup$($groupIndex + 1)"
        
        Write-Host "Creating rule $ruleName with $($groupIPs.Count) IPs"
        
        try {
            # Create match conditions
            $ipMatch = New-AzApplicationGatewayFirewallMatchVariable -VariableName RemoteAddr
            $hostMatch = New-AzApplicationGatewayFirewallMatchVariable -VariableName RequestHeaders -Selector "Host"
            
            $condition1 = New-AzApplicationGatewayFirewallCondition -MatchVariable $ipMatch -Operator IPMatch -MatchValue $groupIPs
            $condition2 = New-AzApplicationGatewayFirewallCondition -MatchVariable $hostMatch -Operator Contains -MatchValue $Subdomain
            
            # Create custom rule
            $rule = New-AzApplicationGatewayFirewallCustomRule `
                -Name $ruleName `
                -Priority $(1 + $groupIndex) `
                -RuleType MatchRule `
                -MatchCondition $condition1,$condition2 `
                -Action Allow
            
            # Add rule to policy
            $wafPolicy.CustomRules.Add($rule)
            
            # Update WAF policy
            $wafPolicy | Set-AzApplicationGatewayFirewallPolicy
            
            Write-Host "Successfully added rule $ruleName"
            Write-Host "IPs in this group: $($groupIPs -join ', ')"
        }
        catch {
            Write-Error "Failed to add rule $ruleName : $_"
        }
    }
    
    Write-Host "Completed adding $groupCount rules for $($validIPs.Count) IPs"
}
else {
    Write-Warning "No valid IPs found in the input file"
}