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

# Function to create valid rule name
function Get-ValidRuleName {
    param(
        [string]$IP,
        [int]$Counter
    )
    # Create a simple rule name that meets Azure requirements
    # Only alphanumeric characters are allowed
    return "BlockIP$Counter"
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

# Initialize rule counter for priority
$ruleCounter = 1

# Read and process IP addresses
Get-Content $IpListFile | ForEach-Object {
    $ip = $_.Trim()
    
    # Skip empty lines and comments
    if ($ip -and -not $ip.StartsWith("#")) {
        # Validate IP format
        if (Test-IPAddress $ip) {
            # Create a valid rule name
            $ruleName = Get-ValidRuleName -IP $ip -Counter $ruleCounter
            
            Write-Host "Adding block rule '$ruleName' for IP: $ip on subdomain: $Subdomain"
            
            # Create match conditions
            $ipMatch = New-AzApplicationGatewayFirewallMatchVariable -VariableName RemoteAddr
            $hostMatch = New-AzApplicationGatewayFirewallMatchVariable -VariableName RequestHeaders -Selector "Host"
            
            $condition1 = New-AzApplicationGatewayFirewallCondition -MatchVariable $ipMatch -Operator IPMatch -MatchValue $ip
            $condition2 = New-AzApplicationGatewayFirewallCondition -MatchVariable $hostMatch -Operator Contains -MatchValue $Subdomain
            
            try {
                # Create custom rule
                $rule = New-AzApplicationGatewayFirewallCustomRule `
                    -Name $ruleName `
                    -Priority $((1 + $ruleCounter)) `
                    -RuleType MatchRule `
                    -MatchCondition $condition1,$condition2 `
                    -Action Block
                
                # Add rule to policy
                $wafPolicy.CustomRules.Add($rule)
                
                # Update WAF policy
                $wafPolicy | Set-AzApplicationGatewayFirewallPolicy
                
                Write-Host "Successfully added rule '$ruleName' for IP: $ip"
                $ruleCounter++
            }
            catch {
                Write-Error "Failed to add rule for IP $ip : $_"
            }
        }
        else {
            Write-Warning "Invalid IP format: $ip (skipping)"
        }
    }
}

Write-Host "Completed adding $($ruleCounter - 1) IP block rules for subdomain $Subdomain"

# Example usage:
# .\block-waf-ips.ps1 -ResourceGroupName "my-resource-group" -PolicyName "my-waf-policy" -Subdomain "hello.myapplication.com" -IpListFile "blocked-ips.txt"