[CmdletBinding()]
param(

  [Parameter(Mandatory)]
  [string]$ConfigPath,

  [Parameter()]
  [string[]]$SkipTests,

  [Parameter(Mandatory)]
  [AllowEmptyCollection()]
  [string[]]$Untrusted,

  [Parameter()]
  [string]$CipherSuites,

  [Parameter()]
  [int]$MaxConsoleTimeout = 5,

  [Parameter()]
  [int]$MaxSshTimeout = 5,

  [Parameter()]
  [int]$MaxHttpTimeout = 5
)


#$here = Split-Path -Parent $MyInvocation.MyCommand.Path
#$sut = (Split-Path -Leaf $MyInvocation.MyCommand.Path) -replace '\.Tests\.', '.'
#. "$here\$sut"


# The contents of the log file should contain the output of the following commands
# show running-config
# show crypto key mypubkey rsa
# show interface ip brief
# show snmp-server group

<#
# Creating the parameters for the test script
# Customise parameters according to your risk appetite
$params = @{
    'Untrusted' = @()
    'SkipTests' = @(
        '1.7.3'
        '1.9.1.1', '1.9.1.2', '1.9.1.3' 
    )
    'MaxConsoleTimeout'=20
    'MaxSshTimeout'=60
    'MaxHttpTimeout'=20
    'CipherSuites'='ECDHE-RSA-AES256-GCM-SHA384:AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384:AES256-SHA256:ECDHE-RSA-AES128-GCM-SHA256:AES128-GCM-SHA256:ECDHE-RSA-AES128-SHA256:AES256-SHA:AES128-SHA'
    'ConfigPath' = 'C:\scripts\audit\ASAConfigAudit\bneasaconfig.log'
}

<# 
# Calling the test with Parameters - customise paths as required
invoke-pester -Script @{'path'='.\*.tests.ps1'; Parameters=$params} -OutputFile .\TestResults.xml -OutputFormat LegacyNUnitXml
#>

<#
# Converting the test results to a html report
$xsl = [System.Xml.Xsl.XslCompiledTransform]::new()
$xsl.load('C:\scripts\audit\ASAConfigAudit\LegacyNunit2Html.xsl')
$xsl.Transform('C:\scripts\audit\ASAConfigAudit\TestResults.xml','C:\scripts\audit\ASAConfigAudit\testresults.html')
#>


Function IsSkipped {
[CmdletBinding()]
param (
        [Parameter(Mandatory)]
        [String]$Test
    )

    ($SkipTests -match "^$Test$").count -ne 0
}

if (-not $PSBoundParameters['CipherSuites'] -and -not (IsSkipped('1.7.3a')) ) {
    $SkipTests += '1.7.3a'
}


$config = Get-Content -path $ConfigPath

# Customise parameters according to your risk appetite
# Specific test Parameters
# 1.7.3a SSL Cipher Suites
# $CipherSuites = 'ECDHE-RSA-AES256-GCM-SHA384:AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384:AES256-SHA256:ECDHE-RSA-AES128-GCM-SHA256:AES128-GCM-SHA256:ECDHE-RSA-AES128-SHA256:AES256-SHA:AES128-SHA'


Describe "0 Configuration PreRequisites" {

    Context "Test configuration prerequisites are complete" {
        It "Ensure configuration prerequisite 'Untrusted' interfaces are defined" {
            $null -eq (Get-Variable -Name 'Untrusted' -ErrorAction SilentlyContinue) | should be $false
        }
        It "Ensure configuration prerequisite 'Untrusted' interfaces are not an empty array" {
            ($Untrusted -is [array]) -and ($Untrusted.Count -gt 0)  | should be $true
        }
    }
}

Describe "1.1 Management Plane - Password Management" {
    Context "Management Plane - Password Management" {
        It "1.1.1 Ensure 'Logon Password' is set" -skip:(IsSkipped('1.1.1')) {
            $Matchinfo = $config | Select-String -Pattern '^passwd'
            $Matchinfo | Should not be $null
        }
        It "1.1.2 Ensure 'Enable Password' is set" -skip:(IsSkipped('1.1.2')) {
            $Matchinfo = $config | Select-String -Pattern '^enable\s+password\s+[^\s]+\s+encrypted'
            $Matchinfo | Should not be $null
        }
        It "1.1.3 Ensure 'Master Key Passphrase' is set" -skip:(IsSkipped('1.1.3')) {
            $Matchinfo = $config | Select-String -Pattern '^key\s+6'
            $Matchinfo | Should not be $null
        }
        It "1.1.4 Ensure 'Password Recovery' is disabled" -skip:(IsSkipped('1.1.4'))  {
            $Matchinfo = $config | Select-String -Pattern '^no\s+service\s+password-recovery'
            $Matchinfo | Should not be $null
        }
        It "1.1.5 Ensure 'Password Policy' is enabled" -skip:(IsSkipped('1.1.5')) {
            $Matchinfo = $config | Select-String -Pattern '^password-policy'
            $Matchinfo | Should not be $null
        }
    }
}

Describe "1.2 Management Plane - Device Management" {
    Context "Management Plane - Device Management" {
        It "1.2.1 Ensure 'Domain Name' is set" -skip:(IsSkipped('1.2.1')) {
            $Matchinfo = $config | Select-String -Pattern '^domain-name'
            $Matchinfo | Should not be $null
        }
        It "1.2.2 Ensure 'Host Name' is set" -skip:(IsSkipped('1.2.2')) {
            $Matchinfo = $config | Select-String -Pattern '^hostname\s+(?!ciscoasa$|asa$)'
            $Matchinfo | Should not be $null
        }
        It "1.2.3 Ensure 'Failover' is enabled" -skip:(IsSkipped('1.2.3')) {
            $Matchinfo = $config | Select-String -Pattern '^(?:failover|cluster\s+group\s+.+$)'
            $Matchinfo | Should not be $null
        }
        It "1.2.4 Ensure 'Unused Interfaces' are disabled"  -skip:(IsSkipped('1.2.4')) {
            $Matchinfo = $config | Select-String -Pattern '(?<!administratively\s+down)\s+down$'
            $Matchinfo | Should be $null
        }
    }
}

Describe "1.4.1 Management Plane - Authentication, Authorisation and Accounting - Local AAA Rules" {

    Context "Management Plane - Authentication, Authorisation and Accounting - Local AAA Rules"  {
        It "1.4.1.1 Ensure 'aaa local authentication max failed attempts' is set to less than or equal to '3'" -skip:(IsSkipped('1.4.1.1')) {
            $Matchinfo = $config | Select-String -Pattern 'aaa local authentication attempts max-fail\s+[1-3]'
            $Matchinfo | Should not be $null
        }
        It "1.4.1.2 Ensure 'local username and password' is set" -skip:(IsSkipped('1.4.1.2')) {
            $Matchinfo = $config | Select-String -Pattern '^username'
            $Matchinfo | Should not be $null
        }
        It "1.4.1.3 Ensure known default accounts do not exist" -skip:(IsSkipped('1.4.1.3')) {
            $Matchinfo = $config | Select-String -Pattern '"^username\s+(admin|asa|cisco|pix|root)"'
            $Matchinfo | Should be $null
        }
    }
}

Describe "1.4.2 Management Plane - Authentication, Authorisation and Accounting - Remote AAA servers" {
    Context "Management Plane - Authentication, Authorisation and Accounting - Remote AAA servers"  {
        It "1.4.2.1 Ensure 'TACACS+/RADIUS' is configured correctly" -skip:(IsSkipped('1.4.2.1')) {
            $Matchinfo = $config | Select-String -Pattern '^aaa-server\s+[^\s]+\s+protocol\s+(radius|tacacs\+)'
            $Matchinfo | Should not be $null
        }
    }
}
Describe "1.4.3 Management Plane - Authentication, Authorisation and Accounting - AAA authentication" {
    Context "Management Plane - Authentication, Authorisation and Accounting - AAA authentication" {
        It "1.4.3.1 Ensure 'aaa authentication enable console' is configured correctly" -skip:(IsSkipped('1.4.3.1')) {
            $Matchinfo = $config | Select-String -Pattern '^aaa authentication enable console'
            $Matchinfo | Should not be $null
        }
        It "1.4.3.2 Ensure 'aaa authentication http console' is configured correctly" -skip:(IsSkipped('1.4.3.2')) {
            $Matchinfo = $config | Select-String -Pattern '^aaa authentication http console'
            $Matchinfo | Should not be $null
        }
        It "1.4.3.3 Ensure 'aaa authentication secure-http-client' is configured correctly" -skip:(IsSkipped('1.4.3.3')) {
            $Matchinfo = $config | Select-String -Pattern '^aaa authentication secure-http-client'
            $Matchinfo | Should not be $null
        }
        It "1.4.3.4 Ensure 'aaa authentication serial console' is configured correctly" -skip:(IsSkipped('1.4.3.4')) {
            $Matchinfo = $config | Select-String -Pattern '^aaa authentication serial console'
            $Matchinfo | Should not be $null
        }
        It "1.4.3.5 Ensure 'aaa authentication ssh console' is configured correctly" -skip:(IsSkipped('1.4.3.5')) {
            $Matchinfo = $config | Select-String -Pattern '^aaa authentication ssh console'
            $Matchinfo | Should not be $null
        }
    }
}

Describe "1.4.4 Management Plane - Authentication, Authorisation and Accounting - AAA Authorization" {
    Context "Management Plane - Authentication, Authorisation and Accounting - AAA Authorization"  {
        It "1.4.4.1 Ensure 'aaa command authorization' is configured correctly" -skip:(IsSkipped('1.4.4.1')) {
            $Matchinfo = $config | Select-String -Pattern '^aaa authorization command'
            $Matchinfo | Should not be $null
        }
        It "1.4.4.2 Ensure 'aaa authorization exec' is configured correctly" -skip:(IsSkipped('1.4.4.2')) {
            $Matchinfo = $config | Select-String -Pattern '^aaa authorization exec authentication-server'
            $Matchinfo | Should not be $null
        }
    }

    Context "Management Plane - Authentication, Authorisation and Accounting - AAA Accounting" {
        It "1.4.5.1 Ensure 'aaa accounting command' is configured correctly" -skip:(IsSkipped('1.4.5.1')) {
            $Matchinfo = $config | Select-String -Pattern '^aaa accounting command [^\s]+$'
            $Matchinfo | Should not be $null
        }
        It "1.4.5.2 Ensure 'aaa accounting for SSH' is configured correctly" -skip:(IsSkipped('1.4.5.2')) {
            $Matchinfo = $config | Select-String -Pattern '^aaa accounting ssh console [^\s]+$'
            $Matchinfo | Should not be $null
        }
        It "1.4.5.3 Ensure 'aaa accounting for Serial console' is configured correctly" -skip:(IsSkipped('1.4.5.3')) {
            $Matchinfo = $config | Select-String -Pattern '^aaa accounting serial console [^\s]+$'
            $Matchinfo | Should not be $null
        }
        It "1.4.5.4 Ensure 'aaa accounting for EXEC mode' is configured correctly" -skip:(IsSkipped('1.4.5.4')) {
            $Matchinfo = $config | Select-String -Pattern '^aaa accounting enable console [^\s]+'
            $Matchinfo | Should not be $null
        }
    }
}

 Describe "1.5 Management Plane - Banner Rules" {
    Context "Management Plane - Banner Rules" {
        It "1.5.1 Ensure 'ASDM banner' is set" -skip:(IsSkipped('1.5.1')) {
            $Matchinfo = $config | Select-String -Pattern '^banner\s+asdm'
            $Matchinfo | Should not be $null
        }
        It "1.5.2 Ensure 'EXEC banner' is set" -skip:(IsSkipped('1.5.2')) {
            $Matchinfo = $config | Select-String -Pattern '^banner\s+exec'
            $Matchinfo | Should not be $null
        }
        It "1.5.3 Ensure 'LOGIN banner' is set" -skip:(IsSkipped('1.5.3')) {
            $Matchinfo = $config | Select-String -Pattern '^banner\s+login'
            $Matchinfo | Should not be $null
        }
        It "1.5.4 Ensure 'MOTD banner' is set" -skip:(IsSkipped('1.5.4')) {
            $Matchinfo = $config | Select-String -Pattern '^banner\s+motd'
            $Matchinfo | Should not be $null
        }
    }
}

Describe "1.6 Management Plane - SSH Rules" {
    Context "Management Plane - SSH Rules" {
        It "1.6.1 Ensure 'SSH source restriction' is set to an authorized IP address" -skip:(IsSkipped('1.6.1')) {
            # possible false positive on ssh key-exchange unless we use [\d.]+
            # needs test for ipv6 interface
            $Matchinfo = $config | Select-String -Pattern '^ssh\s+[\d.]+\s+[\d.]+\s+[^\s]+$'
            $Matchinfo | Should not be $null
        }
        It "1.6.2 Ensure 'SSH version 2' is enabled" -skip:(IsSkipped('1.6.2')) {
            $Matchinfo = $config | Select-String -Pattern '^ssh\s+version\s+2$'
            $Matchinfo | Should not be $null
        }
        It "1.6.3 Ensure 'RSA key pair' is greater than or equal to 2048 bits" -skip:(IsSkipped('1.6.3')) {
            $Matchinfo = $config | Select-String -Pattern 'Modulus\s+Size\s+\(bits\):\s+(?<keysize>\d+)$'
            if ($null -eq $matchinfo) {
                #we found no keys
                $badkeys = $true
            }
            else {
                $badkeys = $matchinfo | foreach-object {
                    ($_.Matches[0].groups['keysize'].value -as[int]) -lt 2048
                }
            }

            $badkeys -contains $true | Should be $false
        }
        It "1.6.4 Ensure 'SCP protocol' is set to Enable for files transfers" -skip:(IsSkipped('1.6.4')) {
            $Matchinfo = $config | Select-String -Pattern '^ssh\s+scopy\s+enable$'
            $Matchinfo | Should not be $null
        }
        It "1.6.5 Ensure 'Telnet' is disabled" -skip:(IsSkipped('1.6.5')) {
            # needs test for ipv6 interface
            $Matchinfo = $config | Select-String -Pattern '^telnet\s+[\d.]+\s+[\d.]+\s+[^\s]+$'
            $Matchinfo | Should be $null
        }
    }
}

Describe "1.7 Management Plane Http Rules" {
    Context "Management Plane - HTTP Rules" {
        It "1.7.1 Ensure 'HTTP source restriction' is set to an authorized IP address" -skip:(IsSkipped('1.7.1')) {
            # possible false positive on ssh key-exchange unless we use [\d.]+
            # needs test for ipv6 interface
            $Matchinfo = $config | Select-String -Pattern '^http\s+[\d.]+\s+[\d.]+\s+[^\s]+$'
            $Matchinfo | Should not be $null
        }
        It "1.7.2 Ensure 'TLS 1.2' is set for HTTPS access" -skip:(IsSkipped('1.7.2')) {
            #need to check config not currently enforced to tlsv1.2
            $Matchinfo = $config | Select-String -Pattern '^ssl server-version tlsv1.2$'
            $Matchinfo | Should not be $null
        }
        It "1.7.3 Ensure 'SSL AES 256 encryption' is set for HTTPS access" -skip:(IsSkipped('1.7.3')) {
            $Matchinfo = $config | Select-String -Pattern '^ssl\s+cipher\s+tlsv1.2\s+custom\s+"AES256-SHA"$'
            $Matchinfo | Should not be $null
        }
        It "1.7.3a Ensure 'SSL tlsv1.2 custom' ciphersuites is set for HTTPS access" -skip:(IsSkipped('1.7.3a')) {
            $Matchinfo = $config | Select-String -Pattern ('^ssl\s+cipher\s+tlsv1.2\s+custom\s+"{0}"$' -f $Ciphersuites)
            $Matchinfo | Should not be $null
        }
    }
}

Describe "1.8 Management Plane - Session timeout Rules" {
    Context "Management Plane - Session timeout Rules" {
        It "1.8.1 Ensure 'console session timeout' is less than or equal to '$MaxConsoleTimeout' minutes" -skip:(IsSkipped('1.8.1')) {
            $Matchinfo = $config | Select-String -Pattern '^console\s+timeout\s+(?<ConsoleTimeout>\d+)$'
            $Timeout = 0
            if ($null -ne $Matchinfo) {
                $Timeout = $Matchinfo.Matches[0].Groups['ConsoleTimeout'].value -as [int]
            }
            ($Timeout -gt 0 -and $Timeout -le $MaxConsoleTimeout) | Should be $true
        }
        It "1.8.2 Ensure 'SSH session timeout' is less than or equal to '$MaxSshTimeout' minutes" -skip:(IsSkipped('1.8.2')) {
            $Matchinfo = $config | Select-String -Pattern '^ssh\s+timeout\s+(?<SshTimeout>\d+)$'
            $Timeout = 0
            if ($null -ne $Matchinfo) {
                $Timeout = $Matchinfo.Matches[0].Groups['SshTimeout'].value -as [int]
            }
            ($Timeout -gt 0 -and $Timeout -le $MaxSshTimeout) | Should be $true
        }
        It "1.8.3 Ensure 'HTTP idle timeout' is less than or equal to '$MaxHttpTimeout' minutes" -skip:(IsSkipped('1.8.3')) {
            $Matchinfo = $config | Select-String -Pattern '^http\s+server\s+idle-timeout\s+(?<HttpTimeout>\d+)$'
            $Timeout = 0
            if ($null -ne $Matchinfo) {
                $Timeout = $Matchinfo.Matches[0].Groups['HttpTimeout'].value -as [int]
            }
            ($Timeout -gt 0 -and $Timeout -le $MaxHttpTimeout) | Should be $true
        }
    }
}

Describe "1.9 Management Plane - Clock Rules" {
    Context "Management Plane - Clock Rules" {
        It "1.9.1.1 Ensure 'NTP authentication' is enabled" -skip:(IsSkipped('1.9.1.1')) {
            $Matchinfo = $config | Select-String -Pattern '^ntp authenticate$'
            $Matchinfo | Should not be $null
        }
        It "1.9.1.2 Ensure 'NTP authentication key' is configured correctly" -skip:(IsSkipped('1.9.1.2')) {
            $Matchinfo = $config | Select-String -Pattern '^ntp authentication-key'
            $Matchinfo | Should not be $null
        }
        It "1.9.1.3 Ensure 'trusted NTP server' exists" -skip:(IsSkipped('1.9.1.3')) {
            $Matchinfo = $config | Select-String -Pattern '^ntp\s+server\s+[^\s]+\s+key\s+\d+\s+source\s+.+$'
            $Matchinfo | Should not be $null
        }
        It "1.9.1.3a Ensure 'NTP server' is configured" -skip:(IsSkipped('1.9.1.3a')) {
            # Extra test for NTP configured
            $Matchinfo = $config | Select-String -Pattern '^ntp\s+server\s+[^\s]+\s+source\s+.+$'
            $Matchinfo | Should not be $null
        }
        It "1.9.2 Ensure 'local timezone' is properly configured" -skip:(IsSkipped('1.9.2')) {
            $Matchinfo = $config | Select-String -Pattern '^clock\s+timezone\s+[^\s]+\s+\d+$'
            $Matchinfo | Should not be $null
        }
    }
}

Describe "Management Plane - Logging Rules" {
    Context "Management Plane - Logging Rules" {
        It "1.10.1 Ensure 'logging' is enabled" -skip:(IsSkipped('1.10.1')) {
            $Matchinfo = $config | Select-String -Pattern '^logging\s+enable$'
            $Matchinfo | Should not be $null
        }
        It "1.10.2 Ensure 'logging to Serial console' is disabled" -skip:(IsSkipped('1.10.2')) {
            $Matchinfo = $config | Select-String -Pattern '^logging\s+console'
            $Matchinfo | Should be $null
        }
        It "1.10.3 Ensure 'logging to monitor' is disabled" -skip:(IsSkipped('1.10.3')) {
            $Matchinfo = $config | Select-String -Pattern '^logging\s+monitor'
            $Matchinfo | Should be $null
        }
        It "1.10.4 Ensure 'syslog hosts' is configured correctly" -skip:(IsSkipped('1.10.4')) {
            $Matchinfo = $config | Select-String -Pattern '^logging\s+host\s+[^\s]+\s+[^\s]+'
            $Matchinfo | Should not be $null
        }
        It "1.10.5 Ensure 'logging with the device ID' is configured correctly" -skip:(IsSkipped('1.10.5'))  {
            $Matchinfo = $config | Select-String -Pattern '^logging\s+device-id'
            $Matchinfo | Should not be $null
        }
        It "1.10.6 Ensure 'logging history severity level' is set to greater than or equal to '5'" -skip:(IsSkipped('1.10.6')) {
            $Matchinfo = $config | Select-String -Pattern '^logging\s+history\s+([5-7]|notifications|informational|debugging)'
            $Matchinfo | Should be $null
        }
        It "1.10.7 Ensure 'logging with timestamps' is enabled" -skip:(IsSkipped('1.10.7')) {
            $Matchinfo = $config | Select-String -Pattern '^logging\s+timestamp$'
            $Matchinfo | Should not be $null
        }
        It "1.10.8 Ensure 'logging buffer size' is greater than or equal to '524288' bytes (512kb)" -skip:(IsSkipped('1.10.8')) {
            $Matchinfo = $config | Select-String -Pattern '^logging\s+buffer-size\s+(?<BuffSize>\d+)$'
            $Buffsize = 0
            If ($null -ne $Matchinfo) {
                $Buffsize = $Matchinfo.Matches[0].Groups['BuffSize'].value -as [int]
            }
            $Buffsize | Should not BeLessThan 524288
        }
        It "1.10.9 Ensure 'logging buffered severity level' is greater than or equal to '3'" -skip:(IsSkipped('1.10.9')) {
            $Matchinfo = $config | Select-String -Pattern '^logging\s+buffered\s+(?!=[0-2]|emergencies|alerts|critical)'
            $Matchinfo | Should not be $null
        }
        It "1.10.10 Ensure 'logging trap severity level' is greater than or equal to '5'" -skip:(IsSkipped('1.10.10')) {
            $Matchinfo = $config | Select-String -Pattern '^logging\s+trap\s+([5-7]|notifications|informational|debugging)'
            $Matchinfo | Should not be $null
        }
        It "1.10.11 Ensure email logging is configured for critical to emergency" -skip:(IsSkipped('1.10.11')) {
            $Matchinfo = $config | Select-String -Pattern '^logging\s+mail\s+([0-2]|emergencies|alerts|critical)'
            $Matchinfo | Should not be $null
        }
    }
}

Describe "1.11 Management Plane - SNMP Rules" {
    Context "Management Plane - SNMP Rules" {
        It "1.11.1 Ensure 'snmp-server group' is set to 'v3 priv'" -skip:(IsSkipped('1.11.1')) {
            #Note that it seems additional space before the carriage return is not truncated
            #If you need to match to the end of string use \s*$ to end the patter
            $Matchinfo = $config | Select-String -Pattern '^snmp-server\s+group\s+[^\s]+\s+v3\s+priv\s*$'
            $Matchinfo | Should not be $null
        }
        It "1.11.2 Ensure 'snmp-server user' is set to 'v3 auth SHA' (aes256 encryption)" -skip:(IsSkipped('1.11.2')) {
            $Matchinfo = $config | Select-String -Pattern '^snmp-server\s+user\s+[^\s]+\s+[^\s]+\s+v3\s+engineID\s+[^\s]+\s+encrypted\s+auth\s+sha\s+[^\s]+\s+priv\s+aes\s+256\s+[^\s]+\s*$'
            $Matchinfo | Should not be $null
        }
        It "1.11.2a Ensure 'snmp-server user' is set to 'v3 auth SHA' (aes128 encryption)" -skip:(IsSkipped('1.11.2a')) {
            $Matchinfo = $config | Select-String -Pattern '^snmp-server\s+user\s+[^\s]+\s+[^\s]+\s+v3\s+engineID\s+[^\s]+\s+encrypted\s+auth\s+sha\s+[^\s]+\s+priv\s+aes\s+128\s+[^\s]+\s*$'
            $Matchinfo | Should not be $null
        }
        It "1.11.3 Ensure 'snmp-server host' is set to 'version 3'" -skip:(IsSkipped('1.11.3')) {
            $Matchinfo = $config | Select-String -Pattern '^snmp-server\s+host\s+[^\s]+\s+[^\s]+\s+version\s+3\s+[^\s]+'
            $Matchinfo | Should not be $null
        }
        It "1.11.4 Ensure 'SNMP traps' is enabled" -skip:(IsSkipped('1.11.4')) {
            $Matchinfo = $config | Select-String -Pattern '^snmp-server\s+enable\s+traps'
            $Matchinfo | Should not be $null
        }
        It "1.11.5 Ensure 'SNMP community string' is not the default string" -skip:(IsSkipped('1.11.5')) {
            $Matchinfo = $config | Select-String -Pattern '^groupname\s+:\s+(?<GroupName>[^\s]+)\s+security\s+model:'
            $CommandExecuted = $Matchinfo.count -gt 0
            if ($CommandExecuted) {
                $FoundPublic = $Matchinfo.line -match 'public'
            }
            ($CommandExecuted -and ($FoundPublic.count -eq 0)) | Should be $true
        }
    }
}

Describe "2.1 Control Plane - Routing Protocol Authentication" {
    Context "Control Plane - Routing Protocol Authentication" {
        It "2.1.1 Ensure 'RIP authentication' is enabled" -skip:(IsSkipped('2.1.1')) {
            $Matchinfo = $config | Select-String -Pattern '^router\s+rip'
            $NoRip = $Matchinfo.count -eq 0
            $RipAuth = $false
            if (-not $NoRip) {
                $Matchinfo = $config | Select-String -Pattern 'rip\s+authentication\s+key'
                $RipAuth = $null -ne $Matchinfo
            }
            $NoRip -or $RipAuth | Should be $true
        }
        It "2.1.2 Ensure 'OSPF authentication' is enabled" -skip:(IsSkipped('2.1.2')) {
            $Matchinfo = $config | Select-String -Pattern '^router\s+ospf'
            $NoOspf = $Matchinfo.count -eq 0
            $OspfAuth = $false
            if (-not $NoOspf) {
                $Matchinfo = $config | Select-String -Pattern 'ospf message-digest-key'
                $OspfAuth = $null -ne $Matchinfo
            }
            $NoOspf -or $OspfAuth | Should be $true
        }
        It "2.1.3 Ensure 'EIGRP authentication' is enabled" -skip:(IsSkipped('2.1.3')) {
            $Matchinfo = $config | Select-String -Pattern '^router\s+eigrp'
            $NoEigrp = $Matchinfo.count -eq 0
            $EigrpAuth = $false
            if (-not $NoEigrp) {
                $Matchinfo = $config | Select-String -Pattern 'authentication\s+key\s+eigrp'
                $EigrpAuth = $null -ne $Matchinfo
            }
            $NoEigrp -or $EigrpAuth | Should be $true
        }
        It "2.1.4 Ensure 'BGP authentication' is enabled" -skip:(IsSkipped('2.1.4')) {
            $Matchinfo = $config | Select-String -Pattern '^router\s+bgp'
            $NoBgp = $Matchinfo.count -eq 0
            $BgpAuth = $false
            if (-not $NoEigrp) {
                $Matchinfo = $config | Select-String -Pattern 'neighbor\s+[^\s]+\s+password'
                $BgpAuth = $null -ne $Matchinfo
            }
            $NoBgp -or $BgpAuth | Should be $true
        }
    }
}

Describe "2.2 Control Plane - General" {
    Context "Control Plane - General" {
        It "2.2 Ensure 'noproxyarp' is enabled for untrusted interfaces" -skip:(IsSkipped('2.2')) {
            if ($null -ne $Untrusted) {
                $Matchinfo = $config | Select-String -Pattern '^sysopt\s+noproxyarp\s+(?<IfName>[^\s]+)'
                $NoProxyArpInt = @()
                if ($null -ne $Matchinfo) {
                    $NoProxyArpInt = $Matchinfo | ForEach-Object {$_.Matches[0].Groups['IfName'].value}
                }

                $cmp = Compare-Object -ReferenceObject $Untrusted -DifferenceObject $NoProxyArpInt
                $IsProperlyConfigured = ($null -eq $cmp) -or ($null -eq ($cmp | where-object {$_.sideindicator -eq '<='}))
            }
            else {
                $IsProperlyConfigured = $false
            }

            $IsProperlyConfigured | Should be $true
        }
        It "2.3 Ensure 'DNS Guard' is enabled" -skip:(IsSkipped('2.3')) {
            $Matchinfo = $config | Select-String -Pattern '^dns-guard'
            $Matchinfo | Should not be $null
        }
        It "2.4 Ensure DHCP services are disabled for untrusted interfaces" -skip:(IsSkipped('2.4')) {
            $Matchinfo = $config | Select-String -Pattern '^dhcpd\s+enable\s+(?<IfName>[^\s]+)'
            $NoDHCP = $Matchinfo.count -eq 0
            if (-not $NoDHCP) {
                if ($null -eq $Untrusted) {
                    $TrustedDHCP = $false
                }
                else {
                    $DhcpInt = $Matchinfo | ForEach-Object {$_.Matches[0].Groups['IfName'].value}
                    $cmp = Compare-Object -ExcludeDifferent -IncludeEqual -ReferenceObject $Untrusted -DifferenceObject $DhcpInt
                    $TrustedDHCP  =  $cmp.Count -eq 0
                }
            }
            $NoDHCP -or $TrustedDHCP | Should be $true
        }
        It "2.4a Ensure DHCP relay services are disabled for untrusted interfaces" -skip:(IsSkipped('2.4a')) {
            $Matchinfo = $config | Select-String -Pattern '^dhcprelay\s+enable\s+(?<IfName>[^\s]+)'
            $NoDHCP = $Matchinfo.count -eq 0
            if (-not $NoDHCP) {
                if ($null -eq $Untrusted) {
                    $TrustedDHCP = $false
                }
                else {
                    $DhcpInt = $Matchinfo | ForEach-Object {$_.Matches[0].Groups['IfName'].value}
                    $cmp = Compare-Object -ExcludeDifferent -IncludeEqual -ReferenceObject $Untrusted -DifferenceObject $DhcpInt
                    $TrustedDHCP = $null -eq $cmp
                }
            }
            $NoDHCP -or $TrustedDHCP | Should be $true
        }

        It "2.5 Ensure ICMP is restricted for untrusted interfaces" -skip:(IsSkipped('2.5')) {
            $Matchinfo = $config | Select-String -Pattern '^icmp\s+deny\s+any\s+(?<IfName>[^\s]+)'
            $DenyICMP = $Matchinfo.count -gt 0
            $IsProperlyConfigured = $false
            $NoUntrustedEdgeCase = $false
            if ($null -ne $Untrusted) {
                if ($DenyICMP) {
                    $DenyICMPInt = $Matchinfo | ForEach-Object {$_.Matches[0].Groups['IfName'].value}
                    $cmp = Compare-Object -ExcludeDifferent -IncludeEqual -ReferenceObject $Untrusted -DifferenceObject $DenyICMPInt
                    $IsProperlyConfigured = $cmp.count -eq $Untrusted.Count
                }
                else {
                    $NoUntrustedEdgeCase = ($Untrusted.count -eq 0) -and (-not $DenyICMP)
                }
            }

            $IsProperlyConfigured -or $NoUntrustedEdgeCase | Should be $true
        }
    }
}

Describe "Data Plane - General" {
    Context "Data Plane - General" {
        It "3.1 Ensure DNS services are configured correctly" -skip:(IsSkipped('3.1')) {
            $Matchinfo = $config | Select-String -Pattern '^dns\s+domain-lookup\s+(?<IfName>[^\s]+)\s*$'
            $DomainLookupConfigured = $Null -ne $Matchinfo
            $NameServerConfigured = $false
            if ($DomainLookupConfigured) {
                $IfNames = $Matchinfo | ForEach-Object {$_.Matches[0].Groups['IfName'].value}
                $Matchinfo = $config | Select-String -Pattern ('name-server\s+[^\s]+\s+(?:{0})\s*$' -f ($IfNames -join '|'))
                $NameServerConfigured = $Matchinfo.count -eq $IfNames.count
            }
            $DomainLookupConfigured -and $NameServerConfigured | Should be $true
        }

        It "3.2 Ensure intrusion prevention is enabled for untrusted interfaces" -skip:(IsSkipped('3.2')) {
            $Matchinfo = $config | Select-String -Pattern '^ip\s+audit\s+interface\s+(?<IfName>[^\s]+)'
            $IpsProtected = $Matchinfo.count -gt 0
            $IsProperlyConfigured = $false
            $NoUntrustedEdgeCase = $false
            if ($null -ne $Untrusted) {
                if ($IpsProtected) {
                    $DenyICMPInt = $Matchinfo | ForEach-Object {$_.Matches[0].Groups['IfName'].value}
                    $cmp = Compare-Object -ExcludeDifferent -IncludeEqual -ReferenceObject $Untrusted -DifferenceObject $DenyICMPInt
                    $IsProperlyConfigured = $cmp.count -eq $Untrusted.Count
                }
                else {
                    $NoUntrustedEdgeCase = ($Untrusted.count -eq 0) -and (-not $IpsProtected)
                }
            }

            $IsProperlyConfigured -or $NoUntrustedEdgeCase | Should be $true
        }

        It "3.3 Ensure packet fragments are restricted for untrusted interfaces" -skip:(IsSkipped('3.3')) {
            $AllInterfaces = ($config | Select-String -Pattern '^fragment\s+chain\s+1\s*$' -Quiet) -as [bool]
            If (-not $AllInterfaces) {
                $Matchinfo = $config | Select-String -Pattern '^fragment\s+chain\s+1\s+(?<IfName>[^\s]+)'
                $FragProtected = $Matchinfo.count -gt 0
                $IsProperlyConfigured = $false
                $NoUntrustedEdgeCase = $false
                if ($null -ne $Untrusted) {
                    if ($FragProtected) {
                        $FragInt = $Matchinfo | ForEach-Object {$_.Matches[0].Groups['IfName'].value}
                        $cmp = Compare-Object -ExcludeDifferent -IncludeEqual -ReferenceObject $Untrusted -DifferenceObject $FragInt
                        $IsProperlyConfigured = $cmp.count -eq $Untrusted.Count
                    }
                    else {
                        $NoUntrustedEdgeCase = ($Untrusted.count -eq 0) -and (-not $FragProtected)
                    }
                }
            }

            $AllInterfaces -or $IsProperlyConfigured -or $NoUntrustedEdgeCase | Should be $true
        }
    }
}
