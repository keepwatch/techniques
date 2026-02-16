# TRR Coverage Analysis Report

## 1. Excluded Techniques (Too Common)
Techniques with > 60 procedures were excluded from the target list as they are likely too common/undetectable.

| Technique ID | Name | Procedure Count |
|---|---|---|
| T1105 | Ingress Tool Transfer | 498 |
| T1071.001 | Web Protocols | 406 |
| T1082 | System Information Discovery | 403 |
| T1059.003 | Windows Command Shell | 372 |
| T1083 | File and Directory Discovery | 355 |
| T1140 | Deobfuscate/Decode Files or Information | 325 |
| T1057 | Process Discovery | 304 |
| T1070.004 | File Deletion | 296 |
| T1016 | System Network Configuration Discovery | 277 |
| T1547.001 | Registry Run Keys / Startup Folder | 252 |
| T1033 | System Owner/User Discovery | 231 |
| T1059.001 | PowerShell | 223 |
| T1027.013 | Encrypted/Encoded File | 221 |
| T1005 | Data from Local System | 218 |
| T1106 | Native API | 211 |
| T1036.005 | Match Legitimate Resource Name or Location | 202 |
| T1041 | Exfiltration Over C2 Channel | 191 |
| T1204.002 | Malicious File | 185 |
| T1053.005 | Scheduled Task | 184 |
| T1573.001 | Symmetric Cryptography | 177 |
| T1112 | Modify Registry | 170 |
| T1113 | Screen Capture | 166 |
| T1056.001 | Keylogging | 152 |
| T1027 | Obfuscated Files or Information | 152 |
| T1566.001 | Spearphishing Attachment | 141 |
| T1047 | Windows Management Instrumentation | 138 |
| T1543.003 | Windows Service | 138 |
| T1518.001 | Security Software Discovery | 135 |
| T1059.005 | Visual Basic | 127 |
| T1074.001 | Local Data Staging | 126 |
| T1132.001 | Standard Encoding | 120 |
| T1012 | Query Registry | 118 |
| T1562.001 | Disable or Modify Tools | 110 |
| T1095 | Non-Application Layer Protocol | 106 |
| T1218.011 | Rundll32 | 103 |
| T1574.001 | DLL | 103 |
| T1588.002 | Tool | 103 |
| T1027.002 | Software Packing | 102 |
| T1018 | Remote System Discovery | 99 |
| T1680 | Local Storage Discovery | 99 |
| T1049 | System Network Connections Discovery | 95 |
| T1124 | System Time Discovery | 93 |
| T1036.004 | Masquerade Task or Service | 90 |
| T1573.002 | Asymmetric Cryptography | 89 |
| T1555.003 | Credentials from Web Browsers | 87 |
| T1553.002 | Code Signing | 85 |
| T1204.001 | Malicious Link | 83 |
| T1055 | Process Injection | 82 |
| T1486 | Data Encrypted for Impact | 82 |
| T1566.002 | Spearphishing Link | 80 |
| T1560.001 | Archive via Utility | 78 |
| T1135 | Network Share Discovery | 77 |
| T1003.001 | LSASS Memory | 75 |
| T1090 | Proxy | 72 |
| T1046 | Network Service Discovery | 71 |
| T1569.002 | Service Execution | 71 |
| T1119 | Automated Collection | 69 |
| T1190 | Exploit Public-Facing Application | 69 |
| T1007 | System Service Discovery | 67 |
| T1497.001 | System Checks | 66 |
| T1055.001 | Dynamic-link Library Injection | 66 |
| T1027.010 | Command Obfuscation | 65 |
| T1021.002 | SMB/Windows Admin Shares | 64 |
| T1087.001 | Local Account | 63 |
| T1059.007 | JavaScript | 62 |
| T1505.003 | Web Shell | 62 |
| T1548.002 | Bypass User Account Control | 61 |

## 2. Coverage Analysis

**Overall Coverage:** 25 / 1605 (1.56%)

### Gaps by Tactic
| Tactic | Total Target Pairs | Gaps | Coverage %
|---|---|---|---|
| Defense Evasion | 458 | 451 | 1.53% |
| Persistence | 294 | 284 | 3.40% |
| Credential Access | 210 | 205 | 2.38% |
| Privilege Escalation | 208 | 198 | 4.81% |
| Command And Control | 153 | 153 | 0.00% |
| Impact | 132 | 131 | 0.76% |
| Discovery | 116 | 116 | 0.00% |
| Collection | 95 | 94 | 1.05% |
| Execution | 88 | 88 | 0.00% |
| Initial Access | 86 | 85 | 1.16% |
| Exfiltration | 73 | 73 | 0.00% |
| Lateral Movement | 66 | 65 | 1.52% |
| Resource Development | 46 | 46 | 0.00% |
| Reconnaissance | 45 | 45 | 0.00% |

### Platform Coverage (Least Covered First)
| Platform | Total Target Pairs | Gaps | Coverage %
|---|---|---|---|
| ESXi | 93 | 93 | 0.00% |
| macOS | 304 | 304 | 0.00% |
| Linux | 304 | 304 | 0.00% |
| PRE | 91 | 91 | 0.00% |
| Network Devices | 79 | 79 | 0.00% |
| Containers | 44 | 44 | 0.00% |
| Office Suite | 76 | 75 | 1.32% |
| IaaS | 95 | 92 | 3.16% |
| Windows | 406 | 392 | 3.45% |
| SaaS | 65 | 61 | 6.15% |
| Identity Provider | 48 | 45 | 6.25% |

## 3. Included Technique/Platform Pairs
List of techniques considered for coverage (Exploded by Platform).

| Technique ID | Platform | Covered? |
|---|---|---|
| T1001 | ESXi | No |
| T1001 | Linux | No |
| T1001 | Windows | No |
| T1001 | macOS | No |
| T1001.001 | ESXi | No |
| T1001.001 | Linux | No |
| T1001.001 | Windows | No |
| T1001.001 | macOS | No |
| T1001.002 | ESXi | No |
| T1001.002 | Linux | No |
| T1001.002 | Windows | No |
| T1001.002 | macOS | No |
| T1001.003 | ESXi | No |
| T1001.003 | Linux | No |
| T1001.003 | Windows | No |
| T1001.003 | macOS | No |
| T1003 | Linux | No |
| T1003 | Windows | No |
| T1003 | macOS | No |
| T1003.002 | Windows | No |
| T1003.003 | Windows | Yes |
| T1003.004 | Windows | No |
| T1003.005 | Linux | No |
| T1003.005 | Windows | No |
| T1003.006 | Windows | Yes |
| T1003.007 | Linux | No |
| T1003.008 | Linux | No |
| T1006 | Network Devices | No |
| T1006 | Windows | No |
| T1008 | ESXi | No |
| T1008 | Linux | No |
| T1008 | Windows | No |
| T1008 | macOS | No |
| T1010 | Linux | No |
| T1010 | Windows | No |
| T1010 | macOS | No |
| T1011 | Linux | No |
| T1011 | Windows | No |
| T1011 | macOS | No |
| T1011.001 | Linux | No |
| T1011.001 | Windows | No |
| T1011.001 | macOS | No |
| T1014 | Linux | No |
| T1014 | Windows | No |
| T1014 | macOS | No |
| T1016.001 | ESXi | No |
| T1016.001 | Linux | No |
| T1016.001 | Windows | No |
| T1016.001 | macOS | No |
| T1016.002 | Linux | No |
| T1016.002 | Windows | No |
| T1016.002 | macOS | No |
| T1020 | Linux | No |
| T1020 | Network Devices | No |
| T1020 | Windows | No |
| T1020 | macOS | No |
| T1020.001 | IaaS | No |
| T1020.001 | Network Devices | No |
| T1021 | ESXi | No |
| T1021 | IaaS | No |
| T1021 | Linux | No |
| T1021 | Windows | No |
| T1021 | macOS | No |
| T1021.001 | Windows | No |
| T1021.003 | Windows | No |
| T1021.004 | ESXi | No |
| T1021.004 | Linux | No |
| T1021.004 | macOS | No |
| T1021.005 | Linux | No |
| T1021.005 | Windows | No |
| T1021.005 | macOS | No |
| T1021.006 | Windows | No |
| T1021.007 | IaaS | No |
| T1021.007 | Identity Provider | No |
| T1021.007 | Office Suite | No |
| T1021.007 | SaaS | No |
| T1021.008 | IaaS | No |
| T1025 | Linux | No |
| T1025 | Windows | No |
| T1025 | macOS | No |
| T1027.001 | Linux | No |
| T1027.001 | Windows | No |
| T1027.001 | macOS | No |
| T1027.003 | Linux | No |
| T1027.003 | Windows | No |
| T1027.003 | macOS | No |
| T1027.004 | Linux | No |
| T1027.004 | Windows | No |
| T1027.004 | macOS | No |
| T1027.005 | Linux | No |
| T1027.005 | Windows | No |
| T1027.005 | macOS | No |
| T1027.006 | Linux | No |
| T1027.006 | Windows | No |
| T1027.006 | macOS | No |
| T1027.007 | Windows | No |
| T1027.008 | Linux | No |
| T1027.008 | Network Devices | No |
| T1027.008 | Windows | No |
| T1027.008 | macOS | No |
| T1027.009 | Linux | No |
| T1027.009 | Windows | No |
| T1027.009 | macOS | No |
| T1027.011 | Linux | No |
| T1027.011 | Windows | No |
| T1027.012 | Windows | No |
| T1027.014 | Linux | No |
| T1027.014 | Windows | No |
| T1027.014 | macOS | No |
| T1027.015 | Linux | No |
| T1027.015 | Windows | No |
| T1027.015 | macOS | No |
| T1027.016 | Linux | No |
| T1027.016 | Windows | No |
| T1027.016 | macOS | No |
| T1027.017 | Linux | No |
| T1027.017 | Windows | No |
| T1027.017 | macOS | No |
| T1029 | Linux | No |
| T1029 | Windows | No |
| T1029 | macOS | No |
| T1030 | ESXi | No |
| T1030 | Linux | No |
| T1030 | Windows | No |
| T1030 | macOS | No |
| T1036 | Containers | No |
| T1036 | ESXi | No |
| T1036 | Linux | No |
| T1036 | Windows | No |
| T1036 | macOS | No |
| T1036.001 | Windows | No |
| T1036.001 | macOS | No |
| T1036.002 | Linux | No |
| T1036.002 | Windows | No |
| T1036.002 | macOS | No |
| T1036.003 | Linux | No |
| T1036.003 | Windows | No |
| T1036.003 | macOS | No |
| T1036.006 | Linux | No |
| T1036.006 | macOS | No |
| T1036.007 | Windows | No |
| T1036.008 | Linux | No |
| T1036.008 | Windows | No |
| T1036.008 | macOS | No |
| T1036.009 | Linux | No |
| T1036.009 | macOS | No |
| T1036.010 | Containers | No |
| T1036.010 | IaaS | No |
| T1036.010 | Identity Provider | No |
| T1036.010 | Linux | No |
| T1036.010 | Office Suite | No |
| T1036.010 | SaaS | No |
| T1036.010 | Windows | No |
| T1036.010 | macOS | No |
| T1036.011 | Linux | No |
| T1036.012 | Linux | No |
| T1036.012 | Windows | No |
| T1036.012 | macOS | No |
| T1037 | ESXi | No |
| T1037 | Linux | No |
| T1037 | Network Devices | No |
| T1037 | Windows | No |
| T1037 | macOS | No |
| T1037.001 | Windows | No |
| T1037.002 | macOS | No |
| T1037.003 | Windows | No |
| T1037.004 | ESXi | No |
| T1037.004 | Linux | No |
| T1037.004 | Network Devices | No |
| T1037.004 | macOS | No |
| T1037.005 | macOS | No |
| T1039 | Linux | No |
| T1039 | Windows | No |
| T1039 | macOS | No |
| T1040 | IaaS | No |
| T1040 | Linux | No |
| T1040 | Network Devices | No |
| T1040 | Windows | No |
| T1040 | macOS | No |
| T1048 | ESXi | No |
| T1048 | IaaS | No |
| T1048 | Linux | No |
| T1048 | Network Devices | No |
| T1048 | Office Suite | No |
| T1048 | SaaS | No |
| T1048 | Windows | No |
| T1048 | macOS | No |
| T1048.001 | ESXi | No |
| T1048.001 | Linux | No |
| T1048.001 | Windows | No |
| T1048.001 | macOS | No |
| T1048.002 | ESXi | No |
| T1048.002 | Linux | No |
| T1048.002 | Windows | No |
| T1048.002 | macOS | No |
| T1048.003 | ESXi | No |
| T1048.003 | Linux | No |
| T1048.003 | Network Devices | No |
| T1048.003 | Windows | No |
| T1048.003 | macOS | No |
| T1052 | Linux | No |
| T1052 | Windows | No |
| T1052 | macOS | No |
| T1052.001 | Linux | No |
| T1052.001 | Windows | No |
| T1052.001 | macOS | No |
| T1053 | Containers | No |
| T1053 | ESXi | No |
| T1053 | Linux | No |
| T1053 | Windows | No |
| T1053 | macOS | No |
| T1053.002 | Linux | No |
| T1053.002 | Windows | No |
| T1053.002 | macOS | No |
| T1053.003 | ESXi | No |
| T1053.003 | Linux | No |
| T1053.003 | macOS | No |
| T1053.006 | Linux | No |
| T1053.007 | Containers | No |
| T1055.002 | Windows | Yes |
| T1055.003 | Windows | No |
| T1055.004 | Windows | Yes |
| T1055.005 | Windows | Yes |
| T1055.008 | Linux | No |
| T1055.009 | Linux | No |
| T1055.011 | Windows | No |
| T1055.012 | Windows | No |
| T1055.013 | Windows | No |
| T1055.014 | Linux | No |
| T1055.015 | Windows | No |
| T1056 | Linux | No |
| T1056 | Network Devices | No |
| T1056 | Windows | No |
| T1056 | macOS | No |
| T1056.002 | Linux | No |
| T1056.002 | Windows | No |
| T1056.002 | macOS | No |
| T1056.003 | Linux | No |
| T1056.003 | Windows | No |
| T1056.003 | macOS | No |
| T1056.004 | Linux | No |
| T1056.004 | Windows | No |
| T1056.004 | macOS | No |
| T1059 | ESXi | No |
| T1059 | IaaS | No |
| T1059 | Identity Provider | No |
| T1059 | Linux | No |
| T1059 | Network Devices | No |
| T1059 | Office Suite | No |
| T1059 | Windows | No |
| T1059 | macOS | No |
| T1059.002 | macOS | No |
| T1059.004 | ESXi | No |
| T1059.004 | Linux | No |
| T1059.004 | Network Devices | No |
| T1059.004 | macOS | No |
| T1059.006 | ESXi | No |
| T1059.006 | Linux | No |
| T1059.006 | Windows | No |
| T1059.006 | macOS | No |
| T1059.008 | Network Devices | No |
| T1059.009 | IaaS | No |
| T1059.009 | Identity Provider | No |
| T1059.009 | Office Suite | No |
| T1059.009 | SaaS | No |
| T1059.010 | Windows | No |
| T1059.011 | Linux | No |
| T1059.011 | Network Devices | No |
| T1059.011 | Windows | No |
| T1059.011 | macOS | No |
| T1059.012 | ESXi | No |
| T1059.013 | Containers | No |
| T1068 | Containers | No |
| T1068 | Linux | No |
| T1068 | Windows | No |
| T1068 | macOS | No |
| T1069 | Containers | No |
| T1069 | IaaS | No |
| T1069 | Identity Provider | No |
| T1069 | Linux | No |
| T1069 | Office Suite | No |
| T1069 | SaaS | No |
| T1069 | Windows | No |
| T1069 | macOS | No |
| T1069.001 | Linux | No |
| T1069.001 | Windows | No |
| T1069.001 | macOS | No |
| T1069.002 | Linux | No |
| T1069.002 | Windows | No |
| T1069.002 | macOS | No |
| T1069.003 | IaaS | No |
| T1069.003 | Identity Provider | No |
| T1069.003 | Office Suite | No |
| T1069.003 | SaaS | No |
| T1070 | Containers | No |
| T1070 | ESXi | No |
| T1070 | Linux | No |
| T1070 | Network Devices | No |
| T1070 | Office Suite | No |
| T1070 | Windows | No |
| T1070 | macOS | No |
| T1070.001 | Windows | Yes |
| T1070.002 | Linux | No |
| T1070.002 | macOS | No |
| T1070.003 | ESXi | No |
| T1070.003 | Linux | No |
| T1070.003 | Network Devices | No |
| T1070.003 | Windows | No |
| T1070.003 | macOS | No |
| T1070.005 | Windows | No |
| T1070.006 | ESXi | No |
| T1070.006 | Linux | No |
| T1070.006 | Windows | No |
| T1070.006 | macOS | No |
| T1070.007 | Linux | No |
| T1070.007 | Network Devices | No |
| T1070.007 | Windows | No |
| T1070.007 | macOS | No |
| T1070.008 | Linux | No |
| T1070.008 | Office Suite | No |
| T1070.008 | Windows | No |
| T1070.008 | macOS | No |
| T1070.009 | ESXi | No |
| T1070.009 | Linux | No |
| T1070.009 | Windows | No |
| T1070.009 | macOS | No |
| T1070.010 | Linux | No |
| T1070.010 | Network Devices | No |
| T1070.010 | Windows | No |
| T1070.010 | macOS | No |
| T1071 | ESXi | No |
| T1071 | Linux | No |
| T1071 | Network Devices | No |
| T1071 | Windows | No |
| T1071 | macOS | No |
| T1071.002 | ESXi | No |
| T1071.002 | Linux | No |
| T1071.002 | Network Devices | No |
| T1071.002 | Windows | No |
| T1071.002 | macOS | No |
| T1071.003 | Linux | No |
| T1071.003 | Network Devices | No |
| T1071.003 | Windows | No |
| T1071.003 | macOS | No |
| T1071.004 | ESXi | No |
| T1071.004 | Linux | No |
| T1071.004 | Network Devices | No |
| T1071.004 | Windows | No |
| T1071.004 | macOS | No |
| T1071.005 | Linux | No |
| T1071.005 | Network Devices | No |
| T1071.005 | Windows | No |
| T1071.005 | macOS | No |
| T1072 | Linux | No |
| T1072 | Network Devices | No |
| T1072 | SaaS | No |
| T1072 | Windows | No |
| T1072 | macOS | No |
| T1074 | ESXi | No |
| T1074 | IaaS | No |
| T1074 | Linux | No |
| T1074 | Windows | No |
| T1074 | macOS | No |
| T1074.002 | ESXi | No |
| T1074.002 | IaaS | No |
| T1074.002 | Linux | No |
| T1074.002 | Windows | No |
| T1074.002 | macOS | No |
| T1078 | Containers | No |
| T1078 | ESXi | No |
| T1078 | IaaS | No |
| T1078 | Identity Provider | No |
| T1078 | Linux | No |
| T1078 | Network Devices | No |
| T1078 | Office Suite | No |
| T1078 | SaaS | No |
| T1078 | Windows | No |
| T1078 | macOS | No |
| T1078.001 | Containers | No |
| T1078.001 | ESXi | No |
| T1078.001 | IaaS | No |
| T1078.001 | Identity Provider | No |
| T1078.001 | Linux | No |
| T1078.001 | Network Devices | No |
| T1078.001 | Office Suite | No |
| T1078.001 | SaaS | No |
| T1078.001 | Windows | No |
| T1078.001 | macOS | No |
| T1078.002 | ESXi | No |
| T1078.002 | Linux | No |
| T1078.002 | Windows | No |
| T1078.002 | macOS | No |
| T1078.003 | Containers | No |
| T1078.003 | ESXi | No |
| T1078.003 | Linux | No |
| T1078.003 | Network Devices | No |
| T1078.003 | Windows | No |
| T1078.003 | macOS | No |
| T1078.004 | IaaS | No |
| T1078.004 | Identity Provider | No |
| T1078.004 | Office Suite | No |
| T1078.004 | SaaS | No |
| T1080 | Linux | No |
| T1080 | Office Suite | No |
| T1080 | SaaS | No |
| T1080 | Windows | No |
| T1080 | macOS | No |
| T1087 | ESXi | No |
| T1087 | IaaS | No |
| T1087 | Identity Provider | No |
| T1087 | Linux | No |
| T1087 | Office Suite | No |
| T1087 | SaaS | No |
| T1087 | Windows | No |
| T1087 | macOS | No |
| T1087.002 | Linux | No |
| T1087.002 | Windows | No |
| T1087.002 | macOS | No |
| T1087.003 | Office Suite | No |
| T1087.003 | Windows | No |
| T1087.004 | IaaS | No |
| T1087.004 | Identity Provider | No |
| T1087.004 | Office Suite | No |
| T1087.004 | SaaS | No |
| T1090.001 | ESXi | No |
| T1090.001 | Linux | No |
| T1090.001 | Network Devices | No |
| T1090.001 | Windows | No |
| T1090.001 | macOS | No |
| T1090.002 | ESXi | No |
| T1090.002 | Linux | No |
| T1090.002 | Network Devices | No |
| T1090.002 | Windows | No |
| T1090.002 | macOS | No |
| T1090.003 | ESXi | No |
| T1090.003 | Linux | No |
| T1090.003 | Network Devices | No |
| T1090.003 | Windows | No |
| T1090.003 | macOS | No |
| T1090.004 | ESXi | No |
| T1090.004 | Linux | No |
| T1090.004 | Windows | No |
| T1090.004 | macOS | No |
| T1091 | Windows | No |
| T1092 | Linux | No |
| T1092 | Windows | No |
| T1092 | macOS | No |
| T1098 | Containers | No |
| T1098 | ESXi | No |
| T1098 | IaaS | No |
| T1098 | Identity Provider | No |
| T1098 | Linux | No |
| T1098 | Network Devices | No |
| T1098 | Office Suite | No |
| T1098 | SaaS | No |
| T1098 | Windows | No |
| T1098 | macOS | No |
| T1098.001 | IaaS | Yes |
| T1098.001 | Identity Provider | Yes |
| T1098.001 | SaaS | Yes |
| T1098.002 | Office Suite | No |
| T1098.002 | Windows | No |
| T1098.003 | IaaS | Yes |
| T1098.003 | Identity Provider | Yes |
| T1098.003 | Office Suite | No |
| T1098.003 | SaaS | Yes |
| T1098.004 | ESXi | No |
| T1098.004 | IaaS | No |
| T1098.004 | Linux | No |
| T1098.004 | Network Devices | No |
| T1098.004 | macOS | No |
| T1098.005 | Identity Provider | No |
| T1098.005 | Windows | No |
| T1098.006 | Containers | No |
| T1098.007 | Linux | No |
| T1098.007 | Windows | No |
| T1098.007 | macOS | No |
| T1102 | ESXi | No |
| T1102 | Linux | No |
| T1102 | Windows | No |
| T1102 | macOS | No |
| T1102.001 | ESXi | No |
| T1102.001 | Linux | No |
| T1102.001 | Windows | No |
| T1102.001 | macOS | No |
| T1102.002 | ESXi | No |
| T1102.002 | Linux | No |
| T1102.002 | Windows | No |
| T1102.002 | macOS | No |
| T1102.003 | ESXi | No |
| T1102.003 | Linux | No |
| T1102.003 | Windows | No |
| T1102.003 | macOS | No |
| T1104 | ESXi | No |
| T1104 | Linux | No |
| T1104 | Windows | No |
| T1104 | macOS | No |
| T1110 | Containers | No |
| T1110 | ESXi | No |
| T1110 | IaaS | No |
| T1110 | Identity Provider | No |
| T1110 | Linux | No |
| T1110 | Network Devices | No |
| T1110 | Office Suite | No |
| T1110 | SaaS | No |
| T1110 | Windows | No |
| T1110 | macOS | No |
| T1110.001 | Containers | No |
| T1110.001 | ESXi | No |
| T1110.001 | IaaS | No |
| T1110.001 | Identity Provider | No |
| T1110.001 | Linux | No |
| T1110.001 | Network Devices | No |
| T1110.001 | Office Suite | No |
| T1110.001 | SaaS | No |
| T1110.001 | Windows | No |
| T1110.001 | macOS | No |
| T1110.002 | Identity Provider | No |
| T1110.002 | Linux | No |
| T1110.002 | Network Devices | No |
| T1110.002 | Office Suite | No |
| T1110.002 | Windows | No |
| T1110.002 | macOS | No |
| T1110.003 | Containers | No |
| T1110.003 | ESXi | No |
| T1110.003 | IaaS | No |
| T1110.003 | Identity Provider | No |
| T1110.003 | Linux | No |
| T1110.003 | Network Devices | No |
| T1110.003 | Office Suite | No |
| T1110.003 | SaaS | No |
| T1110.003 | Windows | No |
| T1110.003 | macOS | No |
| T1110.004 | Containers | No |
| T1110.004 | ESXi | No |
| T1110.004 | IaaS | No |
| T1110.004 | Identity Provider | No |
| T1110.004 | Linux | No |
| T1110.004 | Network Devices | No |
| T1110.004 | Office Suite | No |
| T1110.004 | SaaS | No |
| T1110.004 | Windows | No |
| T1110.004 | macOS | No |
| T1111 | Linux | No |
| T1111 | Windows | No |
| T1111 | macOS | No |
| T1114 | Linux | No |
| T1114 | Office Suite | No |
| T1114 | Windows | No |
| T1114 | macOS | No |
| T1114.001 | Windows | No |
| T1114.002 | Office Suite | Yes |
| T1114.002 | Windows | No |
| T1114.003 | Linux | No |
| T1114.003 | Office Suite | No |
| T1114.003 | Windows | No |
| T1114.003 | macOS | No |
| T1115 | Linux | No |
| T1115 | Windows | No |
| T1115 | macOS | No |
| T1120 | Linux | No |
| T1120 | Windows | No |
| T1120 | macOS | No |
| T1123 | Linux | No |
| T1123 | Windows | No |
| T1123 | macOS | No |
| T1125 | Linux | No |
| T1125 | Windows | No |
| T1125 | macOS | No |
| T1127 | Windows | No |
| T1127.001 | Windows | No |
| T1127.002 | Windows | No |
| T1127.003 | Windows | No |
| T1129 | Linux | No |
| T1129 | Windows | No |
| T1129 | macOS | No |
| T1132 | ESXi | No |
| T1132 | Linux | No |
| T1132 | Windows | No |
| T1132 | macOS | No |
| T1132.002 | ESXi | No |
| T1132.002 | Linux | No |
| T1132.002 | Windows | No |
| T1132.002 | macOS | No |
| T1133 | Containers | No |
| T1133 | Linux | No |
| T1133 | Windows | No |
| T1133 | macOS | No |
| T1134 | Windows | No |
| T1134.001 | Windows | No |
| T1134.002 | Windows | No |
| T1134.003 | Windows | No |
| T1134.004 | Windows | No |
| T1134.005 | Windows | No |
| T1136 | Containers | No |
| T1136 | ESXi | No |
| T1136 | IaaS | No |
| T1136 | Identity Provider | No |
| T1136 | Linux | No |
| T1136 | Network Devices | No |
| T1136 | Office Suite | No |
| T1136 | SaaS | No |
| T1136 | Windows | No |
| T1136 | macOS | No |
| T1136.001 | Containers | No |
| T1136.001 | ESXi | No |
| T1136.001 | Linux | No |
| T1136.001 | Network Devices | No |
| T1136.001 | Windows | No |
| T1136.001 | macOS | No |
| T1136.002 | Linux | No |
| T1136.002 | Windows | No |
| T1136.002 | macOS | No |
| T1136.003 | IaaS | Yes |
| T1136.003 | Identity Provider | Yes |
| T1136.003 | Office Suite | No |
| T1136.003 | SaaS | Yes |
| T1137 | Office Suite | No |
| T1137 | Windows | No |
| T1137.001 | Office Suite | No |
| T1137.001 | Windows | No |
| T1137.002 | Office Suite | No |
| T1137.002 | Windows | No |
| T1137.003 | Office Suite | No |
| T1137.003 | Windows | No |
| T1137.004 | Office Suite | No |
| T1137.004 | Windows | No |
| T1137.005 | Office Suite | No |
| T1137.005 | Windows | No |
| T1137.006 | Office Suite | No |
| T1137.006 | Windows | No |
| T1176 | Linux | No |
| T1176 | Windows | No |
| T1176 | macOS | No |
| T1176.001 | Linux | No |
| T1176.001 | Windows | No |
| T1176.001 | macOS | No |
| T1176.002 | Linux | No |
| T1176.002 | Windows | No |
| T1176.002 | macOS | No |
| T1185 | Windows | No |
| T1187 | Windows | No |
| T1189 | Identity Provider | No |
| T1189 | Linux | No |
| T1189 | Windows | No |
| T1189 | macOS | No |
| T1195 | Linux | No |
| T1195 | SaaS | No |
| T1195 | Windows | No |
| T1195 | macOS | No |
| T1195.001 | Linux | No |
| T1195.001 | Windows | No |
| T1195.001 | macOS | No |
| T1195.002 | Linux | No |
| T1195.002 | Windows | No |
| T1195.002 | macOS | No |
| T1195.003 | Linux | No |
| T1195.003 | Windows | No |
| T1195.003 | macOS | No |
| T1197 | Windows | No |
| T1199 | IaaS | No |
| T1199 | Identity Provider | No |
| T1199 | Linux | No |
| T1199 | Office Suite | No |
| T1199 | SaaS | No |
| T1199 | Windows | No |
| T1199 | macOS | No |
| T1200 | Linux | No |
| T1200 | Windows | Yes |
| T1200 | macOS | No |
| T1201 | IaaS | No |
| T1201 | Identity Provider | No |
| T1201 | Linux | No |
| T1201 | Network Devices | No |
| T1201 | Office Suite | No |
| T1201 | SaaS | No |
| T1201 | Windows | No |
| T1201 | macOS | No |
| T1202 | Windows | No |
| T1203 | Linux | No |
| T1203 | Windows | No |
| T1203 | macOS | No |
| T1204 | Containers | No |
| T1204 | IaaS | No |
| T1204 | Linux | No |
| T1204 | Windows | No |
| T1204 | macOS | No |
| T1204.003 | Containers | No |
| T1204.003 | IaaS | No |
| T1204.004 | Linux | No |
| T1204.004 | Windows | No |
| T1204.004 | macOS | No |
| T1204.005 | Linux | No |
| T1204.005 | Windows | No |
| T1204.005 | macOS | No |
| T1205 | Linux | No |
| T1205 | Network Devices | No |
| T1205 | Windows | No |
| T1205 | macOS | No |
| T1205.001 | Linux | No |
| T1205.001 | Network Devices | No |
| T1205.001 | Windows | No |
| T1205.001 | macOS | No |
| T1205.002 | Linux | No |
| T1205.002 | Windows | No |
| T1205.002 | macOS | No |
| T1207 | Windows | Yes |
| T1210 | ESXi | No |
| T1210 | Linux | No |
| T1210 | Windows | No |
| T1210 | macOS | No |
| T1211 | IaaS | No |
| T1211 | Linux | No |
| T1211 | SaaS | No |
| T1211 | Windows | No |
| T1211 | macOS | No |
| T1212 | Identity Provider | No |
| T1212 | Linux | No |
| T1212 | Windows | No |
| T1212 | macOS | No |
| T1213 | IaaS | No |
| T1213 | Linux | No |
| T1213 | Office Suite | No |
| T1213 | SaaS | No |
| T1213 | Windows | No |
| T1213 | macOS | No |
| T1213.001 | SaaS | No |
| T1213.002 | Office Suite | No |
| T1213.002 | Windows | No |
| T1213.003 | SaaS | No |
| T1213.004 | SaaS | No |
| T1213.005 | Office Suite | No |
| T1213.005 | SaaS | No |
| T1213.006 | IaaS | No |
| T1213.006 | Linux | No |
| T1213.006 | SaaS | No |
| T1213.006 | Windows | No |
| T1213.006 | macOS | No |
| T1216 | Windows | No |
| T1216.001 | Windows | No |
| T1216.002 | Windows | No |
| T1217 | Linux | No |
| T1217 | Windows | No |
| T1217 | macOS | No |
| T1218 | Linux | No |
| T1218 | Windows | No |
| T1218 | macOS | No |
| T1218.001 | Windows | No |
| T1218.002 | Windows | No |
| T1218.003 | Windows | No |
| T1218.004 | Windows | No |
| T1218.005 | Windows | Yes |
| T1218.007 | Windows | No |
| T1218.008 | Windows | No |
| T1218.009 | Windows | No |
| T1218.010 | Windows | No |
| T1218.012 | Windows | No |
| T1218.013 | Windows | No |
| T1218.014 | Windows | No |
| T1218.015 | Linux | No |
| T1218.015 | Windows | No |
| T1218.015 | macOS | No |
| T1219 | Linux | No |
| T1219 | Windows | No |
| T1219 | macOS | No |
| T1219.001 | Linux | No |
| T1219.001 | Windows | No |
| T1219.001 | macOS | No |
| T1219.002 | Linux | No |
| T1219.002 | Windows | No |
| T1219.002 | macOS | No |
| T1219.003 | Linux | No |
| T1219.003 | Windows | No |
| T1219.003 | macOS | No |
| T1220 | Windows | No |
| T1221 | Windows | No |
| T1222 | ESXi | No |
| T1222 | Linux | No |
| T1222 | Windows | No |
| T1222 | macOS | No |
| T1222.001 | Windows | No |
| T1222.002 | Linux | No |
| T1222.002 | macOS | No |
| T1480 | ESXi | No |
| T1480 | Linux | No |
| T1480 | Windows | No |
| T1480 | macOS | No |
| T1480.001 | Linux | No |
| T1480.001 | Windows | No |
| T1480.001 | macOS | No |
| T1480.002 | Linux | No |
| T1480.002 | Windows | No |
| T1480.002 | macOS | No |
| T1482 | Windows | No |
| T1484 | Identity Provider | No |
| T1484 | Windows | No |
| T1484.001 | Windows | No |
| T1484.002 | Identity Provider | No |
| T1484.002 | Windows | No |
| T1485 | Containers | No |
| T1485 | ESXi | No |
| T1485 | IaaS | No |
| T1485 | Linux | No |
| T1485 | Windows | No |
| T1485 | macOS | No |
| T1485.001 | IaaS | No |
| T1489 | ESXi | No |
| T1489 | IaaS | No |
| T1489 | Linux | No |
| T1489 | Windows | No |
| T1489 | macOS | No |
| T1490 | Containers | No |
| T1490 | ESXi | No |
| T1490 | IaaS | No |
| T1490 | Linux | No |
| T1490 | Network Devices | No |
| T1490 | Windows | No |
| T1490 | macOS | No |
| T1491 | ESXi | No |
| T1491 | IaaS | No |
| T1491 | Linux | No |
| T1491 | Windows | No |
| T1491 | macOS | No |
| T1491.001 | ESXi | No |
| T1491.001 | Linux | No |
| T1491.001 | Windows | No |
| T1491.001 | macOS | No |
| T1491.002 | IaaS | No |
| T1491.002 | Linux | No |
| T1491.002 | Windows | No |
| T1491.002 | macOS | No |
| T1495 | Linux | No |
| T1495 | Network Devices | No |
| T1495 | Windows | No |
| T1495 | macOS | No |
| T1496 | Containers | No |
| T1496 | IaaS | No |
| T1496 | Linux | No |
| T1496 | SaaS | No |
| T1496 | Windows | No |
| T1496 | macOS | No |
| T1496.001 | Containers | No |
| T1496.001 | IaaS | No |
| T1496.001 | Linux | No |
| T1496.001 | Windows | No |
| T1496.001 | macOS | No |
| T1496.002 | Containers | No |
| T1496.002 | IaaS | No |
| T1496.002 | Linux | No |
| T1496.002 | Windows | No |
| T1496.002 | macOS | No |
| T1496.003 | SaaS | No |
| T1496.004 | SaaS | Yes |
| T1497 | Linux | No |
| T1497 | Windows | No |
| T1497 | macOS | No |
| T1497.002 | Linux | No |
| T1497.002 | Windows | No |
| T1497.002 | macOS | No |
| T1497.003 | Linux | No |
| T1497.003 | Windows | No |
| T1497.003 | macOS | No |
| T1498 | Containers | No |
| T1498 | IaaS | No |
| T1498 | Linux | No |
| T1498 | Windows | No |
| T1498 | macOS | No |
| T1498.001 | IaaS | No |
| T1498.001 | Linux | No |
| T1498.001 | Windows | No |
| T1498.001 | macOS | No |
| T1498.002 | IaaS | No |
| T1498.002 | Linux | No |
| T1498.002 | Windows | No |
| T1498.002 | macOS | No |
| T1499 | Containers | No |
| T1499 | IaaS | No |
| T1499 | Linux | No |
| T1499 | Windows | No |
| T1499 | macOS | No |
| T1499.001 | Linux | No |
| T1499.001 | Windows | No |
| T1499.001 | macOS | No |
| T1499.002 | IaaS | No |
| T1499.002 | Linux | No |
| T1499.002 | Windows | No |
| T1499.002 | macOS | No |
| T1499.003 | IaaS | No |
| T1499.003 | Linux | No |
| T1499.003 | Windows | No |
| T1499.003 | macOS | No |
| T1499.004 | IaaS | No |
| T1499.004 | Linux | No |
| T1499.004 | Windows | No |
| T1499.004 | macOS | No |
| T1505 | ESXi | No |
| T1505 | Linux | No |
| T1505 | Network Devices | No |
| T1505 | Windows | No |
| T1505 | macOS | No |
| T1505.001 | Linux | No |
| T1505.001 | Windows | No |
| T1505.002 | Linux | No |
| T1505.002 | Windows | No |
| T1505.004 | Windows | No |
| T1505.005 | Windows | No |
| T1505.006 | ESXi | No |
| T1518 | ESXi | No |
| T1518 | IaaS | No |
| T1518 | Linux | No |
| T1518 | Windows | No |
| T1518 | macOS | No |
| T1518.002 | Linux | No |
| T1518.002 | Windows | No |
| T1518.002 | macOS | No |
| T1525 | Containers | No |
| T1525 | IaaS | No |
| T1526 | IaaS | No |
| T1526 | Identity Provider | No |
| T1526 | Office Suite | No |
| T1526 | SaaS | No |
| T1528 | Containers | No |
| T1528 | IaaS | No |
| T1528 | Identity Provider | No |
| T1528 | Office Suite | No |
| T1528 | SaaS | No |
| T1529 | ESXi | No |
| T1529 | Linux | No |
| T1529 | Network Devices | No |
| T1529 | Windows | No |
| T1529 | macOS | No |
| T1530 | IaaS | No |
| T1530 | Office Suite | No |
| T1530 | SaaS | No |
| T1531 | ESXi | No |
| T1531 | IaaS | No |
| T1531 | Linux | No |
| T1531 | Office Suite | No |
| T1531 | SaaS | No |
| T1531 | Windows | No |
| T1531 | macOS | No |
| T1534 | Linux | No |
| T1534 | Office Suite | No |
| T1534 | SaaS | No |
| T1534 | Windows | No |
| T1534 | macOS | No |
| T1535 | IaaS | No |
| T1537 | IaaS | No |
| T1537 | Office Suite | No |
| T1537 | SaaS | No |
| T1538 | IaaS | No |
| T1538 | Identity Provider | No |
| T1538 | Office Suite | No |
| T1538 | SaaS | No |
| T1539 | Linux | No |
| T1539 | Office Suite | No |
| T1539 | SaaS | No |
| T1539 | Windows | No |
| T1539 | macOS | No |
| T1542 | Linux | No |
| T1542 | Network Devices | No |
| T1542 | Windows | No |
| T1542 | macOS | No |
| T1542.001 | Network Devices | No |
| T1542.001 | Windows | No |
| T1542.002 | Linux | No |
| T1542.002 | Windows | No |
| T1542.002 | macOS | No |
| T1542.003 | Linux | No |
| T1542.003 | Windows | No |
| T1542.004 | Network Devices | No |
| T1542.005 | Network Devices | No |
| T1543 | Containers | No |
| T1543 | Linux | No |
| T1543 | Windows | No |
| T1543 | macOS | No |
| T1543.001 | macOS | No |
| T1543.002 | Linux | No |
| T1543.004 | macOS | No |
| T1543.005 | Containers | No |
| T1546 | IaaS | No |
| T1546 | Linux | No |
| T1546 | Office Suite | No |
| T1546 | SaaS | No |
| T1546 | Windows | No |
| T1546 | macOS | No |
| T1546.001 | Windows | No |
| T1546.002 | Windows | No |
| T1546.003 | Windows | Yes |
| T1546.004 | Linux | No |
| T1546.004 | macOS | No |
| T1546.005 | Linux | No |
| T1546.005 | macOS | No |
| T1546.006 | macOS | No |
| T1546.007 | Windows | No |
| T1546.008 | Windows | No |
| T1546.009 | Windows | No |
| T1546.010 | Windows | No |
| T1546.011 | Windows | No |
| T1546.012 | Windows | No |
| T1546.013 | Windows | No |
| T1546.014 | macOS | No |
| T1546.015 | Windows | No |
| T1546.016 | Linux | No |
| T1546.016 | Windows | No |
| T1546.016 | macOS | No |
| T1546.017 | Linux | No |
| T1546.018 | Linux | No |
| T1546.018 | Windows | No |
| T1546.018 | macOS | No |
| T1547 | Linux | No |
| T1547 | Network Devices | No |
| T1547 | Windows | No |
| T1547 | macOS | No |
| T1547.002 | Windows | No |
| T1547.003 | Windows | No |
| T1547.004 | Windows | No |
| T1547.005 | Windows | No |
| T1547.006 | Linux | No |
| T1547.006 | macOS | No |
| T1547.007 | macOS | No |
| T1547.008 | Windows | No |
| T1547.009 | Windows | No |
| T1547.010 | Windows | No |
| T1547.012 | Windows | No |
| T1547.013 | Linux | No |
| T1547.014 | Windows | No |
| T1547.015 | macOS | No |
| T1548 | IaaS | No |
| T1548 | Identity Provider | No |
| T1548 | Linux | No |
| T1548 | Office Suite | No |
| T1548 | Windows | No |
| T1548 | macOS | No |
| T1548.001 | Linux | No |
| T1548.001 | macOS | No |
| T1548.003 | Linux | No |
| T1548.003 | macOS | No |
| T1548.004 | macOS | No |
| T1548.005 | IaaS | No |
| T1548.005 | Identity Provider | No |
| T1548.005 | Office Suite | No |
| T1548.006 | macOS | No |
| T1550 | Containers | No |
| T1550 | IaaS | No |
| T1550 | Identity Provider | No |
| T1550 | Linux | No |
| T1550 | Office Suite | No |
| T1550 | SaaS | No |
| T1550 | Windows | No |
| T1550.001 | Containers | No |
| T1550.001 | IaaS | No |
| T1550.001 | Identity Provider | No |
| T1550.001 | Office Suite | No |
| T1550.001 | SaaS | No |
| T1550.002 | Windows | No |
| T1550.003 | Windows | Yes |
| T1550.004 | IaaS | No |
| T1550.004 | Office Suite | No |
| T1550.004 | SaaS | No |
| T1552 | Containers | No |
| T1552 | IaaS | No |
| T1552 | Identity Provider | No |
| T1552 | Linux | No |
| T1552 | Network Devices | No |
| T1552 | Office Suite | No |
| T1552 | SaaS | No |
| T1552 | Windows | No |
| T1552 | macOS | No |
| T1552.001 | Containers | No |
| T1552.001 | IaaS | No |
| T1552.001 | Linux | No |
| T1552.001 | Windows | No |
| T1552.001 | macOS | No |
| T1552.002 | Windows | No |
| T1552.003 | Linux | No |
| T1552.003 | Windows | No |
| T1552.003 | macOS | No |
| T1552.004 | Linux | No |
| T1552.004 | Network Devices | No |
| T1552.004 | Windows | No |
| T1552.004 | macOS | No |
| T1552.005 | IaaS | No |
| T1552.006 | Windows | No |
| T1552.007 | Containers | No |
| T1552.008 | Office Suite | No |
| T1552.008 | SaaS | No |
| T1553 | Linux | No |
| T1553 | Windows | No |
| T1553 | macOS | No |
| T1553.001 | macOS | No |
| T1553.003 | Windows | No |
| T1553.004 | Linux | No |
| T1553.004 | Windows | No |
| T1553.004 | macOS | No |
| T1553.005 | Windows | No |
| T1553.006 | Windows | No |
| T1553.006 | macOS | No |
| T1554 | ESXi | No |
| T1554 | Linux | No |
| T1554 | Windows | No |
| T1554 | macOS | No |
| T1555 | IaaS | No |
| T1555 | Linux | No |
| T1555 | Windows | No |
| T1555 | macOS | No |
| T1555.001 | macOS | No |
| T1555.002 | Linux | No |
| T1555.002 | macOS | No |
| T1555.004 | Windows | No |
| T1555.005 | Linux | No |
| T1555.005 | Windows | No |
| T1555.005 | macOS | No |
| T1555.006 | IaaS | No |
| T1556 | IaaS | No |
| T1556 | Identity Provider | No |
| T1556 | Linux | No |
| T1556 | Network Devices | No |
| T1556 | Office Suite | No |
| T1556 | SaaS | No |
| T1556 | Windows | No |
| T1556 | macOS | No |
| T1556.001 | Windows | No |
| T1556.002 | Windows | No |
| T1556.003 | Linux | No |
| T1556.003 | macOS | No |
| T1556.004 | Network Devices | No |
| T1556.005 | Windows | No |
| T1556.006 | IaaS | No |
| T1556.006 | Identity Provider | No |
| T1556.006 | Linux | No |
| T1556.006 | Office Suite | No |
| T1556.006 | SaaS | No |
| T1556.006 | Windows | No |
| T1556.006 | macOS | No |
| T1556.007 | IaaS | No |
| T1556.007 | Identity Provider | No |
| T1556.007 | Office Suite | No |
| T1556.007 | SaaS | No |
| T1556.007 | Windows | No |
| T1556.008 | Windows | No |
| T1556.009 | IaaS | No |
| T1556.009 | Identity Provider | No |
| T1557 | Linux | No |
| T1557 | Network Devices | No |
| T1557 | Windows | No |
| T1557 | macOS | No |
| T1557.001 | Windows | No |
| T1557.002 | Linux | No |
| T1557.002 | Windows | No |
| T1557.002 | macOS | No |
| T1557.003 | Linux | No |
| T1557.003 | Windows | No |
| T1557.003 | macOS | No |
| T1557.004 | Network Devices | No |
| T1558 | Linux | No |
| T1558 | Windows | No |
| T1558 | macOS | No |
| T1558.001 | Windows | Yes |
| T1558.002 | Windows | No |
| T1558.003 | Windows | Yes |
| T1558.004 | Windows | Yes |
| T1558.005 | Linux | No |
| T1558.005 | macOS | No |
| T1559 | Linux | No |
| T1559 | Windows | No |
| T1559 | macOS | No |
| T1559.001 | Windows | No |
| T1559.002 | Windows | No |
| T1559.003 | macOS | No |
| T1560 | Linux | No |
| T1560 | Windows | No |
| T1560 | macOS | No |
| T1560.002 | Linux | No |
| T1560.002 | Windows | No |
| T1560.002 | macOS | No |
| T1560.003 | Linux | No |
| T1560.003 | Windows | No |
| T1560.003 | macOS | No |
| T1561 | Linux | No |
| T1561 | Network Devices | No |
| T1561 | Windows | No |
| T1561 | macOS | No |
| T1561.001 | Linux | No |
| T1561.001 | Network Devices | No |
| T1561.001 | Windows | No |
| T1561.001 | macOS | No |
| T1561.002 | Linux | No |
| T1561.002 | Network Devices | No |
| T1561.002 | Windows | No |
| T1561.002 | macOS | No |
| T1562 | Containers | No |
| T1562 | ESXi | No |
| T1562 | IaaS | No |
| T1562 | Identity Provider | No |
| T1562 | Linux | No |
| T1562 | Network Devices | No |
| T1562 | Office Suite | No |
| T1562 | Windows | No |
| T1562 | macOS | No |
| T1562.002 | Windows | No |
| T1562.003 | ESXi | No |
| T1562.003 | Linux | No |
| T1562.003 | Network Devices | No |
| T1562.003 | Windows | No |
| T1562.003 | macOS | No |
| T1562.004 | ESXi | No |
| T1562.004 | Linux | No |
| T1562.004 | Network Devices | No |
| T1562.004 | Windows | No |
| T1562.004 | macOS | No |
| T1562.006 | ESXi | No |
| T1562.006 | Linux | No |
| T1562.006 | Windows | No |
| T1562.006 | macOS | No |
| T1562.007 | IaaS | No |
| T1562.008 | IaaS | No |
| T1562.008 | Identity Provider | No |
| T1562.008 | Office Suite | No |
| T1562.008 | SaaS | No |
| T1562.009 | Windows | No |
| T1562.010 | Linux | No |
| T1562.010 | Windows | No |
| T1562.010 | macOS | No |
| T1562.011 | Linux | No |
| T1562.011 | Windows | No |
| T1562.011 | macOS | No |
| T1562.012 | Linux | No |
| T1562.013 | Network Devices | No |
| T1563 | Linux | No |
| T1563 | Windows | No |
| T1563 | macOS | No |
| T1563.001 | Linux | No |
| T1563.001 | macOS | No |
| T1563.002 | Windows | No |
| T1564 | ESXi | No |
| T1564 | Linux | No |
| T1564 | Office Suite | No |
| T1564 | Windows | No |
| T1564 | macOS | No |
| T1564.001 | Linux | No |
| T1564.001 | Windows | No |
| T1564.001 | macOS | No |
| T1564.002 | Linux | No |
| T1564.002 | Windows | No |
| T1564.002 | macOS | No |
| T1564.003 | Linux | No |
| T1564.003 | Windows | No |
| T1564.003 | macOS | No |
| T1564.004 | Windows | No |
| T1564.005 | Linux | No |
| T1564.005 | Windows | No |
| T1564.005 | macOS | No |
| T1564.006 | ESXi | No |
| T1564.006 | Linux | No |
| T1564.006 | Windows | No |
| T1564.006 | macOS | No |
| T1564.007 | Linux | No |
| T1564.007 | Windows | No |
| T1564.007 | macOS | No |
| T1564.008 | Linux | No |
| T1564.008 | Office Suite | No |
| T1564.008 | Windows | No |
| T1564.008 | macOS | No |
| T1564.009 | macOS | No |
| T1564.010 | Windows | No |
| T1564.011 | Linux | No |
| T1564.011 | Windows | No |
| T1564.011 | macOS | No |
| T1564.012 | Linux | No |
| T1564.012 | Windows | No |
| T1564.012 | macOS | No |
| T1564.013 | Linux | No |
| T1564.014 | Linux | No |
| T1564.014 | macOS | No |
| T1565 | Linux | No |
| T1565 | Windows | No |
| T1565 | macOS | No |
| T1565.001 | Linux | No |
| T1565.001 | Windows | No |
| T1565.001 | macOS | No |
| T1565.002 | Linux | No |
| T1565.002 | Windows | No |
| T1565.002 | macOS | No |
| T1565.003 | Linux | No |
| T1565.003 | Windows | No |
| T1565.003 | macOS | No |
| T1566 | Identity Provider | No |
| T1566 | Linux | No |
| T1566 | Office Suite | No |
| T1566 | SaaS | No |
| T1566 | Windows | No |
| T1566 | macOS | No |
| T1566.003 | Linux | No |
| T1566.003 | Windows | No |
| T1566.003 | macOS | No |
| T1566.004 | Identity Provider | No |
| T1566.004 | Linux | No |
| T1566.004 | Windows | No |
| T1566.004 | macOS | No |
| T1567 | ESXi | No |
| T1567 | Linux | No |
| T1567 | Office Suite | No |
| T1567 | SaaS | No |
| T1567 | Windows | No |
| T1567 | macOS | No |
| T1567.001 | ESXi | No |
| T1567.001 | Linux | No |
| T1567.001 | Windows | No |
| T1567.001 | macOS | No |
| T1567.002 | ESXi | No |
| T1567.002 | Linux | No |
| T1567.002 | Windows | No |
| T1567.002 | macOS | No |
| T1567.003 | ESXi | No |
| T1567.003 | Linux | No |
| T1567.003 | Windows | No |
| T1567.003 | macOS | No |
| T1567.004 | ESXi | No |
| T1567.004 | Linux | No |
| T1567.004 | Office Suite | No |
| T1567.004 | SaaS | No |
| T1567.004 | Windows | No |
| T1567.004 | macOS | No |
| T1568 | ESXi | No |
| T1568 | Linux | No |
| T1568 | Windows | No |
| T1568 | macOS | No |
| T1568.001 | ESXi | No |
| T1568.001 | Linux | No |
| T1568.001 | Windows | No |
| T1568.001 | macOS | No |
| T1568.002 | ESXi | No |
| T1568.002 | Linux | No |
| T1568.002 | Windows | No |
| T1568.002 | macOS | No |
| T1568.003 | ESXi | No |
| T1568.003 | Linux | No |
| T1568.003 | Windows | No |
| T1568.003 | macOS | No |
| T1569 | Linux | No |
| T1569 | Windows | No |
| T1569 | macOS | No |
| T1569.001 | macOS | No |
| T1569.003 | Linux | No |
| T1570 | ESXi | No |
| T1570 | Linux | No |
| T1570 | Windows | No |
| T1570 | macOS | No |
| T1571 | ESXi | No |
| T1571 | Linux | No |
| T1571 | Windows | No |
| T1571 | macOS | No |
| T1572 | ESXi | No |
| T1572 | Linux | No |
| T1572 | Windows | No |
| T1572 | macOS | No |
| T1573 | ESXi | No |
| T1573 | Linux | No |
| T1573 | Network Devices | No |
| T1573 | Windows | No |
| T1573 | macOS | No |
| T1574 | Linux | No |
| T1574 | Windows | No |
| T1574 | macOS | No |
| T1574.004 | macOS | No |
| T1574.005 | Windows | No |
| T1574.006 | Linux | No |
| T1574.006 | macOS | No |
| T1574.007 | Linux | No |
| T1574.007 | Windows | No |
| T1574.007 | macOS | No |
| T1574.008 | Windows | No |
| T1574.009 | Windows | No |
| T1574.010 | Windows | No |
| T1574.011 | Windows | No |
| T1574.012 | Windows | No |
| T1574.013 | Windows | No |
| T1574.014 | Windows | No |
| T1578 | IaaS | No |
| T1578.001 | IaaS | No |
| T1578.002 | IaaS | No |
| T1578.003 | IaaS | No |
| T1578.004 | IaaS | No |
| T1578.005 | IaaS | No |
| T1580 | IaaS | No |
| T1583 | PRE | No |
| T1583.001 | PRE | No |
| T1583.002 | PRE | No |
| T1583.003 | PRE | No |
| T1583.004 | PRE | No |
| T1583.005 | PRE | No |
| T1583.006 | PRE | No |
| T1583.007 | PRE | No |
| T1583.008 | PRE | No |
| T1584 | PRE | No |
| T1584.001 | PRE | No |
| T1584.002 | PRE | No |
| T1584.003 | PRE | No |
| T1584.004 | PRE | No |
| T1584.005 | PRE | No |
| T1584.006 | PRE | No |
| T1584.007 | PRE | No |
| T1584.008 | PRE | No |
| T1585 | PRE | No |
| T1585.001 | PRE | No |
| T1585.002 | PRE | No |
| T1585.003 | PRE | No |
| T1586 | PRE | No |
| T1586.001 | PRE | No |
| T1586.002 | PRE | No |
| T1586.003 | PRE | No |
| T1587 | PRE | No |
| T1587.001 | PRE | No |
| T1587.002 | PRE | No |
| T1587.003 | PRE | No |
| T1587.004 | PRE | No |
| T1588 | PRE | No |
| T1588.001 | PRE | No |
| T1588.003 | PRE | No |
| T1588.004 | PRE | No |
| T1588.005 | PRE | No |
| T1588.006 | PRE | No |
| T1588.007 | PRE | No |
| T1589 | PRE | No |
| T1589.001 | PRE | No |
| T1589.002 | PRE | No |
| T1589.003 | PRE | No |
| T1590 | PRE | No |
| T1590.001 | PRE | No |
| T1590.002 | PRE | No |
| T1590.003 | PRE | No |
| T1590.004 | PRE | No |
| T1590.005 | PRE | No |
| T1590.006 | PRE | No |
| T1591 | PRE | No |
| T1591.001 | PRE | No |
| T1591.002 | PRE | No |
| T1591.003 | PRE | No |
| T1591.004 | PRE | No |
| T1592 | PRE | No |
| T1592.001 | PRE | No |
| T1592.002 | PRE | No |
| T1592.003 | PRE | No |
| T1592.004 | PRE | No |
| T1593 | PRE | No |
| T1593.001 | PRE | No |
| T1593.002 | PRE | No |
| T1593.003 | PRE | No |
| T1594 | PRE | No |
| T1595 | PRE | No |
| T1595.001 | PRE | No |
| T1595.002 | PRE | No |
| T1595.003 | PRE | No |
| T1596 | PRE | No |
| T1596.001 | PRE | No |
| T1596.002 | PRE | No |
| T1596.003 | PRE | No |
| T1596.004 | PRE | No |
| T1596.005 | PRE | No |
| T1597 | PRE | No |
| T1597.001 | PRE | No |
| T1597.002 | PRE | No |
| T1598 | PRE | No |
| T1598.001 | PRE | No |
| T1598.002 | PRE | No |
| T1598.003 | PRE | No |
| T1598.004 | PRE | No |
| T1599 | Network Devices | No |
| T1599.001 | Network Devices | No |
| T1600 | Network Devices | No |
| T1600.001 | Network Devices | No |
| T1600.002 | Network Devices | No |
| T1601 | Network Devices | No |
| T1601.001 | Network Devices | No |
| T1601.002 | Network Devices | No |
| T1602 | Network Devices | No |
| T1602.001 | Network Devices | No |
| T1602.002 | Network Devices | No |
| T1606 | IaaS | No |
| T1606 | Identity Provider | No |
| T1606 | Linux | No |
| T1606 | Office Suite | No |
| T1606 | SaaS | No |
| T1606 | Windows | No |
| T1606 | macOS | No |
| T1606.001 | IaaS | No |
| T1606.001 | Linux | No |
| T1606.001 | SaaS | No |
| T1606.001 | Windows | No |
| T1606.001 | macOS | No |
| T1606.002 | IaaS | No |
| T1606.002 | Identity Provider | No |
| T1606.002 | Office Suite | No |
| T1606.002 | SaaS | No |
| T1606.002 | Windows | No |
| T1608 | PRE | No |
| T1608.001 | PRE | No |
| T1608.002 | PRE | No |
| T1608.003 | PRE | No |
| T1608.004 | PRE | No |
| T1608.005 | PRE | No |
| T1608.006 | PRE | No |
| T1609 | Containers | No |
| T1610 | Containers | No |
| T1611 | Containers | No |
| T1611 | ESXi | No |
| T1611 | Linux | No |
| T1611 | Windows | No |
| T1612 | Containers | No |
| T1613 | Containers | No |
| T1614 | IaaS | No |
| T1614 | Linux | No |
| T1614 | Windows | No |
| T1614 | macOS | No |
| T1614.001 | Linux | No |
| T1614.001 | Windows | No |
| T1614.001 | macOS | No |
| T1615 | Windows | No |
| T1619 | IaaS | No |
| T1620 | Linux | No |
| T1620 | Windows | No |
| T1620 | macOS | No |
| T1621 | IaaS | No |
| T1621 | Identity Provider | No |
| T1621 | Linux | No |
| T1621 | Office Suite | No |
| T1621 | SaaS | No |
| T1621 | Windows | No |
| T1621 | macOS | No |
| T1622 | Linux | No |
| T1622 | Windows | No |
| T1622 | macOS | No |
| T1647 | macOS | No |
| T1648 | IaaS | No |
| T1648 | Office Suite | No |
| T1648 | SaaS | No |
| T1649 | Identity Provider | No |
| T1649 | Linux | No |
| T1649 | Windows | No |
| T1649 | macOS | No |
| T1650 | PRE | No |
| T1651 | IaaS | No |
| T1652 | Linux | No |
| T1652 | Windows | No |
| T1652 | macOS | No |
| T1653 | Linux | No |
| T1653 | Network Devices | No |
| T1653 | Windows | No |
| T1653 | macOS | No |
| T1654 | ESXi | No |
| T1654 | IaaS | No |
| T1654 | Linux | No |
| T1654 | Windows | No |
| T1654 | macOS | No |
| T1656 | Linux | No |
| T1656 | Office Suite | No |
| T1656 | SaaS | No |
| T1656 | Windows | No |
| T1656 | macOS | No |
| T1657 | Linux | No |
| T1657 | Office Suite | No |
| T1657 | SaaS | No |
| T1657 | Windows | No |
| T1657 | macOS | No |
| T1659 | Linux | No |
| T1659 | Windows | No |
| T1659 | macOS | No |
| T1665 | ESXi | No |
| T1665 | Linux | No |
| T1665 | Network Devices | No |
| T1665 | Windows | No |
| T1665 | macOS | No |
| T1666 | IaaS | No |
| T1667 | Linux | No |
| T1667 | Office Suite | No |
| T1667 | Windows | No |
| T1667 | macOS | No |
| T1668 | Linux | No |
| T1668 | Windows | No |
| T1668 | macOS | No |
| T1669 | Linux | No |
| T1669 | Network Devices | No |
| T1669 | Windows | No |
| T1669 | macOS | No |
| T1671 | Office Suite | No |
| T1671 | SaaS | No |
| T1672 | Linux | No |
| T1672 | Office Suite | No |
| T1672 | Windows | No |
| T1672 | macOS | No |
| T1673 | ESXi | No |
| T1673 | Linux | No |
| T1673 | Windows | No |
| T1673 | macOS | No |
| T1674 | Linux | No |
| T1674 | Windows | No |
| T1674 | macOS | No |
| T1675 | ESXi | No |
| T1677 | SaaS | No |
| T1678 | Linux | No |
| T1678 | Windows | No |
| T1678 | macOS | No |
| T1679 | Windows | No |
| T1681 | PRE | No |
