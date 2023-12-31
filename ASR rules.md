## The following command indicates for each device how many times an ASR rule was triggered : 
```
DeviceEvents
| where ActionType startswith "Asr"
| summarize count() by DeviceName
| sort by count_
```

## The following command counts the number of devices Windows 10 and 11 compliant per ASR rule : 
```
//ConfigurationId == "scid-2500", "BlockMailExe",
//ConfigurationId == "scid-2501", "BlockOfficeChildProc",
//ConfigurationId == "scid-2502", "BlockOfficeExe",
//ConfigurationId == "scid-2503", "BlockOfficeInjection",
//ConfigurationId == "scid-2504", "BlockJavaScriptVBScriptExe",
//ConfigurationId == "scid-2505", "BlockObfuscatedScripts",
//ConfigurationId == "scid-2506", "BlockOfficeMacroW32API",
//ConfigurationId == "scid-2507", "BlockUntrustedExecutables",
//ConfigurationId == "scid-2508", "AdvancedRansomwareProtection",
//ConfigurationId == "scid-2509", "BlockCredentialStealing",
//ConfigurationId == "scid-2510", "BlockProcPSexecWMI",
//ConfigurationId == "scid-2511", "BlockUnsignedEXEonUSB",
//ConfigurationId == "scid-2512", "BlockOfficeCommunicationChildProc",
//ConfigurationId == "scid-2513", "BlockAdobeReaderChildProc",
//ConfigurationId == "scid-2514", "BlockWMIPersist",
//ConfigurationId == "scid-2515", "BlockExploitedVulnerableSignedDrivers"
//ConfigurationId == "scid-2021", "ControlledFolderAccess"

DeviceTvmSecureConfigurationAssessment
| where OSPlatform in ("Windows10", "Windows11") and ConfigurationId in ("scid-2500", "scid-2501", "scid-2502", "scid-2503", "scid-2504", "scid-2505", "scid-2506", "scid-2507", "scid-2508", "scid-2509", "scid-2510","scid-2511","scid-2512","scid-2513","scid-2514", "scid-2515", "scid-2021")
| summarize count_distinctif(ConfigurationId,(IsCompliant)==1) by DeviceName
```


## The following command counts the number of devices Windows 10 and 11 compliant per ASR rule : 
```
DeviceTvmSecureConfigurationAssessment
| where OSPlatform in ("Windows10", "Windows11") and ConfigurationId in ("scid-2500", "scid-2501", "scid-2502", "scid-2503", "scid-2504", "scid-2505", "scid-2506", "scid-2507", "scid-2508", "scid-2509", "scid-2510","scid-2511","scid-2512","scid-2513","scid-2514", "scid-2515", "scid-2021")
| summarize count_distinctif(DeviceName,(IsCompliant)==1) by ConfigurationId 
| sort by ConfigurationId asc 
```

## ASR Rules block mode: PIE CHART 
```
DeviceEvents 
| where Timestamp > ago(7d) 
| where ActionType startswith "asr" 
| extend Parsed = parse_json(AdditionalFields) 
| where Parsed.IsAudit == "false" 
| summarize ASR_rule_case = count() by ActionType
| render piechart 
```

## ASR Rules Audit mode: PIE CHART 
```
DeviceEvents 
| where Timestamp > ago(7d) 
| where ActionType startswith "asr" 
| extend Parsed = parse_json(AdditionalFields) 
| where Parsed.IsAudit == "true" 
| summarize ASR_rule_case = count() by ActionType
| render piechart 
```
