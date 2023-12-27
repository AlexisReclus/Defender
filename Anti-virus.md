## This query displays threat family and filename that were detected by Microsoft Defender Antivirus in the past 30 days for each device: 
```
DeviceEvents
| where Timestamp > ago(30d)
| where ActionType == "AntivirusDetection"
| extend DetectionType =parse_json(AdditionalFields)
| summarize MalwareFamilyList = make_list(strcat(DetectionType.ThreatName, @"\", FileName)) by DeviceName, DeviceId
| extend ThreatNumber = array_length(MalwareFamilyList)
| project DeviceId, DeviceName, ThreatNumber, MalwareFamilyList
```

## This query displays the last completed scan time, along with the scan type (Quick/Full), for Microsoft Defender Antivirus on each device in the past 30 days: 
```
DeviceEvents
| where Timestamp > ago(30d)
| where ActionType == "AntivirusScanCompleted"
| extend Parsed = parse_json(AdditionalFields)
| extend ScanType = Parsed.ScanTypeIndex
| summarize arg_max(Timestamp, *) by DeviceId, DeviceName
| project DeviceId, DeviceName, ActionType, ScanType, Timestamp, InitiatingProcessVersionInfoProductVersion
```

## This query displays the devices without AV scan in the past 30 days: 
```
// Devices without successful AV scan in the last 30 days
// As of 27.01.2022 only the following platforms are support
// Windows10, Windows10WVD, Windows11, WindowsServer2012R2, WindowsServer2016, WindowsServer2019, WindowsServer2022
let Timerange = 30d;
DeviceInfo
| where OnboardingStatus == "Onboarded"
| where isnotempty( OSVersion)
| where Timestamp > ago(Timerange)
| summarize LastSeen = arg_max(Timestamp, *) by DeviceId
| extend LastSuccessfulAVScan = strcat("Not in the last ",format_timespan(Timerange,'d')," days")
| project LastSeen, DeviceId, DeviceName, MachineGroup, OSPlatform, OSVersion, DeviceType, LastSuccessfulAVScan, JoinType
// use rightsemi to return all devices that had a successful AV scan in the last n days
// use leftanti to return all devices that NOT had a successful AV scan in the last n days
| join kind=leftanti (
    DeviceEvents
    | where ActionType == "AntivirusScanCompleted"
    | where Timestamp > ago(Timerange)
    | summarize LastSuccessfulAVScan = max(Timestamp) by DeviceName, DeviceId
    | join kind=innerunique (
        DeviceInfo
        | where isnotempty( OSVersion )
    ) on DeviceId
    | summarize LastSeen = arg_max(Timestamp,*) by DeviceName
    | project LastSeen, DeviceId, DeviceName, MachineGroup, OSPlatform, OSVersion, DeviceType, LastSuccessfulAVScan, JoinType
) on DeviceId
| where OSPlatform in ("Windows10","Windows10WVD","Windows11","WindowsServer2012R2","WindowsServer2016","WindowsServer2019","WindowsServer2022")
| sort by DeviceType, MachineGroup, OSPlatform
```
