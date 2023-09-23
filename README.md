# WTSImpersonate BOF

```
a simple bof to impersonate a logged on user session without OpenProcess (only works as SYSTEM iirc). all credit goes to 
https://github.com/OmriBaso/WTSImpersonator
COFFLoader and NiCOFF used for testing.
```
```
usage:
wtsimpersonate <arg/int>
wtsimpersonate -1 to list sessions
wtsimpersonate <sessionid> to impersonate
```