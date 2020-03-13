// connVPN.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include "windows.h"
#include "Ras.h"
#include "RasError.h"
#include <iostream>



bool ImportCert()
{
	bool certRes = false;
	char buffer[MAX_PATH];
	GetModuleFileNameA(NULL, buffer, MAX_PATH);
	std::string::size_type pos = std::string(buffer).find_last_of("\\/");
	std::string myPath = std::string(buffer).substr(0, pos);
	myPath = "C:\\Users\\Administrator\\Desktop\\windows_ikev2";
	//std::string myCommand = "certutil -addstore -f -enterprise -user root \"" + myPath + "\\ca.cert.pem\"";
	std::string myCommand = "certutil -addstore -f -enterprise -user root ca.cert.pem";
	system(myCommand.c_str());

	return certRes;
}


int CreateVPN(const LPCTSTR pszEntryName, const LPCTSTR pszServerName,
	const LPCTSTR pszUserName, const LPCTSTR pszPassWord)
{
	RASENTRY rasEntry;
	DWORD dwResult;

	ZeroMemory(&rasEntry, sizeof(rasEntry));

	rasEntry.dwCountryCode = 86;
	rasEntry.dwCountryID = 86;
	rasEntry.dwDialExtraPercent = 75;
	rasEntry.dwDialExtraSampleSeconds = 120;
	rasEntry.dwDialMode = RASEDM_DialAll;
	rasEntry.dwType = RASET_Vpn;
	rasEntry.dwRedialCount = 1;
	rasEntry.dwRedialPause = 60;
	rasEntry.dwSize = sizeof(rasEntry);
	rasEntry.dwfOptions = RASEO_SwCompression | RASEO_RequireEncryptedPw | RASEO_RequireDataEncryption | RASEO_PreviewUserPw | RASEO_RemoteDefaultGateway;

	rasEntry.dwVpnStrategy = VS_Ikev2First;
    rasEntry.dwfNetProtocols = RASNP_Ip;
    rasEntry.dwEncryptionType = ET_Require;    //需要加密
    rasEntry.dwHangUpExtraPercent = 10;
    rasEntry.dwHangUpExtraSampleSeconds = 120;
    lstrcpy(rasEntry.szLocalPhoneNumber, pszServerName);
    lstrcpy(rasEntry.szDeviceType, RASDT_Vpn);
    lstrcpy(rasEntry.szDeviceName, _T("qh_vpn"));

    dwResult = RasSetEntryProperties(NULL, pszEntryName, &rasEntry, sizeof(rasEntry), NULL, 0);
    if (dwResult != 0)
    {
        if (dwResult == ERROR_INVALID_SIZE) {
            printf("error : SetEntryProperties, size: %d\r\n", sizeof(rasEntry));
            DWORD rasEntrySize = 0;
            RasGetEntryProperties(NULL, NULL, NULL, &rasEntrySize, NULL, NULL);
            rasEntry.dwSize = rasEntrySize > sizeof(RASENTRY) ? sizeof(RASENTRY) : rasEntrySize;
            rasEntrySize = rasEntry.dwSize;
            printf("info : SetEntryProperties, rasentry size: %d\r\n", rasEntrySize);
            dwResult = RasSetEntryProperties(NULL, pszEntryName, &rasEntry, rasEntrySize, NULL, 0);
        }

        //std::cout<<_T("error : SetEntryProperties, errorno: ")<<dwResult<<"\r\n";
        printf("error : SetEntryProperties, errorno: %d\r\n", dwResult);
        return dwResult;
    }

    return 0;
}


int GetRasConns(RASCONN** lpRasConn, LPDWORD lpcConnections){
    DWORD dwCb = sizeof(RASCONN);
    DWORD dwRet = ERROR_SUCCESS;

    printf("GetRasConns, dwCb=%d\r\n", dwCb);

    *lpRasConn = (LPRASCONN)HeapAlloc(GetProcessHeap(), 0, dwCb);
    if (*lpRasConn == NULL){
        printf("HeapAlloc failed!\n");
        return ERROR_ALLOCATING_MEMORY;
    }
    dwRet = RasEnumConnections(*lpRasConn, &dwCb, lpcConnections);

    printf("RasEnumConnections1, ret=%d dwCb=%d connections=%d\r\n", dwRet, dwCb, *lpcConnections);

    if (dwRet == ERROR_BUFFER_TOO_SMALL || dwRet == ERROR_INVALID_SIZE)
    {
        HeapFree(GetProcessHeap(), 0, *lpRasConn);

        *lpRasConn = (LPRASCONN)HeapAlloc(GetProcessHeap(), 0, dwCb);
        if (*lpRasConn == NULL){
            printf("HeapAlloc failed!\n");
            return ERROR_ALLOCATING_MEMORY;
        }
        (*lpRasConn)->dwSize = dwCb;
        dwRet = RasEnumConnections(*lpRasConn, &dwCb, lpcConnections);
    }

    //std::cout<<_T("RasEnumConnections, ret: ")<<dwRet<<"\r\n";
    printf("RasEnumConnections, ret = %d\r\n", dwRet);

    return dwRet;
}

//
//
//
int CheckConnect(const LPCTSTR pszEntryName){
    RASCONN* rasConn;

    DWORD dwConnections = 0;

    int ret = GetRasConns(&rasConn, &dwConnections);
    if (ERROR_SUCCESS == ret)
    {
        ret = 1;
        for (DWORD i = 0; i < dwConnections; i++)
        {
            if (_tcscmp((rasConn)[i].szEntryName, pszEntryName) == 0){
                ret = 0;
                break;
            }
        }
    }

    if (NULL != rasConn)
    {
        HeapFree(GetProcessHeap(), 0, rasConn);
        rasConn = NULL;
    }
    return ret;
}

int CloseVPN(const LPCTSTR pszEntryName){
    RASCONN* rasConn;

    DWORD dwConnections = 0;

    int ret = GetRasConns(&rasConn, &dwConnections);
    if (ERROR_SUCCESS == ret)
    {
        for (DWORD i = 0; i < dwConnections; i++)
        {
            if (_tcscmp((rasConn)[i].szEntryName, pszEntryName) == 0){
                RasHangUp(rasConn[i].hrasconn);
                break;
            }
        }
    }
    if (NULL != rasConn)
    {
        HeapFree(GetProcessHeap(), 0, rasConn);
        rasConn = NULL;
    }
    return ret;
}

void WINAPI RasDialFunc(UINT unMsg, RASCONNSTATE rasconnstate, DWORD dwError)
{
	wchar_t szRasString[256] = { 0 }; // Buffer for storing the error string
	wchar_t szTempBuf[256] = { 0 };  // Buffer used for printing out the text
	if (dwError)  // Error occurred
	{
		RasGetErrorString(static_cast<UINT>(dwError), reinterpret_cast<LPWSTR>(szRasString), 256);
		ZeroMemory(static_cast<LPVOID>(szTempBuf), sizeof(szTempBuf));
		std::cout << szRasString;
		return;
	}

	// Map each of the states of RasDial() and display on the screen
	// the next state that RasDial() is entering
	switch (rasconnstate)
	{
	case RASCS_OpenPort:
		std::cout << "RASCS_OpenPort = " << rasconnstate;
		std::cout << "Opening port...";
		std::cout << std::endl;
		//g_pFrame->setUserInfo("test","test","test","test","test");
		break;
	case RASCS_PortOpened:
		std::cout << "RASCS_PortOpened = " << rasconnstate;
		std::cout << "Port opened.";
		std::cout << std::endl;
		break;
	case RASCS_ConnectDevice:
		std::cout << "RASCS_ConnectDevice = " << rasconnstate;
		std::cout << "Connecting device...";
		std::cout << std::endl;
		break;
	case RASCS_DeviceConnected:
		std::cout << "RASCS_DeviceConnected = " << rasconnstate;
		std::cout << "Device connected.";
		std::cout << std::endl;
		break;
	case RASCS_AllDevicesConnected:
		std::cout << "RASCS_AllDevicesConnected = " << rasconnstate;
		std::cout << "All devices connected.";
		std::cout << std::endl;
		break;
	case RASCS_Authenticate:
		std::cout << "RASCS_Authenticate = " << rasconnstate;
		std::cout << "Authenticating...";
		std::cout << std::endl;
		break;
	case RASCS_AuthNotify:
		std::cout << "RASCS_AuthNotify = " << rasconnstate;
		std::cout << "Authentication notify.";
		std::cout << std::endl;
		break;
	case RASCS_AuthRetry:
		std::cout << "RASCS_AuthRetry = \n" << rasconnstate;
		std::cout << "Retrying authentication...";
		std::cout << std::endl;
		break;
	case RASCS_AuthCallback:
		std::cout << "RASCS_AuthCallback = " << rasconnstate;
		std::cout << "Authentication callback...";
		std::cout << std::endl;
		break;
	case RASCS_AuthChangePassword:
		std::cout << "RASCS_AuthChangePassword = " << rasconnstate;
		std::cout << "Change password...";
		std::cout << std::endl;
		break;
	case RASCS_AuthProject:
		std::cout << "RASCS_AuthProject = " << rasconnstate;
		std::cout << "Projection phase started...";
		std::cout << std::endl;
		break;
	case RASCS_AuthLinkSpeed:
		std::cout << "RASCS_AuthLinkSpeed = " << rasconnstate;
		std::cout << "Negoting speed...";
		std::cout << std::endl;
		break;
	case RASCS_AuthAck:
		std::cout << "RASCS_AuthAck = " << rasconnstate;
		std::cout << "Authentication acknowledge...";
		std::cout << std::endl;
		break;
	case RASCS_ReAuthenticate:
		std::cout << "RASCS_ReAuthenticate = " << rasconnstate;
		std::cout << "Retrying Authentication...";
		std::cout << std::endl;
		break;
	case RASCS_Authenticated:
		std::cout << "RASCS_Authenticated = " << rasconnstate;
		std::cout << "Authentication complete.";
		std::cout << std::endl;
		break;
	case RASCS_PrepareForCallback:
		std::cout << "RASCS_PrepareForCallback = " << rasconnstate;
		std::cout << "Preparing for callback...";
		std::cout << std::endl;
		break;
	case RASCS_WaitForModemReset:
		std::cout << "RASCS_WaitForModemReset = " << rasconnstate;
		std::cout << "Waiting for modem reset...";
		std::cout << std::endl;
		break;
	case RASCS_WaitForCallback:
		std::cout << "RASCS_WaitForCallback = " << rasconnstate;
		std::cout << "Waiting for callback...";
		std::cout << std::endl;
		break;
	case RASCS_Projected:
		std::cout << "RASCS_Projected = " << rasconnstate;
		std::cout << "Projection completed.";
		std::cout << std::endl;
		break;
	case RASCS_StartAuthentication:// Windows 95 only
		std::cout << "RASCS_StartAuthentication = " << rasconnstate;
		std::cout << "Starting authentication...";
		std::cout << std::endl;
		break;
	case RASCS_CallbackComplete:   // Windows 95 only
		std::cout << "RASCS_CallbackComplete = " << rasconnstate;
		std::cout << "Callback complete.";
		std::cout << std::endl;
		break;
	case RASCS_LogonNetwork:   // Windows 95 only
		std::cout << "RASCS_LogonNetwork = " << rasconnstate;
		std::cout << "Login to the network.";
		std::cout << std::endl;
		break;
	case RASCS_SubEntryConnected:
		std::cout << "RASCS_SubEntryConnected = " << rasconnstate;
		std::cout << "Subentry connected.";
		std::cout << std::endl;
		break;
	case RASCS_SubEntryDisconnected:
		std::cout << "RASCS_SubEntryDisconnected = " << rasconnstate;
		std::cout << "Subentry disconnected.";
		std::cout << std::endl;
		break;
		//PAUSED STATES:
	case RASCS_Interactive:
		std::cout << "RASCS_Interactive = " << rasconnstate;
		std::cout << "In Paused state: Interactive mode.";
		std::cout << std::endl;
		break;
	case RASCS_RetryAuthentication:
		std::cout << "RASCS_RetryAuthentication = " << rasconnstate;
		std::cout << "In Paused state: Retry Authentication...";
		std::cout << std::endl;
		break;
	case RASCS_CallbackSetByCaller:
		std::cout << "RASCS_CallbackSetByCaller = " << rasconnstate;
		std::cout << "In Paused state: Callback set by Caller.";
		std::cout << std::endl;
		break;
	case RASCS_PasswordExpired:
		std::cout << "RASCS_PasswordExpired = " << rasconnstate;
		std::cout << "In Paused state: Password has expired...";
		std::cout << std::endl;
		break;
	case RASCS_Connected: // = RASCS_DONE:
		std::cout << "RASCS_Connected = " << rasconnstate;
		std::cout << "#########Connection completed.";
		//SetEvent(gEvent_handle);
		std::cout << std::endl;
		break;
	case RASCS_Disconnected:
		std::cout << "RASCS_Disconnected = " << rasconnstate;
		std::cout << "Disconnecting...";
		std::cout << std::endl;
		break;
	default:
		std::cout << "Unknown Status = " << rasconnstate;
		std::cout << "What are you going to do about it?";
		std::cout << std::endl;
		break;
	}

}

int DoConnectVPN(const LPCTSTR pszEntryName, const LPCTSTR pszServerName,
    const LPCTSTR pszUserName, const LPCTSTR pszPassWord, LPHRASCONN lphRasConn)
{
    RASDIALPARAMS RasDialParams;
    ZeroMemory(&RasDialParams, sizeof(RASDIALPARAMS));
    RasDialParams.dwSize = sizeof(RASDIALPARAMS);
    lstrcpy(RasDialParams.szEntryName, pszEntryName);
    lstrcpy(RasDialParams.szPhoneNumber, pszServerName);
    lstrcpy(RasDialParams.szUserName, pszUserName);
    lstrcpy(RasDialParams.szPassword, pszPassWord);

    DWORD ret = RasDial(NULL, NULL, &RasDialParams, 0, NULL, lphRasConn);
    //std::cout<<_T("RasDial, ret: ")<<ret<<"\r\n";
    printf("RasDial! ret = %d\r\n", ret);
    return ret;
}

int DeleteVPN(const LPCTSTR pszEntryName){

    CloseVPN(pszEntryName);

    int ret = RasDeleteEntry(NULL, pszEntryName);
    if (ret == ERROR_CANNOT_DELETE){
        HRASCONN hRasConn = NULL;
        DoConnectVPN(pszEntryName, NULL, NULL, NULL, &hRasConn);
        if (NULL != hRasConn){
            RasHangUp(hRasConn);
            ret = RasDeleteEntry(NULL, pszEntryName);
        }
    }
    return ret;
}

int GetVPN(const LPCTSTR pszEntryName)
{
    DWORD rasEntrySize = 0;
    RASENTRY rasEntry;
    ZeroMemory(&rasEntry, sizeof(RASENTRY));

    int ret = RasGetEntryProperties(NULL, NULL, NULL, &rasEntrySize, NULL, NULL);
    printf("RasGetEntryProperties! EntrySize=%d ret = %d\r\n", rasEntrySize, ret);
    if (ret == ERROR_BUFFER_TOO_SMALL || ret == ERROR_INVALID_SIZE)
    {
        rasEntry.dwSize = rasEntrySize > sizeof(RASENTRY) ? sizeof(RASENTRY) : rasEntrySize;
        rasEntrySize = rasEntry.dwSize;
    }

    ret = RasGetEntryProperties(NULL, pszEntryName, &rasEntry, &rasEntrySize, NULL, NULL);

    //std::cout<<_T("RasGetEntryProperties, ret: ")<<ret<<"\r\n";
    printf("RasGetEntryProperties! ret=%d EntrySize=%d sizeof(RASENTRY)=%d \r\n", ret, rasEntrySize, sizeof(RASENTRY));
    return ret;
}

int ConnectVPN(const LPCTSTR pszEntryName, const LPCTSTR pszServerName,
    const LPCTSTR pszUserName, const LPCTSTR pszPassWord)
{
    int ret = 0;

    if (CheckConnect(pszEntryName) == 0) return 0;

    if (GetVPN(pszEntryName))
    {
        ret = CreateVPN(pszEntryName, pszServerName, pszUserName, pszPassWord);
        if (ret != 0)
        {
            return ret;
        }
    }

    HRASCONN hRasConn = NULL;
    ret = DoConnectVPN(pszEntryName, pszServerName, pszUserName, pszPassWord, &hRasConn);
    if (ret != ERROR_SUCCESS && NULL != hRasConn){
        RasHangUp(hRasConn);
    }
    return ret;
}

void test() {
	int ret = 0;
	//ret = DeleteVPN(L"qh_vpn1");
	if (ret != 0) {
		std::cout << " DeleteVPN failed!" << "\r\n";
	}
	ret = ConnectVPN(L"qh_vpn1", L"192.81.220.119", L"myUserName", L"myUserPass");
	if (ret != 0) {
		std::cout << " ConnectVPN failed!" << "\r\n";
	}
}

int _tmain(int argc, _TCHAR* argv[])
{
	/*test();
	return 0;*/
	ImportCert();
    if (argc == 3 && _tcsicmp(argv[2], _T("/DELVPN")) == 0){
        return DeleteVPN(argv[1]);
    }
    else if (argc == 5){
        return ConnectVPN(argv[1], argv[2], argv[3], argv[4]);
    }
    else{
		//connVPN.exe qh_vpn1 192.81.220.119 myUserName myUserPass
        std::cout << "connVPN usage:" << "\r\n";
        std::cout << "              EntryName ServerName UserName PassWord" << "\r\n";
        std::cout << "\r\n";
        std::cout << "              EntryName /DELVPN" << "\r\n";
        return -1;
    }
    return 0;
}
