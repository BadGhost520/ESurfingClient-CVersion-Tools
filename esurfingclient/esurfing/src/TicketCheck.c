#include "TicketCheck.h"

#include "AlgoFinder.h"
#include "NetClient.h"
#include "cipher/CipherInterface.h"
#include "utils/Utils.h"
#include "utils/sim/SimEvp.h"

#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>

#ifdef _WIN32
#include <direct.h>
#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>
#include <winternl.h>
#else
#include <sys/stat.h>
#include <unistd.h>
#endif

#define TICKET_REQUEST_RETRY 3
#define TICKET_REQUEST_DELAY_MS 300
#define TICKET_DUMP_DIR "ticket_failed_dumps"

/* 功能 4 直连使用：必须是服务端认可的 client-id，不能每次随机 */
#define DIRECT_CLIENT_ID "047eb6a0-8b54-4658-b97b-1e666a8938fe"
#define DIRECT_TICKET_URL "http://14.146.227.141:7001/ticket.cgi?wlanuserip=172.19.208.191&wlanacip=14.148.0.67"

#define TICKET_XML_LEN 1024
#define TICKET_ACCEPT "text/html,text/xml,application/xhtml+xml,application/x-javascript,*/*"
#define TICKET_SCHOOL_ID "221"
#define TICKET_DOMAIN "zsdzkd"
#define TICKET_AREA "0760"
#define MAX_GROUP_IDS 128
#define SAMPLE_BATCH_SIZE 24

typedef enum
{
    CIPHER_MODE_AUTO = 0,   /* 先硬编码，缺失时回退 ZSM（功能 3 硬编码模式） */
    CIPHER_MODE_HARDCODED,  /* 只允许硬编码 */
    CIPHER_MODE_DYNAMIC     /* 只允许从 ZSM 动态解析 */
} cipher_mode_t;

static volatile sig_atomic_t s_ticket_stop = 0;

static void on_ticket_sigint(int sig)
{
    (void)sig;
    s_ticket_stop = 1;
}

static const char* const WINDOWS_IDS[] = {
    "023BD049-E130-4FBF-AB73-800FA2E38948",
    "03F8A638-5C23-418B-972C-A2BA6927EF77",
    "066474E5-503E-4B82-98C4-DF4483DAF0B5",
    "079637D7-A2A2-41CE-A50D-4CAD3B2334E7",
    "0A2375CB-1F91-4064-B00F-1CF3A1AF6E4A",
    "0A4E0BB5-A13D-4FB1-A5C5-D78F1D92CE64",
    "0E045477-EF58-46D8-BEE5-8D9D577C91F3",
    "11734889-14D8-48FA-ACEC-36452CA3FE8D",
    "1401F41B-06EA-4236-8E68-7AA1555A7C28",
    "23CBE797-3BC2-4FCF-A589-23C3D31BCED7",
    "262A30B9-FE27-4206-B57A-3CB44E2A1138",
    "466FBBBF-E526-4A13-A306-6AF402688F5E",
    "46D3C896-2B45-41B2-91B6-A5C9718EF7CD",
    "47C78640-9E7D-4115-B140-BE2DF6C49BF9",
    "4C0EAF45-8E70-45C2-BD82-52C834005758",
    "4FE47EF4-1BDC-43DE-AF53-4D6C30DA9ACD",
    "50495282-EDFD-4371-B4FE-6706326B2F12",
    "51A47203-4DCB-4A5A-9838-C452FD2774DC",
    "52116A19-3222-40F0-A117-DC377BED0D3E",
    "5678F2AA-C270-4F0A-9CB3-AE7A5D912FCD",
    "5D79B368-0B90-4194-8437-AB0571DF0BD5",
    "6067E3B6-3AB5-45AE-8CEC-E8DACB3C76DE",
    "68361562-0864-4EB3-8508-9CDE34269D8C",
    "6C5CF775-8F43-4CAA-856E-2845431B4CC0",
    "7809936E-EA7E-4BA2-AD3B-5621259530FC",
    "7A16C88E-1E0C-4C4E-8702-E76D7C743C01",
    "7EDCC3AB-5B1B-409A-A5E3-E9623A5EC1B7",
    "8F950701-C9FC-45A5-9780-7305FE025D4E",
    "A7984530-FDA0-455C-ACAC-19854FB7A659",
    "AA4D098D-336C-4523-AD31-C99D3F1514CA",
    "B453C03E-871D-4B13-8AD1-EB61162F2EED",
    "BE5EC2E8-248A-4868-9A34-B53BE5FDB887",
    "C12422B4-A6B9-4977-952B-D6627D482627",
    "CA582532-4E58-448A-976B-4E1E9809966B",
    "CA9A519E-AD98-401B-8111-83EFC3C76F7C",
    "CF750526-3D99-44BE-A0DE-09DEADC97D52",
    "D245DD7B-900F-456C-9ED5-8C094E8E240C",
    "DA2B057E-5D9E-48BC-B2BC-EA43D8D2A65E",
    "DDE9BF30-FBD3-4184-9B38-8855C1F47FD1",
    "EB353E96-94B2-486C-9FA6-31A37C222EA7",
    "EBD34028-0E59-4B21-86EB-CF892E75F6FF",
    "EC4D2CF4-EC20-4DCA-B35D-097F9C2370FC",
    "ECE4A1E8-A530-48B2-B968-F503CB1CBAAC",
    "EE0D4296-FC76-4BBB-8E0D-B03DB50776F2",
    "F0DA8287-3EF6-4C7C-BD59-B9542BC16898",
    "F1C01068-FFAB-4E4E-A043-0B06B2299AF4",
    "F3557D5A-9F79-4A63-A152-4A939FCC96F9",
    "F9A253A7-4D9E-4ED3-BA0F-118E56D34267",
    "FC05D786-59A7-4469-B276-0D9B89EAD057",
    "FF25BFEC-B03C-4EF0-8487-71D41E04FF65",
};

static const char* const WINDOWS_SERVER0_IDS[] = {
    "03F8A638-5C23-418B-972C-A2BA6927EF77",
    "066474E5-503E-4B82-98C4-DF4483DAF0B5",
    "079637D7-A2A2-41CE-A50D-4CAD3B2334E7",
    "0A2375CB-1F91-4064-B00F-1CF3A1AF6E4A",
    "11734889-14D8-48FA-ACEC-36452CA3FE8D",
    "1401F41B-06EA-4236-8E68-7AA1555A7C28",
    "466FBBBF-E526-4A13-A306-6AF402688F5E",
    "46D3C896-2B45-41B2-91B6-A5C9718EF7CD",
    "47C78640-9E7D-4115-B140-BE2DF6C49BF9",
    "50495282-EDFD-4371-B4FE-6706326B2F12",
    "5678F2AA-C270-4F0A-9CB3-AE7A5D912FCD",
    "6067E3B6-3AB5-45AE-8CEC-E8DACB3C76DE",
    "68361562-0864-4EB3-8508-9CDE34269D8C",
    "7809936E-EA7E-4BA2-AD3B-5621259530FC",
    "7EDCC3AB-5B1B-409A-A5E3-E9623A5EC1B7",
    "B453C03E-871D-4B13-8AD1-EB61162F2EED",
    "CA582532-4E58-448A-976B-4E1E9809966B",
    "CF750526-3D99-44BE-A0DE-09DEADC97D52",
    "DDE9BF30-FBD3-4184-9B38-8855C1F47FD1",
    "EB353E96-94B2-486C-9FA6-31A37C222EA7",
    "EBD34028-0E59-4B21-86EB-CF892E75F6FF",
    "ECE4A1E8-A530-48B2-B968-F503CB1CBAAC",
    "EE0D4296-FC76-4BBB-8E0D-B03DB50776F2",
    "F1C01068-FFAB-4E4E-A043-0B06B2299AF4",
    "FC05D786-59A7-4469-B276-0D9B89EAD057",
};

static const char* const WINDOWS_SERVER1_IDS[] = {
    "023BD049-E130-4FBF-AB73-800FA2E38948",
    "0A4E0BB5-A13D-4FB1-A5C5-D78F1D92CE64",
    "0E045477-EF58-46D8-BEE5-8D9D577C91F3",
    "23CBE797-3BC2-4FCF-A589-23C3D31BCED7",
    "262A30B9-FE27-4206-B57A-3CB44E2A1138",
    "4C0EAF45-8E70-45C2-BD82-52C834005758",
    "4FE47EF4-1BDC-43DE-AF53-4D6C30DA9ACD",
    "51A47203-4DCB-4A5A-9838-C452FD2774DC",
    "52116A19-3222-40F0-A117-DC377BED0D3E",
    "5D79B368-0B90-4194-8437-AB0571DF0BD5",
    "6C5CF775-8F43-4CAA-856E-2845431B4CC0",
    "7A16C88E-1E0C-4C4E-8702-E76D7C743C01",
    "8F950701-C9FC-45A5-9780-7305FE025D4E",
    "A7984530-FDA0-455C-ACAC-19854FB7A659",
    "AA4D098D-336C-4523-AD31-C99D3F1514CA",
    "BE5EC2E8-248A-4868-9A34-B53BE5FDB887",
    "C12422B4-A6B9-4977-952B-D6627D482627",
    "CA9A519E-AD98-401B-8111-83EFC3C76F7C",
    "D245DD7B-900F-456C-9ED5-8C094E8E240C",
    "DA2B057E-5D9E-48BC-B2BC-EA43D8D2A65E",
    "EC4D2CF4-EC20-4DCA-B35D-097F9C2370FC",
    "F0DA8287-3EF6-4C7C-BD59-B9542BC16898",
    "F3557D5A-9F79-4A63-A152-4A939FCC96F9",
    "F9A253A7-4D9E-4ED3-BA0F-118E56D34267",
    "FF25BFEC-B03C-4EF0-8487-71D41E04FF65",
};

static const char* const WINDOWS_EXCLUDED_IDS[] = {
    "014AC5DB-0B7C-4F05-B21E-55C2535B3A01",
    "04DB9EC7-155A-4482-B6A4-1F37A3B905A4",
    "054DDD03-911E-49F5-89D6-EFBF5055FBFF",
    "083B005A-7ACA-419A-AC00-6929C0AADB55",
    "08BDB042-5D25-4397-875F-357E9F7700C8",
    "10FD0A56-0044-45F0-A342-7CE242B1A427",
    "14D50A01-FB30-4ED0-B287-96286E3091C1",
    "14F3C2A4-19E9-4C4D-A5C1-E5A316C884F0",
    "1B652785-1153-4741-8A1C-2D9E752BE0E5",
    "2C2C4070-6644-4E84-BDBD-1760A2DA875C",
    "2E86DCEE-4E28-4AC2-A3FB-19F68115141E",
    "32C8C121-2467-42C4-A09D-1B0BA754D18F",
    "37620C35-7A97-4A4F-9EF3-822DD38FE211",
    "376412D4-ACA3-4452-8A79-4589B3817760",
    "3FBF4B5E-972D-43EF-A454-46E6BE15B329",
    "42184E84-A844-486E-83C3-4CB9FD874D67",
    "52271930-386B-4EC7-B5E9-7DEF7C1C11A8",
    "578FDB96-AF47-461D-AC36-D08EADF10130",
    "58FD3FCA-C8BC-4547-9DA5-6FAEE884F26E",
    "6B4D085A-17D5-4404-94BE-FD5FED11007F",
    "6BB82AD9-D331-4BE8-BC52-C1F56E351C1C",
    "6DF91D90-3324-4064-BBA8-EFF3820BDF1E",
    "70CDBBAB-C9C9-49DE-A8D9-068579EAFFD0",
    "76C9B8BC-FCAA-445A-93CC-D22B9413159D",
    "76CD0763-8C5F-49B0-85CD-549BB32886A2",
    "78AD4214-E71F-421A-A13B-C65EC32890C3",
    "79F1CC4F-A213-4DE0-AAED-A276D2E1F21F",
    "7DE2123D-3868-4D5E-86A1-687FE2683476",
    "7F224CA8-0DF5-47C6-9195-2D335E31D882",
    "895E36A7-0175-4EF2-A00D-7F3482D70D72",
    "9E6620CB-628D-49CA-80DD-9E6BCA401A31",
    "A1DFF4B8-770B-4EB3-9F79-719F2196E315",
    "A7BBDBD5-DB4C-46A8-91E8-E4C8003C8CDD",
    "ABA03E9C-E7E3-4AD0-94F9-4224DAA975C4",
    "AF69A651-96D0-4B88-B388-644CB6822159",
    "BFAC1582-AA39-4CBC-AD0E-6D37ACDA369B",
    "C8E20AA2-0254-4C36-ACF1-EF4779934D08",
    "CAC870CA-C03D-475A-8CB0-F4E9C80B9153",
    "DF011932-AFC2-447D-948D-A21EFA7411B8",
    "DF4FF2CD-3387-4377-9A91-E90E05081073",
    "DF92372F-EF9B-44FC-ABB4-EC5625DE60B6",
    "E2BC8BAC-D7E0-4DAD-9400-789C63D6A0DC",
    "E51E14F1-BCB1-45F4-8FF6-3992CA3FCD05",
    "E9747EF1-6849-4F87-957B-3B93E6A90393",
    "EA85A478-CDD9-483C-98C4-4CEE1347C9B9",
    "F1D8F312-EADC-4803-9B47-9C7684B2156F",
    "F6B5CFB0-17FD-453C-9791-B2887E2C9859",
    "FE8F87FC-726F-4303-B15D-88A9F5B63174",
    "FEE5E4DA-50A0-4ECD-8392-92E09CB1B775",
    "FF5F345F-B580-43DF-9ED3-D92FAE586133",
};

static const char* const IOS_IDS[] = {
    "2E75BFA5-76C5-4691-BBF5-A49C94908464",
    "4D10D93E-5A68-46D4-83EA-49E7C4933C91",
    "E2F8C4B2-2742-4690-9BD5-BBAB926FB9E8",
};

static const char* const MACOS_IDS[] = {
    "634D7C6F-581F-47CC-959C-D9265EDAB9B4",
    "7781847B-446E-4CF7-A418-79989EFA1B00",
    "E366503B-B6E5-40A5-BCE1-39001D18D90E",
};

static const char* const ANDROID_OLD_IDS[] = {
    "CAFBCBAD-B6E7-4CAB-8A67-14D39F00CE1E",
    "A474B1C2-3DE0-4EA2-8C5F-7093409CE6C4",
    "5BFBA864-BBA9-42DB-8EAD-49B5F412BD81",
    "6E0B65FF-0B5B-459C-8FCE-EC7F2BEA9FF5",
    "B809531F-0007-4B5B-923B-4BD560398113",
    "F3974434-C0DD-4C20-9E87-DDB6814A1C48",
    "ED382482-F72C-4C41-A76D-28EEA0F1F2AF",
    "B3047D4E-67DF-4864-A6A5-DF9B9E525C79",
    "C32C68F9-CA81-4260-A329-BBAFD1A9CCD1",
};

static const char* const ANDROID_NEW_IDS[] = {
    "07E824B2-9E5C-4D1B-BBB0-5E07C251E4AA",
    "319FC5AB-EC0E-46B9-A252-2285F9DAE813",
    "D6544CFE-F2DE-459B-9B77-0F2B367EF169",
    "D755A536-B551-468C-BD87-322182B223D4",
    "BB2EA626-590B-4C42-82BE-E052FCBBB88E",
    "DEABB8C8-A2BC-48CA-8ED0-8CDF1BD62F61",
    "9ABF4D29-34DB-4CE9-BB8C-7E371D637758",
    "AD8BB5B0-0E72-4198-A362-96D52C1B7ED1",
    "35101415-A20F-4DFE-B00B-0B4F3B2F8C66",
};

static const char* const LINUX_IDS[] = {
    "1A7343EC-7F9B-4570-BF58-16279A81116B",
    "4BA5496A-2123-46A7-85F2-35956EA7BE39",
    "45433DCF-9ECA-4BE5-83F2-F92BA0B4F291",
    "60639D8B-272E-4A4D-976E-AA270987A169",
    "AB6C8EBE-B8F8-4C08-8222-69A3B5E86A91",
    "B306E770-B7D5-49F2-A574-BCE2C5C650ED",
};

typedef struct
{
    const char* name;
    const char* file_tag;
    const char* const* ids;
    size_t count;
} ticket_group_t;

#define GROUP_ENTRY(name, tag, ids) { name, tag, ids, sizeof(ids) / sizeof(ids[0]) }

static const ticket_group_t s_groups[] = {
    GROUP_ENTRY("Windows", "windows", WINDOWS_IDS),
    GROUP_ENTRY("iOS", "ios", IOS_IDS),
    GROUP_ENTRY("macOS", "macos", MACOS_IDS),
    GROUP_ENTRY("Android 旧版", "android_old", ANDROID_OLD_IDS),
    GROUP_ENTRY("Android 新版", "android_new", ANDROID_NEW_IDS),
    GROUP_ENTRY("Linux", "linux", LINUX_IDS),
};

static void sleep_ms(const unsigned ms)
{
#ifdef _WIN32
    Sleep(ms);
#else
    usleep(ms * 1000);
#endif
}

static void url_param(const char* url, const char* key, char* out, const size_t out_len)
{
    const size_t key_len = strlen(key);
    const char* p = url;

    if (out == NULL || out_len == 0) return;
    out[0] = '\0';
    if (url == NULL || key == NULL) return;

    while ((p = strstr(p, key)) != NULL)
    {
        const bool at_boundary = (p == url) || p[-1] == '?' || p[-1] == '&';
        if (at_boundary && p[key_len] == '=')
        {
            const char* value = p + key_len + 1;
            size_t len = 0;
            while (value[len] != '\0' && value[len] != '&' && value[len] != '#') len++;
            if (len >= out_len) len = out_len - 1;
            memcpy(out, value, len);
            out[len] = '\0';
            return;
        }
        p += key_len;
    }
}

static void uuid_to_hex(const char* uuid, char* hex, const size_t hex_len)
{
    size_t j = 0;

    if (hex == NULL || hex_len == 0) return;
    for (size_t i = 0; uuid != NULL && uuid[i] != '\0' && j + 1 < hex_len; i++)
    {
        if (uuid[i] != '-') hex[j++] = uuid[i];
    }
    hex[j] = '\0';
}

static void md5_hex(const char* data, char out[33])
{
    unsigned char digest[16];

    simssl_md5((const unsigned char*)data, strlen(data), digest);
    for (int i = 0; i < 16; i++) snprintf(out + i * 2, 3, "%02x", digest[i]);
    out[32] = '\0';
}

static char* extract_tag(const char* xml, const char* tag)
{
    char start[64];
    char end[64];
    const char* p;
    const char* q;
    size_t len;
    char* value;

    if (xml == NULL || tag == NULL) return NULL;
    snprintf(start, sizeof(start), "<%s>", tag);
    snprintf(end, sizeof(end), "</%s>", tag);
    p = strstr(xml, start);
    if (p == NULL) return NULL;
    p += strlen(start);
    q = strstr(p, end);
    if (q == NULL || q <= p) return NULL;

    len = (size_t)(q - p);
    value = malloc(len + 1);
    if (value == NULL) return NULL;
    memcpy(value, p, len);
    value[len] = '\0';
    return value;
}

static const char BASE62_ALPHABET[] =
    "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

static unsigned hex_nibble(const char c)
{
    if (c >= '0' && c <= '9') return (unsigned)(c - '0');
    if (c >= 'a' && c <= 'f') return (unsigned)(c - 'a' + 10);
    if (c >= 'A' && c <= 'F') return (unsigned)(c - 'A' + 10);
    return 0;
}

static void fallback_mac(char* mac, const size_t mac_len, const char* hex)
{
    snprintf(mac, mac_len, "%c%c-%c%c-%c%c-%c%c-%c%c-%c%c",
        (char)toupper((unsigned char)hex[0]), (char)toupper((unsigned char)hex[1]),
        (char)toupper((unsigned char)hex[2]), (char)toupper((unsigned char)hex[3]),
        (char)toupper((unsigned char)hex[4]), (char)toupper((unsigned char)hex[5]),
        (char)toupper((unsigned char)hex[6]), (char)toupper((unsigned char)hex[7]),
        (char)toupper((unsigned char)hex[8]), (char)toupper((unsigned char)hex[9]),
        (char)toupper((unsigned char)hex[10]), (char)toupper((unsigned char)hex[11]));
}

#ifdef _WIN32
static void official_host_name(char* host_name, const size_t host_name_len, const char* fallback)
{
    DWORD size = (DWORD)host_name_len;
    if (host_name_len == 0) return;
    if (GetComputerNameA(host_name, &size) == 0 || host_name[0] == '\0')
        snprintf(host_name, host_name_len, "%.10s", fallback);
}

static void official_os_tag(char* ostag, const size_t ostag_len)
{
    OSVERSIONINFOW os;
    const char* name = "Windows";
    const char* bits = "32";
    SYSTEM_INFO si;

    ZeroMemory(&os, sizeof(os));
    os.dwOSVersionInfoSize = sizeof(os);

    typedef LONG (WINAPI * RtlGetVersionFn)(OSVERSIONINFOW*);
    RtlGetVersionFn rtl_get_version = (RtlGetVersionFn)GetProcAddress(
        GetModuleHandleA("ntdll.dll"), "RtlGetVersion");
    if (rtl_get_version == NULL || rtl_get_version(&os) != 0)
    {
        ZeroMemory(&os, sizeof(os));
        os.dwOSVersionInfoSize = sizeof(os);
        GetVersionExW(&os);
    }

    if (os.dwMajorVersion == 10 && os.dwBuildNumber >= 22000) name = "Windows 11";
    else if (os.dwMajorVersion == 10) name = "Windows 10";
    else if (os.dwMajorVersion == 6 && os.dwMinorVersion == 3) name = "Windows 8.1";
    else if (os.dwMajorVersion == 6 && os.dwMinorVersion == 2) name = "Windows 8";
    else if (os.dwMajorVersion == 6 && os.dwMinorVersion == 1) name = "Windows 7";

    GetNativeSystemInfo(&si);
    if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64)
        bits = "64";
#ifdef PROCESSOR_ARCHITECTURE_ARM64
    else if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM64)
        bits = "64";
#endif

    snprintf(ostag, ostag_len, "%s(%lu),%s bit ", name,
        (unsigned long)os.dwBuildNumber, bits);
}

static bool adapter_has_ipv4(const IP_ADAPTER_ADDRESSES* a, const char* client_ip)
{
    IP_ADAPTER_UNICAST_ADDRESS* u;
    ULONG want;

    if (a == NULL || client_ip == NULL || client_ip[0] == '\0') return false;
    want = inet_addr(client_ip);
    if (want == INADDR_NONE) return false;

    for (u = a->FirstUnicastAddress; u != NULL; u = u->Next)
    {
        const struct sockaddr_in* sin;
        if (u->Address.lpSockaddr == NULL || u->Address.lpSockaddr->sa_family != AF_INET)
            continue;
        sin = (const struct sockaddr_in*)u->Address.lpSockaddr;
        if (sin->sin_addr.s_addr == want) return true;
    }
    return false;
}

static bool is_virtual_mac(const IP_ADAPTER_ADDRESSES* a)
{
    static const unsigned char vnet_ouis[][3] = {
        {0x00, 0x50, 0x56}, /* VMware */
        {0x00, 0x0C, 0x29}, /* VMware */
        {0x00, 0x05, 0x69}, /* VMware */
        {0x00, 0x1C, 0x14}  /* VMware */
    };
    size_t i;

    if (a->PhysicalAddressLength != 6) return true;
    for (i = 0; i < sizeof(vnet_ouis) / sizeof(vnet_ouis[0]); ++i)
    {
        if (memcmp(a->PhysicalAddress, vnet_ouis[i], 3) == 0) return true;
    }
    return false;
}

static bool official_mac(char* mac, const size_t mac_len, const char* client_ip)
{
    ULONG size = 0;
    DWORD rc = GetAdaptersAddresses(AF_UNSPEC, 0, NULL, NULL, &size);
    IP_ADAPTER_ADDRESSES* addrs;
    bool found = false;

    if (rc != ERROR_BUFFER_OVERFLOW || size == 0) return false;
    addrs = (IP_ADAPTER_ADDRESSES*)malloc(size);
    if (addrs == NULL) return false;

    rc = GetAdaptersAddresses(AF_UNSPEC, 0, NULL, addrs, &size);
    if (rc == NO_ERROR)
    {
        int pass;
        for (pass = 0; pass < 2 && !found; ++pass)
        {
            IP_ADAPTER_ADDRESSES* a;
            for (a = addrs; a != NULL; a = a->Next)
            {
                /* Ethernet(6) / IEEE80211(71)，只接受 6 字节物理地址 */
                if (a->IfType != 6 && a->IfType != 71) continue;
                if (a->OperStatus != 1) continue;
                if (a->PhysicalAddressLength != 6) continue;
                if (pass == 0 && !adapter_has_ipv4(a, client_ip)) continue;
                if (pass == 1 && is_virtual_mac(a)) continue;

                snprintf(mac, mac_len, "%02X-%02X-%02X-%02X-%02X-%02X",
                    a->PhysicalAddress[0], a->PhysicalAddress[1],
                    a->PhysicalAddress[2], a->PhysicalAddress[3],
                    a->PhysicalAddress[4], a->PhysicalAddress[5]);
                found = true;
                break;
            }
        }
    }

    free(addrs);
    return found;
}
#endif

/*
 * 官方 Windows 客户端的 local-time 不是标准时间，而是：
 *   8 位 Base62 tick（约 90 秒一个 tick，从客户端启动开始）+ 1 位随机后缀
 * 例：0000001OS / 0000002L6。
 * 这里按同样结构生成，便于验证服务端是否接受这种格式。
 */
static void official_local_time(char* local_time, const size_t local_time_len,
    const char* seed_hex)
{
    uint64_t seconds;
    uint64_t ticks;
    char prefix[9];
    unsigned seed;
    char suffix;

#ifdef _WIN32
    static ULONGLONG start = 0;
    if (start == 0) start = GetTickCount64();
    seconds = (GetTickCount64() - start) / 1000ULL;
#else
    static time_t start = 0;
    time_t now = time(NULL);
    if (start == 0) start = now;
    seconds = (uint64_t)(now - start);
#endif

    ticks = seconds / 90ULL;
    memset(prefix, '0', 8);
    prefix[8] = '\0';
    for (int i = 7; i >= 0 && ticks > 0; --i)
    {
        prefix[i] = BASE62_ALPHABET[ticks % 62];
        ticks /= 62;
    }

    seed = hex_nibble(seed_hex[0]) * 16u + hex_nibble(seed_hex[1]);
    suffix = BASE62_ALPHABET[seed % 62];
    snprintf(local_time, local_time_len, "%s%c", prefix, suffix);
}

static bool fill_identity(const char* url, const char* ua,
    char* host_name, const size_t host_name_len,
    char* ostag, const size_t ostag_len, char* mac, const size_t mac_len,
    char* client_ip, const size_t client_ip_len, char* ac_ip, const size_t ac_ip_len,
    char* local_time, const size_t local_time_len)
{
    char identity[37];
    char identity_hex[33];
    time_t now;
    struct tm local_tm;

    if (generate_uuid(identity, sizeof(identity)) == false) return false;
    uuid_to_hex(identity, identity_hex, sizeof(identity_hex));

    url_param(url, "wlanuserip", client_ip, client_ip_len);
    url_param(url, "wlanacip", ac_ip, ac_ip_len);

#ifdef _WIN32
    official_host_name(host_name, host_name_len, identity_hex);
    official_os_tag(ostag, ostag_len);
    if (official_mac(mac, mac_len, client_ip) == false)
        fallback_mac(mac, mac_len, identity_hex);
#else
    snprintf(host_name, host_name_len, "%.10s", identity_hex);
    snprintf(ostag, ostag_len, "%.10s", identity_hex);
    fallback_mac(mac, mac_len, identity_hex);
#endif

    if (ua != NULL && strstr(ua, "WinSVR") != NULL)
    {
        official_local_time(local_time, local_time_len, identity_hex);
        return true;
    }

    now = time(NULL);
#ifdef _WIN32
    if (localtime_s(&local_tm, &now) != 0) return false;
#else
    if (localtime_r(&now, &local_tm) == NULL) return false;
#endif
    return strftime(local_time, local_time_len, "%Y-%m-%d %H:%M:%S", &local_tm) > 0;
}

#ifdef _WIN32
#define MAKE_DIR(path) _mkdir(path)
#else
#define MAKE_DIR(path) mkdir(path, 0755)
#endif

typedef struct
{
    char* request_headers;
    size_t request_headers_size;
    char* request_body;
    size_t request_body_size;
    char* response_headers;
    size_t response_headers_size;
    char* response_body;
    size_t response_body_size;
    long http_code;
    char error_code[64];
    bool has_request;
    bool has_response;
} ticket_raw_response_t;

static void ticket_raw_free(ticket_raw_response_t* raw)
{
    if (raw == NULL) return;
    free(raw->request_headers);
    free(raw->request_body);
    free(raw->response_headers);
    free(raw->response_body);
    memset(raw, 0, sizeof(*raw));
}

static bool append_text(char** buf, size_t* len, size_t* cap, const char* text)
{
    const size_t text_len = strlen(text);
    if (*len + text_len + 1 > *cap)
    {
        size_t new_cap = *cap == 0 ? 512 : *cap;
        while (new_cap < *len + text_len + 1) new_cap *= 2;
        char* next = realloc(*buf, new_cap);
        if (next == NULL) return false;
        *buf = next;
        *cap = new_cap;
    }
    memcpy(*buf + *len, text, text_len);
    *len += text_len;
    (*buf)[*len] = '\0';
    return true;
}

static void ticket_raw_set_request(ticket_raw_response_t* raw, const char* url,
    const char* const* headers, const char* body)
{
    char* buf = NULL;
    size_t len = 0;
    size_t cap = 0;
    char line[512];

    if (raw == NULL) return;

    free(raw->request_headers);
    free(raw->request_body);
    raw->request_headers = NULL;
    raw->request_headers_size = 0;
    raw->request_body = NULL;
    raw->request_body_size = 0;

    snprintf(line, sizeof(line), "POST %s HTTP/1.1\r\n", url != NULL ? url : "");
    if (append_text(&buf, &len, &cap, line) == false) goto done;

    if (headers != NULL)
    {
        for (size_t i = 0; headers[i] != NULL; i++)
        {
            snprintf(line, sizeof(line), "%s\r\n", headers[i]);
            if (append_text(&buf, &len, &cap, line) == false) goto done;
        }
    }

    snprintf(line, sizeof(line), "Content-Length: %zu\r\n\r\n",
        body != NULL ? strlen(body) : 0);
    if (append_text(&buf, &len, &cap, line) == false) goto done;

    raw->request_headers = buf;
    raw->request_headers_size = len;
    buf = NULL;
    raw->has_request = true;

    if (body != NULL && body[0] != '\0')
    {
        const size_t body_len = strlen(body);
        raw->request_body = malloc(body_len);
        if (raw->request_body != NULL)
        {
            memcpy(raw->request_body, body, body_len);
            raw->request_body_size = body_len;
        }
    }

done:
    free(buf);
}

static void ticket_raw_copy(ticket_raw_response_t* raw, const http_resp_t* resp)
{
    if (raw == NULL || resp == NULL) return;

    free(raw->response_headers);
    free(raw->response_body);
    raw->response_headers = NULL;
    raw->response_headers_size = 0;
    raw->response_body = NULL;
    raw->response_body_size = 0;
    raw->has_response = true;
    raw->http_code = resp->http_code;
    snprintf(raw->error_code, sizeof(raw->error_code), "%s", resp->error_code);

    if (resp->header_data != NULL && resp->header_size > 0)
    {
        raw->response_headers = malloc(resp->header_size);
        if (raw->response_headers != NULL)
        {
            memcpy(raw->response_headers, resp->header_data, resp->header_size);
            raw->response_headers_size = resp->header_size;
        }
    }

    if (resp->request_header_data != NULL && resp->request_header_size > 0)
    {
        char* request_headers = malloc(resp->request_header_size);
        if (request_headers != NULL)
        {
            memcpy(request_headers, resp->request_header_data, resp->request_header_size);
            free(raw->request_headers);
            raw->request_headers = request_headers;
            raw->request_headers_size = resp->request_header_size;
            raw->has_request = true;
        }
    }

    if (resp->body_data != NULL && resp->body_size > 0)
    {
        raw->response_body = malloc(resp->body_size);
        if (raw->response_body != NULL)
        {
            memcpy(raw->response_body, resp->body_data, resp->body_size);
            raw->response_body_size = resp->body_size;
        }
    }
}

static bool write_file(const char* path, const void* data, const size_t len)
{
    FILE* fp = fopen(path, "wb");
    if (fp == NULL) return false;
    if (data != NULL && len > 0) fwrite(data, 1, len, fp);
    fclose(fp);
    return true;
}

static bool save_failed_dump(const char* algo_id, const ticket_raw_response_t* raw)
{
    static bool dir_ready = false;
    char dir[192];
    char path[256];
    char info[512];
    bool ok = true;

    if (!dir_ready)
    {
        MAKE_DIR(TICKET_DUMP_DIR);
        dir_ready = true;
    }

    snprintf(dir, sizeof(dir), "%s/%s", TICKET_DUMP_DIR, algo_id);
    MAKE_DIR(dir);

    snprintf(path, sizeof(path), "%s/request_headers.txt", dir);
    ok &= write_file(path, raw != NULL ? raw->request_headers : NULL,
        raw != NULL ? raw->request_headers_size : 0);

    snprintf(path, sizeof(path), "%s/request_body.bin", dir);
    ok &= write_file(path, raw != NULL ? raw->request_body : NULL,
        raw != NULL ? raw->request_body_size : 0);

    snprintf(path, sizeof(path), "%s/response_headers.txt", dir);
    ok &= write_file(path, raw != NULL ? raw->response_headers : NULL,
        raw != NULL ? raw->response_headers_size : 0);

    snprintf(path, sizeof(path), "%s/response_body.bin", dir);
    ok &= write_file(path, raw != NULL ? raw->response_body : NULL,
        raw != NULL ? raw->response_body_size : 0);

    snprintf(info, sizeof(info),
        "Algo-ID: %s\n"
        "HTTP: %ld\n"
        "Error-Code: %s\n"
        "Request-Headers-Bytes: %zu\n"
        "Request-Body-Bytes: %zu\n"
        "Response-Headers-Bytes: %zu\n"
        "Response-Body-Bytes: %zu\n",
        algo_id,
        raw != NULL ? raw->http_code : 0,
        raw != NULL && raw->error_code[0] != '\0' ? raw->error_code : "(none)",
        raw != NULL ? raw->request_headers_size : 0,
        raw != NULL ? raw->request_body_size : 0,
        raw != NULL ? raw->response_headers_size : 0,
        raw != NULL ? raw->response_body_size : 0);

    snprintf(path, sizeof(path), "%s/info.txt", dir);
    ok &= write_file(path, info, strlen(info));

    if (!ok) printf("         部分 dump 文件写入失败: %s/\n", dir);
    printf("         请求/响应现场: %s/ (请求头 %zu, 请求体 %zu, 响应头 %zu, 响应体 %zu 字节)\n",
        dir,
        raw != NULL ? raw->request_headers_size : 0,
        raw != NULL ? raw->request_body_size : 0,
        raw != NULL ? raw->response_headers_size : 0,
        raw != NULL ? raw->response_body_size : 0);
    return true;
}

static bool response_is_zsm(const char* body, const size_t body_size)
{
    return body != NULL && body_size >= 4 && memcmp(body, "001", 3) == 0;
}

static bool init_dynamic_cipher_for_ua(const char* ua, const char* zsm, const size_t zsm_len,
    char* algo_id_out)
{
    if (zsm == NULL || zsm_len == 0 || algo_id_out == NULL) return false;

    if (strstr(ua, "WinSVR") != NULL)
        return init_win_cipher_from_zsm((const uint8_t*)zsm, zsm_len, algo_id_out);
    if (strstr(ua, "iOSdy") != NULL || strstr(ua, "macdy") != NULL)
        return init_ios_cipher_from_zsm((const uint8_t*)zsm, zsm_len, algo_id_out);
    return false;
}

static bool check_one_id(const char* ua, const char* url, const char* algo_id,
    const char* client_id, const char* zsm, const size_t zsm_len, cipher_mode_t cipher_mode,
    const int update_retry, char* reason, const size_t reason_len, ticket_raw_response_t* raw,
    char** out_ticket)
{
    char host_name[64];
    char ostag[64];
    char mac[24];
    char client_ip[64];
    char ac_ip[64];
    char local_time[32];
    char xml[TICKET_XML_LEN];
    char checksum[33];
    char checksum_header[64];
    char ua_header[ALGO_UA_LEN + 16];
    char client_header[80];
    char algo_header[64];
    char last_error[160] = "";
    const char* headers[10];
    char* encrypted = NULL;
    char* plain = NULL;
    char* ticket = NULL;
    http_resp_t resp;
    bool inited = false;
    bool request_ok = false;
    bool ok = false;

    if (reason != NULL && reason_len > 0) reason[0] = '\0';
    if (out_ticket != NULL) *out_ticket = NULL;
    ticket_raw_free(raw);

    if (fill_identity(url, ua, host_name, sizeof(host_name), ostag, sizeof(ostag),
            mac, sizeof(mac), client_ip, sizeof(client_ip), ac_ip, sizeof(ac_ip),
            local_time, sizeof(local_time)) == false)
    {
        snprintf(reason, reason_len, "生成身份字段失败");
        return false;
    }

    if (cipher_mode == CIPHER_MODE_HARDCODED)
    {
        inited = init_cipher(algo_id);
    }
    else if (cipher_mode == CIPHER_MODE_DYNAMIC)
    {
        if (zsm == NULL || zsm_len == 0)
        {
            snprintf(reason, reason_len, "动态解析缺少 ZSM 数据");
            return false;
        }
        if (strstr(ua, "WinSVR") != NULL)
            inited = init_win_cipher_from_zsm((const uint8_t*)zsm, zsm_len, NULL);
        else if (strstr(ua, "iOSdy") != NULL || strstr(ua, "macdy") != NULL)
            inited = init_ios_cipher_from_zsm((const uint8_t*)zsm, zsm_len, NULL);
        else
        {
            snprintf(reason, reason_len, "该 UA 没有动态解析路径");
            return false;
        }
    }
    else if (init_cipher(algo_id))
    {
        inited = true;
        if (getenv("TICKET_DEBUG_XML") != NULL)
            printf("[cipher] %s 使用硬编码 key/iv\n", algo_id);
    }
    else if (zsm == NULL || zsm_len == 0)
    {
        snprintf(reason, reason_len, "目标 Algo-ID 没有可用的硬编码 key/iv");
        return false;
    }
    else if (strstr(ua, "WinSVR") != NULL)
    {
        if (getenv("TICKET_DEBUG_XML") != NULL)
            printf("[cipher] %s 未找到硬编码 key/iv, 回退到 ZSM\n", algo_id);
        inited = init_win_cipher_from_zsm((const uint8_t*)zsm, zsm_len, NULL);
    }
    else if (strstr(ua, "iOSdy") != NULL || strstr(ua, "macdy") != NULL)
    {
        inited = init_ios_cipher_from_zsm((const uint8_t*)zsm, zsm_len, NULL);
    }

    if (inited == false)
    {
        snprintf(reason, reason_len, "初始化算法失败");
        return false;
    }

    snprintf(xml, sizeof(xml),
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
        "<request>\n"
        "    <ostag>%s</ostag>\n"
        "    <local-time>%s</local-time>\n"
        "    <gwip>%s</gwip>\n"
        "    <mac>%s</mac>\n"
        "    <ipv6></ipv6>\n"
        "    <ipv4>%s</ipv4>\n"
        "    <client-id>%s</client-id>\n"
        "    <user-agent>%s</user-agent>\n"
        "    <host-name>%s</host-name>\n"
        "</request>\n",
        ostag, local_time, ac_ip, mac, client_ip, client_id, ua, host_name);

    if (getenv("TICKET_DEBUG_XML") != NULL)
    {
        printf("---- GET_TICKET XML ----\n%s--------------------------------\n", xml);
    }

    encrypted = session_encrypt(xml);
    if (encrypted == NULL)
    {
        snprintf(reason, reason_len, "加密失败");
        goto cleanup;
    }

    md5_hex(encrypted, checksum);
    snprintf(checksum_header, sizeof(checksum_header), "CDC-Checksum: %s", checksum);
    snprintf(ua_header, sizeof(ua_header), "User-Agent: %s", ua);
    snprintf(client_header, sizeof(client_header), "Client-ID: %s", client_id);
    snprintf(algo_header, sizeof(algo_header), "Algo-ID: %s", algo_id);

    headers[0] = checksum_header;
    headers[1] = "Content-Type: application/x-www-form-urlencoded";
    headers[2] = ua_header;
    headers[3] = "Accept: " TICKET_ACCEPT;
    headers[4] = client_header;
    headers[5] = algo_header;
    headers[6] = "CDC-SchoolId: " TICKET_SCHOOL_ID;
    headers[7] = "CDC-Domain: " TICKET_DOMAIN;
    headers[8] = "CDC-Area: " TICKET_AREA;
    headers[9] = NULL;
    ticket_raw_set_request(raw, url, headers, encrypted);

    sleep_ms(150);
    for (int attempt = 0; attempt < TICKET_REQUEST_RETRY; attempt++)
    {
        resp = http_post_timeout(url, headers, encrypted, 5L);
        ticket_raw_copy(raw, &resp);
        if (resp.curl_code == CURLE_OK && resp.http_code == 200
            && resp.body_data != NULL && resp.body_size > 0)
        {
            request_ok = true;
            break;
        }

        const bool explicit_error = resp.error_code[0] != '\0';
        if (explicit_error)
        {
            snprintf(last_error, sizeof(last_error), "Error-Code=%s%s%s",
                resp.error_code,
                resp.sub_error[0] != '\0' ? " / Sub-Error=" : "",
                resp.sub_error[0] != '\0' ? resp.sub_error : "");
        }
        else if (resp.curl_code == CURLE_OPERATION_TIMEDOUT)
        {
            snprintf(last_error, sizeof(last_error), "请求超时");
        }
        else if (resp.http_code != 200)
        {
            snprintf(last_error, sizeof(last_error), "HTTP %ld", resp.http_code);
        }
        else
        {
            snprintf(last_error, sizeof(last_error), "响应为空");
        }

        http_resp_free(&resp);
        if (explicit_error) break;
        if (attempt + 1 < TICKET_REQUEST_RETRY) sleep_ms(TICKET_REQUEST_DELAY_MS);
    }
    if (request_ok == false)
    {
        snprintf(reason, reason_len, "%s", last_error[0] != '\0' ? last_error : "Ticket 请求失败");
        goto cleanup;
    }

    /* 官方流程: Error-Code 200 + ZSM 表示更新 algoid，然后同一服务器重试 */
    if (getenv("TICKET_DEBUG_XML") != NULL)
    {
        printf("[resp] error-code='%s' body=%zu prefix=%.8s\n", resp.error_code,
            resp.body_size, resp.body_data != NULL ? resp.body_data : "(null)");
    }
    if (strcmp(resp.error_code, "200") == 0
        && response_is_zsm(resp.body_data, resp.body_size))
    {
        char new_algo[ALGO_ID_LEN] = "";
        char* new_zsm;
        const size_t new_size = resp.body_size;

        if (update_retry >= 2)
        {
            snprintf(reason, reason_len, "算法更新重试次数已达上限");
            http_resp_free(&resp);
            goto cleanup;
        }

        new_zsm = (char*)malloc(new_size);
        if (new_zsm == NULL)
        {
            snprintf(reason, reason_len, "保存更新 ZSM 内存不足");
            http_resp_free(&resp);
            goto cleanup;
        }
        memcpy(new_zsm, resp.body_data, new_size);

        if (init_dynamic_cipher_for_ua(ua, new_zsm, new_size, new_algo) == false
            || new_algo[0] == '\0')
        {
            free(new_zsm);
            snprintf(reason, reason_len, "Error-Code=200 但 ZSM 解析失败");
            http_resp_free(&resp);
            goto cleanup;
        }

        if (getenv("TICKET_DEBUG_XML") != NULL)
            printf("[官方流程] Error-Code=200, 更新 Algo-ID: %s, 重试 %d/2\n",
                new_algo, update_retry + 1);

        http_resp_free(&resp);
        {
            const bool updated = check_one_id(ua, url, new_algo, client_id, new_zsm,
                new_size, CIPHER_MODE_DYNAMIC, update_retry + 1,
                reason, reason_len, raw, out_ticket);
            free(new_zsm);
            return updated;
        }
    }

    plain = session_decrypt(resp.body_data);
    if (plain == NULL)
    {
        if (response_is_zsm(resp.body_data, resp.body_size))
            snprintf(reason, reason_len, "服务端返回 ZSM (该 Algo-ID 未绑定有效会话)");
        else
            snprintf(reason, reason_len, "响应解密失败");
        http_resp_free(&resp);
        goto cleanup;
    }
    http_resp_free(&resp);

    ticket = extract_tag(plain, "ticket");
    if (ticket == NULL || ticket[0] == '\0')
    {
        snprintf(reason, reason_len, "响应中没有 ticket");
        goto cleanup;
    }

    if (out_ticket != NULL)
    {
        const size_t ticket_len = strlen(ticket);
        *out_ticket = (char*)malloc(ticket_len + 1);
        if (*out_ticket == NULL)
        {
            snprintf(reason, reason_len, "保存 ticket 内存不足");
            goto cleanup;
        }
        memcpy(*out_ticket, ticket, ticket_len + 1);
    }

    ok = true;

cleanup:
    free(ticket);
    free(plain);
    free(encrypted);
    destroy_cipher_factory();
    return ok;
}


static bool is_excluded_algo_id(const char* algo_id)
{
    if (algo_id == NULL) return false;
    for (size_t i = 0; i < sizeof(WINDOWS_EXCLUDED_IDS) / sizeof(WINDOWS_EXCLUDED_IDS[0]); ++i)
    {
        if (strcmp(WINDOWS_EXCLUDED_IDS[i], algo_id) == 0) return true;
    }
    return false;
}

static const ticket_group_t* select_group(const char* ua)
{
    if (strstr(ua, "WinSVR") != NULL) return &s_groups[0];
    if (strstr(ua, "iOSdy") != NULL) return &s_groups[1];
    if (strstr(ua, "macdy") != NULL) return &s_groups[2];
    if (strstr(ua, "android64_vpn") != NULL) return &s_groups[3];
    if (strstr(ua, "android") != NULL) return &s_groups[4];
    if (strstr(ua, "Linux") != NULL) return &s_groups[5];
    return NULL;
}

static int find_id(const ticket_group_t* group, const char* algo_id)
{
    for (size_t i = 0; i < group->count; i++)
    {
        if (strcmp(group->ids[i], algo_id) == 0) return (int)i;
    }
    return -1;
}

static bool ua_has_dynamic_cipher(const char* ua)
{
    return strstr(ua, "WinSVR") != NULL
        || strstr(ua, "iOSdy") != NULL
        || strstr(ua, "macdy") != NULL;
}

static bool prompt_cipher_mode(const char* ua, cipher_mode_t* mode)
{
    char input[16];

    *mode = CIPHER_MODE_AUTO;
    if (ua_has_dynamic_cipher(ua) == false) return true;

    printf("\n该 UA 有动态 ZSM 解析路径。请选择解析方式:\n");
    printf("  1. 动态解析 (只使用 ZSM，Ctrl+C 停止)\n");
    printf("  2. 硬编码 (选一个服务器，按官方流程重试)\n");
    printf("请输入选项 (直接回车默认 2): ");
    if (read_line(input, sizeof(input)) == false) return false;
    trim_str(input);

    if (strcmp(input, "1") == 0)
    {
        *mode = CIPHER_MODE_DYNAMIC;
    }
    else if (input[0] == '\0' || strcmp(input, "2") == 0)
    {
        *mode = CIPHER_MODE_AUTO;
    }
    else
    {
        printf("输入无效\n");
        return false;
    }
    return true;
}

/*
 * 动态解析模式：
 * 官方流程：Error-Code 200 + ZSM 更新算法后，同一服务器重试；
 * 不切换服务器。只有 Ctrl+C 才会停止。
 */
static void ticket_dynamic_run(const char* ua, const char* url, const ticket_group_t* group)
{
    const char* server_name = algo_server_name(0);
    size_t samples = 0;
    size_t success_count = 0;
    size_t fail_count = 0;
    void (*old_sigint)(int) = NULL;

    s_ticket_stop = 0;
    old_sigint = signal(SIGINT, on_ticket_sigint);

    printf("\n动态解析模式: %s\n", group->name);
    printf("服务器: %s\n", server_name);
    printf("按官方流程处理 Error-Code 200 + ZSM；只有 Ctrl+C 才会停止\n\n");

    while (s_ticket_stop == 0)
    {
        ticket_sample_t batch[SAMPLE_BATCH_SIZE];
        size_t got = 0;

        if (algo_fetch_ticket_samples(ua, SAMPLE_BATCH_SIZE, batch, &got) == false || got == 0)
        {
            printf("  采样请求失败, 1 秒后重试 (Ctrl+C 停止)\n");
            sleep_ms(1000);
            continue;
        }

        for (size_t i = 0; i < got; ++i)
        {
            char reason[192] = "";
            ticket_raw_response_t raw = {0};

            if (s_ticket_stop != 0)
            {
                for (size_t j = i; j < got; ++j) free(batch[j].body);
                break;
            }

            if (is_excluded_algo_id(batch[i].algo_id))
            {
                printf("  [跳过] %s 已知 Error-Code=1, 重新获取\n", batch[i].algo_id);
                free(batch[i].body);
                /* 立即取下一个样本, 不等待 */
                continue;
            }
            samples++;
            printf("  [%zu] [%s] %s ... ", samples, server_name, batch[i].algo_id);
            fflush(stdout);

            const bool ok = check_one_id(ua, url, batch[i].algo_id, batch[i].client_id,
                batch[i].body, batch[i].body_size, CIPHER_MODE_DYNAMIC, 0,
                reason, sizeof(reason), &raw, NULL);
            ticket_raw_free(&raw);
            free(batch[i].body);

            if (ok)
            {
                printf("OK\n");
                success_count++;
            }
            else
            {
                printf("FAIL (%s)\n", reason[0] != '\0' ? reason : "未知错误");
                fail_count++;
            }
        }
    }

    if (old_sigint != SIG_ERR) signal(SIGINT, old_sigint);
    printf("\n动态解析已停止: 采样 %zu 个, 成功 %zu 个, 失败 %zu 个\n",
        samples, success_count, fail_count);
}

/*
 * 硬编码模式：
 * 只使用用户选择的服务器，不切换另一台服务器。
 * 每个 Algo-ID 走官方 check_one_id：Error-Code 200 + ZSM 更新算法后同服务器重试。
 */
typedef struct
{
    bool tested;
    bool ok;
    char reason[192];
    char* ticket;
} hardcoded_server_result_t;

static const char* hardcoded_result_text(const hardcoded_server_result_t* result)
{
    if (result == NULL || result->tested == false) return "NOT_TESTED";
    return result->ok ? "OK" : "FAIL";
}

static int find_id_in_list(const char* const* ids, const size_t count, const char* id)
{
    for (size_t i = 0; i < count; ++i)
    {
        if (strcmp(ids[i], id) == 0) return (int)i;
    }
    return -1;
}

static bool prompt_server_choice(const bool windows, size_t* chosen)
{
    char input[16];

    printf("\n请选择获取 Ticket 的服务器:\n");
    if (windows)
    {
        printf("  1. %s (%zu 个可用 Algo-ID)\n", algo_server_name(0),
            sizeof(WINDOWS_SERVER0_IDS) / sizeof(WINDOWS_SERVER0_IDS[0]));
        printf("  2. %s (%zu 个可用 Algo-ID)\n", algo_server_name(1),
            sizeof(WINDOWS_SERVER1_IDS) / sizeof(WINDOWS_SERVER1_IDS[0]));
    }
    else
    {
        printf("  1. %s\n", algo_server_name(0));
        printf("  2. %s\n", algo_server_name(1));
    }
    printf("请输入选项 (直接回车默认 1): ");
    if (read_line(input, sizeof(input)) == false) return false;
    trim_str(input);

    if (input[0] == '\0' || strcmp(input, "1") == 0)
    {
        *chosen = 0;
        return true;
    }
    if (strcmp(input, "2") == 0)
    {
        *chosen = 1;
        return true;
    }
    printf("输入无效\n");
    return false;
}

static bool hardcoded_check(const char* ua, const char* url, const char* id,
    const char* client_id, char* reason, const size_t reason_len, char** ticket)
{
    ticket_raw_response_t raw = {0};
    const bool ok = check_one_id(ua, url, id, client_id, NULL, 0, CIPHER_MODE_HARDCODED, 0,
        reason, reason_len, &raw, ticket);
    ticket_raw_free(&raw);
    return ok;
}

static void ticket_check_hardcoded_server(const char* ua, const ticket_group_t* group,
    const size_t chosen_server)
{
    const bool windows = group == &s_groups[0];
    const char* const* ids = group->ids;
    size_t count = group->count;
    const char* primary_url = algo_server_url(chosen_server);
    const char* primary_name = algo_server_name(chosen_server);
    hardcoded_server_result_t* results;
    char path[128];
    void (*old_sigint)(int) = NULL;

    if (windows)
    {
        ids = chosen_server == 0 ? WINDOWS_SERVER0_IDS : WINDOWS_SERVER1_IDS;
        count = chosen_server == 0
            ? sizeof(WINDOWS_SERVER0_IDS) / sizeof(WINDOWS_SERVER0_IDS[0])
            : sizeof(WINDOWS_SERVER1_IDS) / sizeof(WINDOWS_SERVER1_IDS[0]);
    }

    results = calloc(count, sizeof(*results));
    if (results == NULL || primary_url == NULL)
    {
        free(results);
        printf("服务器参数错误或内存不足\n");
        return;
    }

    printf("\n硬编码模式: 只使用所选服务器\n");
    printf("  服务器: %s\n", primary_name);
    printf("  共 %zu 个 Algo-ID\n", count);
    printf("  按官方流程处理 Error-Code 200 + ZSM；不会切换另一台服务器\n");
    printf("按 Ctrl+C 可停止\n\n");

    s_ticket_stop = 0;
    old_sigint = signal(SIGINT, on_ticket_sigint);

    size_t tested_count = 0;
    size_t samples = 0;

    while (tested_count < count && s_ticket_stop == 0)
    {
        ticket_sample_t batch[SAMPLE_BATCH_SIZE];
        size_t got = 0;

        if (algo_fetch_ticket_samples_from(ua, primary_url, SAMPLE_BATCH_SIZE, batch, &got) == false
            || got == 0)
        {
            printf("  采样失败, 1 秒后重试 (Ctrl+C 停止)\n");
            sleep_ms(1000);
            continue;
        }

        for (size_t i = 0; i < got; ++i)
        {
            samples++;
            if (s_ticket_stop != 0)
            {
                for (size_t j = i; j < got; ++j) free(batch[j].body);
                break;
            }

            const int idx = find_id_in_list(ids, count, batch[i].algo_id);
            if (is_excluded_algo_id(batch[i].algo_id) || idx < 0 || results[idx].tested)
            {
                free(batch[i].body);
                continue;
            }

            hardcoded_server_result_t* result = &results[idx];
            char reason[192] = "";
            char* ticket = NULL;

            result->tested = true;
            tested_count++;
            printf("  [%zu/%zu] [%s] %s ... ", tested_count, count, primary_name, ids[idx]);
            fflush(stdout);

            if (hardcoded_check(ua, primary_url, ids[idx], batch[i].client_id,
                    reason, sizeof(reason), &ticket))
            {
                printf("OK\n");
                result->ok = true;
                result->ticket = ticket;
            }
            else
            {
                printf("FAIL (%s)\n", reason[0] != '\0' ? reason : "未知错误");
                snprintf(result->reason, sizeof(result->reason), "%s",
                    reason[0] != '\0' ? reason : "未知错误");
            }

            free(batch[i].body);
        }

        if (samples / 100 != (samples - got) / 100)
        {
            printf("  ... 已采样 %zu 次, 已测试 %zu/%zu\n", samples, tested_count, count);
        }
    }

    if (old_sigint != SIG_ERR) signal(SIGINT, old_sigint);

    printf("\n所选服务器结果:\n");
    printf("  %-36s  %-12s\n", "Algo-ID", primary_name);
    for (size_t i = 0; i < count; ++i)
    {
        printf("  %-36s  %-12s\n", ids[i],
            hardcoded_result_text(&results[i]));
    }

    snprintf(path, sizeof(path), "ticket_check_%s_%s.tsv", group->file_tag, primary_name);
    {
        FILE* fp = fopen(path, "w");
        if (fp == NULL)
        {
            printf("无法写入结果文件: %s\n", path);
        }
        else
        {
            fprintf(fp, "# selected_server\t%s\n", primary_name);
            fprintf(fp, "# UA\t%s\n", ua);
            fprintf(fp, "Algo-ID\tResult\tDetail\n");

            for (size_t i = 0; i < count; ++i)
            {
                const hardcoded_server_result_t* r = &results[i];
                if (r->tested == false)
                    fprintf(fp, "%s\tNOT_TESTED\t-\n", ids[i]);
                else if (r->ok)
                    fprintf(fp, "%s\tOK\t%s\n", ids[i],
                        r->ticket != NULL ? r->ticket : "");
                else
                    fprintf(fp, "%s\tFAIL\t%s\n", ids[i], r->reason);
            }
            fclose(fp);
            printf("\n结果已导出: %s\n", path);
        }
    }

    for (size_t i = 0; i < count; ++i) free(results[i].ticket);
    free(results);
}

void ticket_check_run(void)
{
    char ua[ALGO_UA_LEN];
    const ticket_group_t* group;
    cipher_mode_t mode;

    if (algo_prompt_ua(ua, sizeof(ua)) == false) return;

    group = select_group(ua);
    if (group == NULL)
    {
        printf("无法根据 UA 判断平台, 支持 Windows/iOS/macOS/Android/Linux\n");
        return;
    }

    if (prompt_cipher_mode(ua, &mode) == false) return;

    if (mode == CIPHER_MODE_DYNAMIC)
    {
        ticket_dynamic_run(ua, algo_ticket_url(), group);
    }
    else
    {
        size_t chosen_server = 0;
        if (prompt_server_choice(group == &s_groups[0], &chosen_server) == false) return;
        ticket_check_hardcoded_server(ua, group, chosen_server);
    }
}

static bool ticket_direct_one(const char* ua, const char* url, const char* client_id,
    const char* algo_id, ticket_raw_response_t* out_raw, char** out_ticket,
    char* reason, const size_t reason_len)
{
    ticket_raw_response_t local_raw = {0};
    ticket_raw_response_t* raw = out_raw != NULL ? out_raw : &local_raw;
    const bool ok = check_one_id(ua, url, algo_id, client_id, NULL, 0, CIPHER_MODE_HARDCODED, 0,
        reason, reason_len, raw, out_ticket);

    if (out_raw == NULL) ticket_raw_free(&local_raw);
    return ok;
}

/*
 * 指定 Algo-ID 直接获取 Ticket：
 * - 完全跳过服务端 ZSM 采样
 * - 使用本第三方客户端自己生成的 XML/body
 * - 固定有效 client-id + 指定 URL，直接使用目标 Algo-ID 的硬编码 key/iv
 * - 支持单个 ID，也支持输入 0/all 轮询全部 Windows ID
 */
void ticket_direct_run(void)
{
    char ua[ALGO_UA_LEN];
    char input[64];
    char client_id[37];
    char reason[192] = "";
    char* ticket = NULL;
    ticket_raw_response_t raw = {0};
    const char* url;
    const char* algo_id = NULL;
    bool all_ids = false;
    const size_t id_count = sizeof(WINDOWS_IDS) / sizeof(WINDOWS_IDS[0]);

    if (algo_prompt_ua(ua, sizeof(ua)) == false) return;
    if (strstr(ua, "WinSVR") == NULL)
    {
        printf("功能 4 当前只支持 Windows UA, 请使用 CCTP/WinSVR5/1068\n");
        return;
    }

    printf("\n可尝试的 Windows Algo-ID (全部 %zu 个, 暂不筛选):\n", id_count);
    for (size_t i = 0; i < id_count; ++i)
    {
        printf("  %2zu. %s\n", i + 1, WINDOWS_IDS[i]);
    }
    printf("请选择序号 (直接回车默认 1, 输入 0/all 轮询全部, 也可输入完整 Algo-ID): ");
    if (read_line(input, sizeof(input)) == false) return;
    trim_str(input);

    if (input[0] == '\0')
    {
        algo_id = WINDOWS_IDS[0];
    }
    else if (strcmp(input, "0") == 0 || strcmp(input, "all") == 0 || strcmp(input, "ALL") == 0)
    {
        all_ids = true;
    }
    else
    {
        char* end = NULL;
        unsigned long index = strtoul(input, &end, 10);
        if (end != input && *end == '\0')
        {
            if (index < 1 || index > id_count)
            {
                printf("序号超出范围\n");
                return;
            }
            algo_id = WINDOWS_IDS[index - 1];
        }
        else if (strlen(input) == 36)
        {
            algo_id = input;
        }
        else
        {
            printf("输入不是有效序号、all 或 Algo-ID\n");
            return;
        }
    }

    {
        const char* direct_client_id = getenv("TICKET_DIRECT_CLIENT_ID");
        const char* direct_url = getenv("TICKET_DIRECT_URL");
        if (direct_client_id == NULL || direct_client_id[0] == '\0')
            direct_client_id = DIRECT_CLIENT_ID;
        if (direct_url == NULL || direct_url[0] == '\0')
            direct_url = DIRECT_TICKET_URL;
        snprintf(client_id, sizeof(client_id), "%s", direct_client_id);
        url = direct_url;
    }

    if (all_ids)
    {
        size_t ok_count = 0;
        FILE* all_fp = fopen("ticket_direct_all.txt", "w");

        printf("\n轮询全部 %zu 个 Algo-ID (不请求 ZSM)\n", id_count);
        printf("  Client-ID: %s\n", client_id);
        printf("  URL      : %s\n\n", url);
        if (all_fp != NULL)
            fprintf(all_fp, "# client_id=%s\n# url=%s\n\n", client_id, url);

        for (size_t i = 0; i < id_count; ++i)
        {
            char* one_ticket = NULL;
            char one_reason[192] = "";
            printf("  [%2zu/%zu] %s ... ", i + 1, id_count, WINDOWS_IDS[i]);
            fflush(stdout);

            if (ticket_direct_one(ua, url, client_id, WINDOWS_IDS[i], NULL, &one_ticket,
                    one_reason, sizeof(one_reason)))
            {
                printf("OK %s\n", one_ticket);
                ok_count++;
                if (all_fp != NULL)
                    fprintf(all_fp, "algo_id=%s\nticket=%s\n\n", WINDOWS_IDS[i], one_ticket);
            }
            else
            {
                printf("FAIL (%s)\n", one_reason[0] != '\0' ? one_reason : "未知错误");
            }

            free(one_ticket);
            sleep_ms(100);
        }

        if (all_fp != NULL) fclose(all_fp);
        printf("\n轮询完成: 成功 %zu/%zu\n", ok_count, id_count);
        if (all_fp != NULL) printf("成功结果已写入 ticket_direct_all.txt\n");
        return;
    }

    printf("\n直接获取 Ticket (不请求 ZSM)\n");
    printf("  Algo-ID  : %s\n", algo_id);
    printf("  Client-ID: %s\n", client_id);
    printf("  URL      : %s\n", url);

    if (ticket_direct_one(ua, url, client_id, algo_id, &raw, &ticket,
            reason, sizeof(reason)) == false)
    {
        printf("失败: %s\n", reason[0] != '\0' ? reason : "未知错误");
        if (raw.has_request || raw.has_response) save_failed_dump(algo_id, &raw);
        ticket_raw_free(&raw);
        return;
    }

    printf("\nTicket 获取成功:\n%s\n", ticket);
    {
        FILE* fp = fopen("ticket_direct.txt", "w");
        if (fp != NULL)
        {
            fprintf(fp, "algo_id=%s\nclient_id=%s\nticket=%s\n", algo_id, client_id, ticket);
            fclose(fp);
            printf("已写入 ticket_direct.txt\n");
        }
        else
        {
            printf("无法写入 ticket_direct.txt\n");
        }
    }

    free(ticket);
    ticket_raw_free(&raw);
}
