#define _WIN32_WINNT 0x0A00
#define WIN32_LEAN_AND_MEAN
#define COBJMACROS
#define UNICODE
#define _UNICODE
#ifdef _MSC_VER
#pragma execution_character_set("utf-8")
#endif
#include <windows.h>
#include <shellapi.h>
#include <pdh.h>
#include <pdhmsg.h>
#include <dxgi.h>
#include <wchar.h>
#include <math.h>
#include <winioctl.h>
#ifdef _MSC_VER
#include <intrin.h>
#else
#include <cpuid.h>
#endif
#include <winhttp.h>
#include <bcrypt.h>
#include <sddl.h>
#include <uiautomationclient.h>

static HMODULE sysdll(const wchar_t *name)
{
    return LoadLibraryExW(name, NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
}

typedef PDH_STATUS (WINAPI *T_PdhOpenQueryW)(LPCWSTR, DWORD_PTR, PDH_HQUERY *);
typedef PDH_STATUS (WINAPI *T_PdhAddEnglishCounterW)(PDH_HQUERY, LPCWSTR, DWORD_PTR, PDH_HCOUNTER *);
typedef PDH_STATUS (WINAPI *T_PdhCollectQueryData)(PDH_HQUERY);
typedef PDH_STATUS (WINAPI *T_PdhGetFormattedCounterArrayW)(PDH_HCOUNTER, DWORD, LPDWORD, LPDWORD, PPDH_FMT_COUNTERVALUE_ITEM_W);
typedef PDH_STATUS (WINAPI *T_PdhCloseQuery)(PDH_HQUERY);
typedef HINTERNET (WINAPI *T_WinHttpOpen)(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD);
typedef HINTERNET (WINAPI *T_WinHttpConnect)(HINTERNET, LPCWSTR, INTERNET_PORT, DWORD);
typedef HINTERNET (WINAPI *T_WinHttpOpenRequest)(HINTERNET, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR *, DWORD);
typedef BOOL (WINAPI *T_WinHttpSendRequest)(HINTERNET, LPCWSTR, DWORD, LPVOID, DWORD, DWORD, DWORD_PTR);
typedef BOOL (WINAPI *T_WinHttpReceiveResponse)(HINTERNET, LPVOID);
typedef BOOL (WINAPI *T_WinHttpQueryHeaders)(HINTERNET, DWORD, LPCWSTR, LPVOID, LPDWORD, LPDWORD);
typedef BOOL (WINAPI *T_WinHttpQueryDataAvailable)(HINTERNET, LPDWORD);
typedef BOOL (WINAPI *T_WinHttpReadData)(HINTERNET, LPVOID, DWORD, LPDWORD);
typedef BOOL (WINAPI *T_WinHttpWriteData)(HINTERNET, LPCVOID, DWORD, LPDWORD);
typedef BOOL (WINAPI *T_WinHttpCloseHandle)(HINTERNET);
typedef NTSTATUS (WINAPI *T_BCryptOpenAlgorithmProvider)(BCRYPT_ALG_HANDLE *, LPCWSTR, LPCWSTR, ULONG);
typedef NTSTATUS (WINAPI *T_BCryptCreateHash)(BCRYPT_ALG_HANDLE, BCRYPT_HASH_HANDLE *, PUCHAR, ULONG, PUCHAR, ULONG, ULONG);
typedef NTSTATUS (WINAPI *T_BCryptHashData)(BCRYPT_HASH_HANDLE, PUCHAR, ULONG, ULONG);
typedef NTSTATUS (WINAPI *T_BCryptFinishHash)(BCRYPT_HASH_HANDLE, PUCHAR, ULONG, ULONG);
typedef NTSTATUS (WINAPI *T_BCryptDestroyHash)(BCRYPT_HASH_HANDLE);
typedef NTSTATUS (WINAPI *T_BCryptCloseAlgorithmProvider)(BCRYPT_ALG_HANDLE, ULONG);

#define FN(n) static T_##n p_##n;
FN(PdhOpenQueryW) FN(PdhAddEnglishCounterW) FN(PdhCollectQueryData) FN(PdhGetFormattedCounterArrayW) FN(PdhCloseQuery)
FN(WinHttpOpen) FN(WinHttpConnect) FN(WinHttpOpenRequest) FN(WinHttpSendRequest) FN(WinHttpReceiveResponse)
FN(WinHttpQueryHeaders) FN(WinHttpQueryDataAvailable) FN(WinHttpReadData) FN(WinHttpWriteData) FN(WinHttpCloseHandle)
FN(BCryptOpenAlgorithmProvider) FN(BCryptCreateHash) FN(BCryptHashData) FN(BCryptFinishHash)
FN(BCryptDestroyHash) FN(BCryptCloseAlgorithmProvider)
#undef FN
#define GETFN(m, n) ((p_##n = (T_##n)(void *)GetProcAddress(m, #n)) != NULL)

static int load_pdh(void)
{
    static int done, ok;
    if (done) return ok;
    done = 1;
    HMODULE m = sysdll(L"pdh.dll");
    ok = m && GETFN(m, PdhOpenQueryW) && GETFN(m, PdhAddEnglishCounterW) && GETFN(m, PdhCollectQueryData) &&
         GETFN(m, PdhGetFormattedCounterArrayW) && GETFN(m, PdhCloseQuery);
    return ok;
}

static int load_net(void)
{
    static int done, ok;
    if (done) return ok;
    done = 1;
    HMODULE w = sysdll(L"winhttp.dll"), b = sysdll(L"bcrypt.dll");
    ok = w && b && GETFN(w, WinHttpOpen) && GETFN(w, WinHttpConnect) && GETFN(w, WinHttpOpenRequest) &&
         GETFN(w, WinHttpSendRequest) && GETFN(w, WinHttpReceiveResponse) && GETFN(w, WinHttpQueryHeaders) &&
         GETFN(w, WinHttpQueryDataAvailable) && GETFN(w, WinHttpReadData) && GETFN(w, WinHttpWriteData) &&
         GETFN(w, WinHttpCloseHandle) &&
         GETFN(b, BCryptOpenAlgorithmProvider) && GETFN(b, BCryptCreateHash) && GETFN(b, BCryptHashData) &&
         GETFN(b, BCryptFinishHash) && GETFN(b, BCryptDestroyHash) && GETFN(b, BCryptCloseAlgorithmProvider);
    return ok;
}

#define PdhOpenQueryW                p_PdhOpenQueryW
#define PdhAddEnglishCounterW        p_PdhAddEnglishCounterW
#define PdhCollectQueryData          p_PdhCollectQueryData
#define PdhGetFormattedCounterArrayW p_PdhGetFormattedCounterArrayW
#define PdhCloseQuery                p_PdhCloseQuery
#define WinHttpOpen                  p_WinHttpOpen
#define WinHttpConnect               p_WinHttpConnect
#define WinHttpOpenRequest           p_WinHttpOpenRequest
#define WinHttpSendRequest           p_WinHttpSendRequest
#define WinHttpReceiveResponse       p_WinHttpReceiveResponse
#define WinHttpQueryHeaders          p_WinHttpQueryHeaders
#define WinHttpQueryDataAvailable    p_WinHttpQueryDataAvailable
#define WinHttpReadData              p_WinHttpReadData
#define WinHttpWriteData             p_WinHttpWriteData
#define WinHttpCloseHandle           p_WinHttpCloseHandle
#define BCryptOpenAlgorithmProvider  p_BCryptOpenAlgorithmProvider
#define BCryptCreateHash             p_BCryptCreateHash
#define BCryptHashData               p_BCryptHashData
#define BCryptFinishHash             p_BCryptFinishHash
#define BCryptDestroyHash            p_BCryptDestroyHash
#define BCryptCloseAlgorithmProvider p_BCryptCloseAlgorithmProvider

static int sys_path(wchar_t *out, const wchar_t *file)
{
    UINT n = GetSystemDirectoryW(out, MAX_PATH);
    if (!n || n + lstrlenW(file) + 2 >= MAX_PATH) return 0;
    lstrcatW(out, L"\\");
    lstrcatW(out, file);
    return 1;
}

static HANDLE g_self = INVALID_HANDLE_VALUE;

static void lock_self(void)
{
    wchar_t p[MAX_PATH];
    DWORD n = GetModuleFileNameW(NULL, p, MAX_PATH);
    if (n && n < MAX_PATH)
        g_self = CreateFileW(p, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
}

static int copy_self(const wchar_t *dst)
{
    LARGE_INTEGER sz, zero = { 0 };
    DWORD got, w;
    int ok = 0;
    if (g_self == INVALID_HANDLE_VALUE || !GetFileSizeEx(g_self, &sz) || sz.QuadPart <= 0 || sz.QuadPart > (16 << 20))
        return 0;
    BYTE *buf = HeapAlloc(GetProcessHeap(), 0, (SIZE_T)sz.QuadPart);
    if (!buf) return 0;
    if (SetFilePointerEx(g_self, zero, NULL, FILE_BEGIN) &&
        ReadFile(g_self, buf, (DWORD)sz.QuadPart, &got, NULL) && got == (DWORD)sz.QuadPart) {
        HANDLE f = CreateFileW(dst, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
        if (f != INVALID_HANDLE_VALUE) {
            ok = WriteFile(f, buf, got, &w, NULL) && w == got;
            CloseHandle(f);
            if (!ok) DeleteFileW(dst);
        }
    }
    HeapFree(GetProcessHeap(), 0, buf);
    return ok;
}

static int app_dir(wchar_t *out)
{
    DWORD sz = MAX_PATH * sizeof(wchar_t);
    if (RegGetValueW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion", L"ProgramFilesDir",
                     RRF_RT_REG_SZ, NULL, out, &sz) != ERROR_SUCCESS) return 0;
    if (lstrlenW(out) > MAX_PATH - 48) return 0;
    lstrcatW(out, L"\\TraySense");
    if (!CreateDirectoryW(out, NULL) && GetLastError() != ERROR_ALREADY_EXISTS) return 0;
    DWORD a = GetFileAttributesW(out);
    return a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY) && !(a & FILE_ATTRIBUTE_REPARSE_POINT);
}

#define APP      L"TraySense"
#define REGKEY   L"Software\\TraySense"
#define RUNKEY   L"Software\\Microsoft\\Windows\\CurrentVersion\\Run"
#define WM_TRAY  (WM_APP + 1)

enum { M_CPU, M_CPUT, M_RAM, M_GPU, M_GPUT, M_VRAM, M_DISKT, M_CPUW, M_GPUW, M_DISKA, M_GPUCLK, M_MEMCLK, M_N };
#define M_TRAYN (M_DISKT + 1)
static const wchar_t *NAMES[M_N] = { L"Mức dùng CPU", L"Nhiệt độ CPU", L"Mức dùng RAM",
                                     L"Mức dùng GPU", L"Nhiệt độ GPU", L"Mức dùng VRAM", L"Nhiệt độ SSD",
                                     L"Công suất CPU", L"Công suất GPU", L"Mức dùng ổ đĩa",
                                     L"Xung nhịp GPU", L"Xung nhịp VRAM" };

static const COLORREF COL_D[M_N] = { RGB(80,190,255), 0, RGB(185,145,255), RGB(118,215,90), 0, RGB(118,215,90), 0 };
static const COLORREF COL_L[M_N] = { RGB(0,100,180),  0, RGB(110,60,200),  RGB(35,135,30),  0, RGB(35,135,30), 0 };

static HWND     g_wnd;
static UINT     g_taskbarCreated, g_msgQuit;
static DWORD    g_mask = ((1u << M_TRAYN) - 1) & ~(1u << M_VRAM), g_interval = 2000;
static double   g_val[M_N];
static int      g_ok[M_N], g_shown[M_N], g_size, g_light;
static wchar_t  g_txt[M_N][4];
static HICON    g_icon[M_N];
static wchar_t  g_gpuName[64];
static double   g_ramUsed, g_ramTotal, g_vramUsed;

static PDH_HQUERY   g_q;
static PDH_HCOUNTER g_cTherm, g_cEng, g_cMem, g_cDisk;
static BYTE        *g_buf;
static DWORD        g_bufSz;

static LUID       g_luid;
static int        g_hasGpu;
static ULONGLONG  g_vramTotal;
static wchar_t    g_luidStr[40];
static UINT       g_kmt;
typedef LONG (APIENTRY *PFN_KMT)(void *);
static PFN_KMT    pKmtQuery;
typedef struct { LUID Luid; UINT hAdapter; } KMT_OPEN;
typedef struct { UINT hAdapter; UINT Type; void *pData; UINT Size; } KMT_QAI;
typedef struct { UINT32 PhysIdx; ULONGLONG MemFreq, MaxMemFreq, MaxMemFreqOC, MemBw, PcieBw;
                 ULONG FanRPM, Power, Temperature; UCHAR PowerStateOverride; } KMT_PERF;
#define KMTQAITYPE_NODEPERFDATA 61
#define KMTQAITYPE_ADAPTERPERFDATA 62
typedef struct { UINT32 Node, PhysIdx; ULONGLONG Freq, MaxFreq, MaxFreqOC; ULONG Volt, VoltMax, VoltMaxOC; ULONGLONG Latency; } KMT_NODE;
typedef int (*PFN_NVTEMP)(void *, int, unsigned *);
typedef int (*PFN_NVPOWER)(void *, unsigned *);
typedef int (*PFN_NVENERGY)(void *, unsigned long long *);
typedef struct { unsigned fieldId, scopeId; long long timestamp, latencyUsec; int valueType, nvmlReturn;
                 union { double d; unsigned ui; unsigned long ul; unsigned long long ull; long long sll; } value; } NV_FIELD;
typedef int (*PFN_NVFIELDS)(void *, int, NV_FIELD *);
#define NVML_FI_DEV_POWER_INSTANT 186
#define NVML_FI_DEV_POWER_AVERAGE 185
static PFN_NVTEMP pNvTemp;
static PFN_NVPOWER pNvPower;
static PFN_NVENERGY pNvEnergy;
static PFN_NVFIELDS pNvFields;
typedef int (*PFN_NVCLOCK)(void *, int, unsigned *);
static PFN_NVCLOCK pNvClock;
static unsigned    g_nvField;
static UINT       g_gpuVendor;
static int        g_gpuPowerPct, g_kmtPower;

typedef struct { int supported, value; } ADL_SENSOR;
typedef struct { int size; ADL_SENSOR sensors[256]; } ADL_PMLOG;
typedef void *(__stdcall *ADL_MALLOC)(int);
typedef int (*T_ADL2_Create)(ADL_MALLOC, int, void **);
typedef int (*T_ADL2_Count)(void *, int *);
typedef int (*T_ADL2_PMLog)(void *, int, ADL_PMLOG *);
#define ADL_ASIC_POWER  23
#define ADL_BOARD_POWER 73
static T_ADL2_PMLog pAdlPMLog;
static void *g_adl;
static int   g_adlIndex = -1;
static void      *g_nvDev;

static const GUID IID_F1 = {0x770aae78,0xf26f,0x4dba,{0xa8,0x29,0x25,0x3c,0x83,0xd1,0xb3,0x87}};
static const GUID G_DISPLAY = {0x6fe69556,0x704a,0x47a0,{0x8f,0x24,0xc2,0x8d,0x93,0x6f,0xda,0x47}};

static ULONGLONG ft(FILETIME f) { return ((ULONGLONG)f.dwHighDateTime << 32) | f.dwLowDateTime; }

static void read_cpu(void)
{
    static ULONGLONG pi, pt;
    FILETIME i, k, u;
    if (!GetSystemTimes(&i, &k, &u)) return;
    ULONGLONG id = ft(i), tot = ft(k) + ft(u);
    if (pt && tot > pt) {
        g_val[M_CPU] = 100.0 * (1.0 - (double)(id - pi) / (double)(tot - pt));
        g_ok[M_CPU] = 1;
    }
    pi = id; pt = tot;
}

static void read_ram(void)
{
    MEMORYSTATUSEX m = { sizeof m };
    if (!GlobalMemoryStatusEx(&m)) return;
    g_ramTotal = m.ullTotalPhys / 1073741824.0;
    g_ramUsed  = (m.ullTotalPhys - m.ullAvailPhys) / 1073741824.0;
    g_val[M_RAM] = 100.0 * (double)(m.ullTotalPhys - m.ullAvailPhys) / (double)m.ullTotalPhys;
    g_ok[M_RAM] = 1;
}

static PDH_FMT_COUNTERVALUE_ITEM_W *pdh_items(PDH_HCOUNTER c, DWORD *n)
{
    DWORD sz = g_bufSz;
    *n = 0;
    if (!c) return NULL;
    PDH_STATUS s = PdhGetFormattedCounterArrayW(c, PDH_FMT_DOUBLE | PDH_FMT_NOCAP100, &sz, n,
                                                (PPDH_FMT_COUNTERVALUE_ITEM_W)g_buf);
    if ((DWORD)s == (DWORD)PDH_MORE_DATA) {
        BYTE *nb = g_buf ? HeapReAlloc(GetProcessHeap(), 0, g_buf, sz)
                         : HeapAlloc(GetProcessHeap(), 0, sz);
        if (!nb) return NULL;
        g_buf = nb; g_bufSz = sz;
        s = PdhGetFormattedCounterArrayW(c, PDH_FMT_DOUBLE | PDH_FMT_NOCAP100, &sz, n,
                                         (PPDH_FMT_COUNTERVALUE_ITEM_W)g_buf);
    }
    return s == ERROR_SUCCESS ? (PDH_FMT_COUNTERVALUE_ITEM_W *)g_buf : NULL;
}

static int good(PDH_FMT_COUNTERVALUE_ITEM_W *it)
{
    return it->FmtValue.CStatus == PDH_CSTATUS_VALID_DATA || it->FmtValue.CStatus == PDH_CSTATUS_NEW_DATA;
}

static int has_luid(const wchar_t *s)
{
    size_t L = wcslen(g_luidStr);
    for (; *s; s++)
        if (_wcsnicmp(s, g_luidStr, L) == 0) return 1;
    return 0;
}

static void read_therm(void)
{
    DWORD n; double mx = 0;
    PDH_FMT_COUNTERVALUE_ITEM_W *it = pdh_items(g_cTherm, &n);
    g_ok[M_CPUT] = 0;
    if (!it) return;
    for (DWORD i = 0; i < n; i++)
        if (good(&it[i]) && it[i].FmtValue.doubleValue > mx) mx = it[i].FmtValue.doubleValue;
    if (mx > 200.0) { g_val[M_CPUT] = mx - 273.15; g_ok[M_CPUT] = 1; }
}

static void read_gpu_usage(void)
{
    DWORD n; double eng[64] = {0}, mx = 0;
    PDH_FMT_COUNTERVALUE_ITEM_W *it = pdh_items(g_cEng, &n);
    g_ok[M_GPU] = 0;
    if (!it) return;
    for (DWORD i = 0; i < n; i++) {
        if (!good(&it[i]) || !has_luid(it[i].szName)) continue;
        const wchar_t *e = wcsstr(it[i].szName, L"_eng_");
        if (!e) continue;
        int k = _wtoi(e + 5);
        if (k >= 0 && k < 64) eng[k] += it[i].FmtValue.doubleValue;
    }
    for (int k = 0; k < 64; k++) if (eng[k] > mx) mx = eng[k];
    g_val[M_GPU] = mx > 100.0 ? 100.0 : mx;
    g_ok[M_GPU] = 1;
}

static void read_vram(void)
{
    DWORD n; double used = 0; int found = 0;
    PDH_FMT_COUNTERVALUE_ITEM_W *it = pdh_items(g_cMem, &n);
    g_ok[M_VRAM] = 0;
    if (!it || !g_vramTotal) return;
    for (DWORD i = 0; i < n; i++)
        if (good(&it[i]) && has_luid(it[i].szName)) { used += it[i].FmtValue.doubleValue; found = 1; }
    if (!found) return;
    g_vramUsed = used / 1073741824.0;
    g_val[M_VRAM] = 100.0 * used / (double)g_vramTotal;
    g_ok[M_VRAM] = 1;
}

static void *__stdcall adl_alloc(int size)
{
    return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size > 0 ? (SIZE_T)size : 1);
}

static int adl_query(ADL_PMLOG *log)
{
    if (!pAdlPMLog || g_adlIndex < 0) return 0;
    ZeroMemory(log, sizeof *log);
    log->size = sizeof *log;
    return pAdlPMLog(g_adl, g_adlIndex, log) == 0;
}

static int adl_power(ADL_PMLOG *log, double *w)
{
    if (!adl_query(log)) return 0;
    if (log->sensors[ADL_BOARD_POWER].supported && log->sensors[ADL_BOARD_POWER].value > 0)
        *w = log->sensors[ADL_BOARD_POWER].value;
    else if (log->sensors[ADL_ASIC_POWER].supported && log->sensors[ADL_ASIC_POWER].value > 0)
        *w = log->sensors[ADL_ASIC_POWER].value;
    else return 0;
    return 1;
}

static void init_adl(void)
{
    static ADL_PMLOG log;
    HMODULE m = sysdll(L"atiadlxx.dll");
    if (!m) return;
    T_ADL2_Create create = (T_ADL2_Create)(void *)GetProcAddress(m, "ADL2_Main_Control_Create");
    T_ADL2_Count count = (T_ADL2_Count)(void *)GetProcAddress(m, "ADL2_Adapter_NumberOfAdapters_Get");
    pAdlPMLog = (T_ADL2_PMLog)(void *)GetProcAddress(m, "ADL2_New_QueryPMLogData_Get");
    int n = 0;
    if (!create || !count || !pAdlPMLog || create(adl_alloc, 1, &g_adl) != 0 || !g_adl || count(g_adl, &n) != 0) {
        pAdlPMLog = NULL;
        return;
    }
    double w;
    for (int i = 0; i < n && i < 64; i++) {
        g_adlIndex = i;
        if (adl_power(&log, &w)) return;
    }
    g_adlIndex = -1;
    pAdlPMLog = NULL;
}

static int kmt_perf(KMT_PERF *p)
{
    if (!g_kmt || !pKmtQuery) return 0;
    ZeroMemory(p, sizeof *p);
    KMT_QAI q = { g_kmt, KMTQAITYPE_ADAPTERPERFDATA, p, sizeof *p };
    return pKmtQuery(&q) == 0;
}

static int kmt_temp(double *t)
{
    KMT_PERF p;
    if (!kmt_perf(&p) || p.Temperature == 0) return 0;
    *t = p.Temperature / 10.0;
    return 1;
}

static void read_gpu_temp(void)
{
    double t; unsigned nt;
    g_ok[M_GPUT] = 0;
    if (kmt_temp(&t)) { g_val[M_GPUT] = t; g_ok[M_GPUT] = 1; }
    else if (pNvTemp && pNvTemp(g_nvDev, 0, &nt) == 0) { g_val[M_GPUT] = nt; g_ok[M_GPUT] = 1; }
}

typedef struct { int Version; WCHAR Name[MAX_PATH]; } KMT_UMD;
#define KMTQAITYPE_UMDRIVERNAME 1

static HMODULE nvml_from_driver_store(void)
{
    KMT_UMD u;
    wchar_t path[MAX_PATH + 16];
    if (!g_kmt || !pKmtQuery) return NULL;
    ZeroMemory(&u, sizeof u);
    u.Version = 2;
    KMT_QAI q = { g_kmt, KMTQAITYPE_UMDRIVERNAME, &u, sizeof u };
    if (pKmtQuery(&q) != 0 || !u.Name[0]) return NULL;
    lstrcpynW(path, u.Name, MAX_PATH);
    int n = lstrlenW(path);
    while (n && path[n - 1] != L'\\') n--;
    if (!n || _wcsnicmp(path, L"C:\\Windows\\System32\\DriverStore\\", 31) != 0) return NULL;
    lstrcpyW(path + n, L"nvml.dll");
    return LoadLibraryExW(path, NULL, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
}

static int nv_field_power(double *w)
{
    NV_FIELD f;
    if (!pNvFields) return 0;
    ZeroMemory(&f, sizeof f);
    f.fieldId = g_nvField;
    if (pNvFields(g_nvDev, 1, &f) != 0 || f.nvmlReturn != 0 || !f.value.ui) return 0;
    *w = f.value.ui / 1000.0;
    return 1;
}

static void init_nvml(void)
{
    HMODULE nv = sysdll(L"nvml.dll");
    if (!nv) nv = nvml_from_driver_store();
    if (!nv) nv = LoadLibraryExW(L"C:\\Program Files\\NVIDIA Corporation\\NVSMI\\nvml.dll", NULL,
                                 LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!nv) return;
    int (*init)(void) = (int (*)(void))(void *)GetProcAddress(nv, "nvmlInit_v2");
    int (*hnd)(unsigned, void **) = (int (*)(unsigned, void **))(void *)GetProcAddress(nv, "nvmlDeviceGetHandleByIndex_v2");
    PFN_NVTEMP tp = (PFN_NVTEMP)(void *)GetProcAddress(nv, "nvmlDeviceGetTemperature");
    if (!init || !hnd || !tp || init() != 0) { FreeLibrary(nv); return; }
    if (hnd(0, &g_nvDev) != 0) return;
    pNvTemp = tp;
    pNvClock = (PFN_NVCLOCK)(void *)GetProcAddress(nv, "nvmlDeviceGetClockInfo");
    unsigned mw;
    unsigned long long mj;
    pNvPower = (PFN_NVPOWER)(void *)GetProcAddress(nv, "nvmlDeviceGetPowerUsage");
    if (pNvPower && pNvPower(g_nvDev, &mw) != 0) pNvPower = NULL;
    if (!pNvPower) {
        pNvEnergy = (PFN_NVENERGY)(void *)GetProcAddress(nv, "nvmlDeviceGetTotalEnergyConsumption");
        if (pNvEnergy && pNvEnergy(g_nvDev, &mj) != 0) pNvEnergy = NULL;
    }
    if (!pNvPower && !pNvEnergy) {
        double w;
        pNvFields = (PFN_NVFIELDS)(void *)GetProcAddress(nv, "nvmlDeviceGetFieldValues");
        g_nvField = NVML_FI_DEV_POWER_INSTANT;
        if (!nv_field_power(&w)) {
            g_nvField = NVML_FI_DEV_POWER_AVERAGE;
            if (!nv_field_power(&w)) pNvFields = NULL;
        }
    }
}

static void init_gpu(void)
{
    HMODULE d = sysdll(L"dxgi.dll");
    if (d) {
        typedef HRESULT (WINAPI *CF)(const GUID *, void **);
        CF cf = (CF)(void *)GetProcAddress(d, "CreateDXGIFactory1");
        IDXGIFactory1 *f;
        if (cf && SUCCEEDED(cf(&IID_F1, (void **)&f))) {
            IDXGIAdapter1 *a;
            for (UINT i = 0; IDXGIFactory1_EnumAdapters1(f, i, &a) != DXGI_ERROR_NOT_FOUND; i++) {
                DXGI_ADAPTER_DESC1 dd;
                if (SUCCEEDED(IDXGIAdapter1_GetDesc1(a, &dd)) && !(dd.Flags & DXGI_ADAPTER_FLAG_SOFTWARE)
                    && dd.VendorId != 0x1414 && (!g_hasGpu || dd.DedicatedVideoMemory > g_vramTotal)) {
                    g_vramTotal = dd.DedicatedVideoMemory;
                    g_gpuVendor = dd.VendorId;
                    g_luid = dd.AdapterLuid;
                    g_hasGpu = 1;
                    lstrcpynW(g_gpuName, dd.Description, 64);
                }
                IDXGIAdapter1_Release(a);
            }
            IDXGIFactory1_Release(f);
        }
    }
    if (!g_hasGpu) return;
    _snwprintf(g_luidStr, 40, L"luid_0x%08X_0x%08X", (unsigned)g_luid.HighPart, (unsigned)g_luid.LowPart);

    HMODULE gdi = GetModuleHandleW(L"gdi32.dll");
    PFN_KMT pOpen = (PFN_KMT)(void *)GetProcAddress(gdi, "D3DKMTOpenAdapterFromLuid");
    pKmtQuery     = (PFN_KMT)(void *)GetProcAddress(gdi, "D3DKMTQueryAdapterInfo");
    KMT_OPEN o = { g_luid, 0 };
    if (pOpen && pOpen(&o) == 0) g_kmt = o.hAdapter;

    double t;
    KMT_PERF kp;
    g_kmtPower = kmt_perf(&kp) && kp.Power > 0;
    if (g_gpuVendor == 0x1002) init_adl();
    if (!kmt_temp(&t) || g_gpuVendor == 0x10DE) init_nvml();
}

#define IOCTL_PIO_LOAD 0xA1B22084u
#define IOCTL_PIO_EXEC 0xA1B22104u
enum { PIO_UNTRIED, PIO_OK, PIO_NODRIVER, PIO_NOMODULE, PIO_NOADMIN, PIO_FAILED, PIO_UNSUPPORTED };
static int              g_pioState;
static HANDLE           g_pio = INVALID_HANDLE_VALUE, g_pciMutex;
static int              g_cpuVendor, g_tjmax;
static CRITICAL_SECTION g_pioCs;

static int pio_exec(const char *fn, ULONGLONG in, ULONGLONG *out)
{
    BYTE buf[40]; ULONGLONG o = 0; DWORD got = 0;
    ZeroMemory(buf, sizeof buf);
    lstrcpynA((char *)buf, fn, 32);
    memcpy(buf + 32, &in, 8);
    if (!DeviceIoControl(g_pio, IOCTL_PIO_EXEC, buf, sizeof buf, &o, sizeof o, &got, NULL) || got < 8) return 0;
    *out = o;
    return 1;
}

static void pio_init(void)
{
    EnterCriticalSection(&g_pioCs);
    if (g_pio != INVALID_HANDLE_VALUE) { CloseHandle(g_pio); g_pio = INVALID_HANDLE_VALUE; }
    unsigned b;
#ifdef _MSC_VER
    int r[4]; __cpuid(r, 0); b = (unsigned)r[1];
#else
    unsigned a, c, d;
    if (!__get_cpuid(0, &a, &b, &c, &d)) b = 0;
#endif
    g_cpuVendor = b == 0x756e6547 ? 1 : b == 0x68747541 ? 2 : 0;
    if (!g_cpuVendor) { g_pioState = PIO_UNSUPPORTED; goto out; }

    g_pio = CreateFileW(L"\\\\?\\GLOBALROOT\\Device\\PawnIO", GENERIC_READ | GENERIC_WRITE,
                        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (g_pio == INVALID_HANDLE_VALUE) {
        g_pioState = GetLastError() == ERROR_ACCESS_DENIED ? PIO_NOADMIN : PIO_NODRIVER;
        goto out;
    }

    HRSRC r = FindResourceW(NULL, MAKEINTRESOURCEW(g_cpuVendor == 1 ? 101 : 102), (LPCWSTR)RT_RCDATA);
    HGLOBAL hg = r ? LoadResource(NULL, r) : NULL;
    const void *src = hg ? LockResource(hg) : NULL;
    DWORD sz = r ? SizeofResource(NULL, r) : 0, got = 0;
    int ok = src && sz;
    if (!ok) { g_pioState = PIO_NOMODULE; }
    else if (!DeviceIoControl(g_pio, IOCTL_PIO_LOAD, (void *)src, sz, NULL, 0, &got, NULL)) g_pioState = PIO_FAILED;
    else {
        ULONGLONG v;
        g_pioState = PIO_OK;
        if (g_cpuVendor == 1) {
            g_tjmax = pio_exec("ioctl_read_msr", 0x1A2, &v) ? (int)((v >> 16) & 0xFF) : 0;
            if (g_tjmax < 60 || g_tjmax > 130) g_tjmax = 100;
        } else if (!g_pciMutex) g_pciMutex = CreateMutexW(NULL, FALSE, L"Global\\Access_PCI");
    }
    if (g_pioState != PIO_OK) { CloseHandle(g_pio); g_pio = INVALID_HANDLE_VALUE; }
out:
    LeaveCriticalSection(&g_pioCs);
}

static int pio_temp(double *t)
{
    ULONGLONG v; int ok = 0;
    if (g_pioState != PIO_OK) return 0;
    EnterCriticalSection(&g_pioCs);
    if (g_pio != INVALID_HANDLE_VALUE) {
        if (g_cpuVendor == 1) {
            if (pio_exec("ioctl_read_msr", 0x1B1, &v)) { *t = g_tjmax - (double)((v >> 16) & 0x7F); ok = 1; }
        } else {
            DWORD w = g_pciMutex ? WaitForSingleObject(g_pciMutex, 20) : WAIT_OBJECT_0;
            if (w == WAIT_OBJECT_0 || w == WAIT_ABANDONED) {
                if (pio_exec("ioctl_read_smn", 0x00059800, &v)) {
                    double c = ((v >> 21) & 0x7FF) / 8.0;
                    if (v & 0x80000) c -= 49.0;
                    *t = c; ok = 1;
                }
                if (g_pciMutex) ReleaseMutex(g_pciMutex);
            }
        }
    }
    LeaveCriticalSection(&g_pioCs);
    return ok && *t > 0 && *t < 125;
}

#define PAWNIO_HOST L"github.com"
#define PAWNIO_PATH L"/namazso/PawnIO.Setup/releases/download/2.2.0/PawnIO_setup.exe"
static const BYTE PAWNIO_SHA256[32] = {
    0x1f,0x51,0x9a,0x22,0xe4,0x71,0x87,0xf7,0x0a,0x13,0x79,0xa4,0x8c,0xa6,0x04,0x98,
    0x1c,0x4f,0xcf,0x69,0x4f,0x4e,0x65,0xb7,0x34,0xaa,0xa7,0x4a,0x9f,0xba,0x30,0x32 };

static BYTE *http_get(const wchar_t *host, const wchar_t *path, DWORD *len)
{
    BYTE *buf = NULL; DWORD cap = 0, n = 0;
    HINTERNET s = WinHttpOpen(L"TraySense", 4 , NULL, NULL, 0);
    if (!s) s = WinHttpOpen(L"TraySense", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, NULL, NULL, 0);
    HINTERNET c = s ? WinHttpConnect(s, host, INTERNET_DEFAULT_HTTPS_PORT, 0) : NULL;
    HINTERNET r = c ? WinHttpOpenRequest(c, L"GET", path, NULL, NULL, NULL, WINHTTP_FLAG_SECURE) : NULL;
    DWORD status = 0, ssz = sizeof status;
    if (r && WinHttpSendRequest(r, NULL, 0, NULL, 0, 0, 0) && WinHttpReceiveResponse(r, NULL) &&
        WinHttpQueryHeaders(r, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, NULL, &status, &ssz, NULL) &&
        status == 200) {
        for (;;) {
            DWORD avail = 0, rd = 0;
            if (!WinHttpQueryDataAvailable(r, &avail) || !avail) break;
            if (n + avail > (16u << 20)) { n = 0; break; }
            if (n + avail > cap) {
                cap = (n + avail) * 2;
                BYTE *nb = buf ? HeapReAlloc(GetProcessHeap(), 0, buf, cap) : HeapAlloc(GetProcessHeap(), 0, cap);
                if (!nb) { n = 0; break; }
                buf = nb;
            }
            if (!WinHttpReadData(r, buf + n, avail, &rd) || !rd) break;
            n += rd;
        }
    }
    if (r) WinHttpCloseHandle(r);
    if (c) WinHttpCloseHandle(c);
    if (s) WinHttpCloseHandle(s);
    if (!n && buf) { HeapFree(GetProcessHeap(), 0, buf); buf = NULL; }
    *len = n;
    return buf;
}

static int sha256_is(const BYTE *data, DWORD len, const BYTE *want)
{
    BCRYPT_ALG_HANDLE alg; BCRYPT_HASH_HANDLE h; BYTE out[32]; int ok = 0;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, NULL, 0)) return 0;
    if (!BCryptCreateHash(alg, &h, NULL, 0, NULL, 0, 0)) {
        if (!BCryptHashData(h, (PUCHAR)data, len, 0) && !BCryptFinishHash(h, out, 32, 0)) ok = !memcmp(out, want, 32);
        BCryptDestroyHash(h);
    }
    BCryptCloseAlgorithmProvider(alg, 0);
    return ok;
}

static int pawnio_install(const wchar_t **msg)
{
    DWORD len = 0, w, code = 1;
    if (!load_net()) { *msg = L"Không thể tải các thành phần mạng của Windows."; return 0; }
    BYTE *bin = http_get(PAWNIO_HOST, PAWNIO_PATH, &len);
    if (!bin) { *msg = L"Không thể tải trình cài đặt PawnIO từ GitHub. Hãy kiểm tra kết nối Internet."; return 0; }
    if (!sha256_is(bin, len, PAWNIO_SHA256)) {
        HeapFree(GetProcessHeap(), 0, bin);
        *msg = L"Trình cài đặt PawnIO đã tải xuống không khớp mã kiểm tra đã biết nên không được chạy.";
        return 0;
    }
    wchar_t dir[MAX_PATH], exe[MAX_PATH], cmd[MAX_PATH + 32];
    if (!app_dir(dir)) {
        HeapFree(GetProcessHeap(), 0, bin);
        *msg = L"Không thể tạo thư mục TraySense trong Program Files.";
        return 0;
    }
    _snwprintf(exe, MAX_PATH, L"%s\\PawnIO_setup.exe", dir); exe[MAX_PATH - 1] = 0;
    HANDLE f = CreateFileW(exe, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    int wrote = f != INVALID_HANDLE_VALUE && WriteFile(f, bin, len, &w, NULL) && w == len;
    if (f != INVALID_HANDLE_VALUE) CloseHandle(f);
    HeapFree(GetProcessHeap(), 0, bin);
    if (!wrote) { DeleteFileW(exe); *msg = L"Không thể lưu trình cài đặt PawnIO."; return 0; }

    _snwprintf(cmd, MAX_PATH + 32, L"\"%s\" -install -silent", exe); cmd[MAX_PATH + 31] = 0;
    STARTUPINFOW si; PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof si); si.cb = sizeof si;
    if (CreateProcessW(exe, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, dir, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, 180000);
        GetExitCodeProcess(pi.hProcess, &code);
        CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    }
    DeleteFileW(exe);
    if (code != 0 && code != 3010) { *msg = L"Trình cài đặt PawnIO báo lỗi."; return 0; }
    return 1;
}

static HANDLE g_disk = INVALID_HANDLE_VALUE;

static void init_disk(void)
{
    DWORD num = 0, got;
    wchar_t sysdrv[8] = L"\\\\.\\C:", p[40];
    wchar_t win[MAX_PATH];
    if (GetWindowsDirectoryW(win, MAX_PATH) >= 2) sysdrv[4] = win[0];
    HANDLE v = CreateFileW(sysdrv, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (v != INVALID_HANDLE_VALUE) {
        BYTE b[256];
        if (DeviceIoControl(v, IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS, NULL, 0, b, sizeof b, &got, NULL))
            num = ((VOLUME_DISK_EXTENTS *)b)->Extents[0].DiskNumber;
        CloseHandle(v);
    }
    _snwprintf(p, 40, L"\\\\.\\PhysicalDrive%u", (unsigned)num); p[39] = 0;
    g_disk = CreateFileW(p, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
}

static void read_disk(void)
{
    STORAGE_PROPERTY_QUERY q; BYTE b[512]; DWORD got = 0;
    g_ok[M_DISKT] = 0;
    if (g_disk == INVALID_HANDLE_VALUE) return;
    ZeroMemory(&q, sizeof q);
    q.PropertyId = StorageDeviceTemperatureProperty;
    q.QueryType = PropertyStandardQuery;
    if (!DeviceIoControl(g_disk, IOCTL_STORAGE_QUERY_PROPERTY, &q, sizeof q, b, sizeof b, &got, NULL)) return;
    STORAGE_TEMPERATURE_DATA_DESCRIPTOR *d = (STORAGE_TEMPERATURE_DATA_DESCRIPTOR *)b;
    if (got < sizeof *d || !d->InfoCount) return;
    int mx = -1000;
    for (WORD i = 0; i < d->InfoCount; i++) {
        if ((BYTE *)&d->TemperatureInfo[i + 1] > b + got) break;
        if (d->TemperatureInfo[i].Temperature > mx) mx = d->TemperatureInfo[i].Temperature;
    }
    if (mx > 0 && mx < 150) { g_val[M_DISKT] = mx; g_ok[M_DISKT] = 1; }
}

static void build_query(void)
{
    if (g_q) { PdhCloseQuery(g_q); g_q = 0; }
    g_cTherm = g_cEng = g_cMem = g_cDisk = 0;
    if (!(g_mask & ((1u << M_CPUT) | (1u << M_GPU) | (1u << M_VRAM) | (1u << M_DISKA))) || !load_pdh()) return;
    if (PdhOpenQueryW(NULL, 0, &g_q) != ERROR_SUCCESS) { g_q = 0; return; }
    if ((g_mask & (1u << M_CPUT)) && g_pioState != PIO_OK &&
        PdhAddEnglishCounterW(g_q, L"\\Thermal Zone Information(*)\\Temperature", 0, &g_cTherm)) g_cTherm = 0;
    if (g_hasGpu && (g_mask & (1u << M_GPU)) &&
        PdhAddEnglishCounterW(g_q, L"\\GPU Engine(*)\\Utilization Percentage", 0, &g_cEng)) g_cEng = 0;
    if (g_hasGpu && (g_mask & (1u << M_VRAM)) &&
        PdhAddEnglishCounterW(g_q, L"\\GPU Adapter Memory(*)\\Dedicated Usage", 0, &g_cMem)) g_cMem = 0;
    if ((g_mask & (1u << M_DISKA)) &&
        PdhAddEnglishCounterW(g_q, L"\\PhysicalDisk(*)\\% Idle Time", 0, &g_cDisk)) g_cDisk = 0;
    PdhCollectQueryData(g_q);
}

static void read_cpu_power(void)
{
    static ULONG64 lastE, lastT;
    static double unit;
    ULONGLONG v = 0;
    int ok = 0;
    if (g_pioState != PIO_OK) { g_ok[M_CPUW] = 0; return; }
    EnterCriticalSection(&g_pioCs);
    if (g_pio != INVALID_HANDLE_VALUE) {
        int intel = g_cpuVendor == 1;
        if (!unit && pio_exec("ioctl_read_msr", intel ? 0x606 : 0xC0010299, &v))
            unit = 1.0 / (double)(1ull << ((v >> 8) & 0x1F));
        if (unit && pio_exec("ioctl_read_msr", intel ? 0x611 : 0xC001029B, &v)) ok = 1;
    }
    LeaveCriticalSection(&g_pioCs);
    if (!ok) { g_ok[M_CPUW] = 0; return; }
    ULONG64 e = v & 0xFFFFFFFFull, now = GetTickCount64();
    if (lastT && now > lastT) {
        double w = (double)((e - lastE) & 0xFFFFFFFFull) * unit / ((now - lastT) / 1000.0);
        if (w >= 0 && w < 1000) { g_val[M_CPUW] = w; g_ok[M_CPUW] = 1; }
    }
    lastE = e; lastT = now;
}

static void read_gpu_power(void)
{
    static ADL_PMLOG log;
    static unsigned long long lastMj, lastT;
    unsigned long long mj;
    unsigned mw;
    double w;
    KMT_PERF p;
    g_ok[M_GPUW] = 0;
    if (pNvPower && pNvPower(g_nvDev, &mw) == 0) {
        g_val[M_GPUW] = mw / 1000.0;
        g_gpuPowerPct = 0;
        g_ok[M_GPUW] = 1;
    } else if (nv_field_power(&w)) {
        g_val[M_GPUW] = w;
        g_gpuPowerPct = 0;
        g_ok[M_GPUW] = 1;
    } else if (pNvEnergy && pNvEnergy(g_nvDev, &mj) == 0) {
        unsigned long long now = GetTickCount64();
        if (lastT && now > lastT && mj >= lastMj) {
            g_val[M_GPUW] = (double)(mj - lastMj) / (double)(now - lastT);
            g_gpuPowerPct = 0;
            g_ok[M_GPUW] = 1;
        }
        lastMj = mj; lastT = now;
    } else if (adl_power(&log, &w)) {
        g_val[M_GPUW] = w;
        g_gpuPowerPct = 0;
        g_ok[M_GPUW] = 1;
    } else if (g_kmtPower && kmt_perf(&p) && p.Power > 0 && p.Power <= 2000) {
        g_val[M_GPUW] = p.Power / 10.0;
        g_gpuPowerPct = 1;
        g_ok[M_GPUW] = 1;
    }
}

static void read_gpu_clocks(void)
{
    static ADL_PMLOG log;
    unsigned mhz;
    KMT_PERF p;
    KMT_NODE nd;
    int wantCore = g_mask >> M_GPUCLK & 1, wantMem = g_mask >> M_MEMCLK & 1, adl = 0;
    g_ok[M_GPUCLK] = g_ok[M_MEMCLK] = 0;
    if (pNvClock) {
        if (wantCore && pNvClock(g_nvDev, 0, &mhz) == 0 && mhz) { g_val[M_GPUCLK] = mhz; g_ok[M_GPUCLK] = 1; }
        if (wantMem && pNvClock(g_nvDev, 2, &mhz) == 0 && mhz) { g_val[M_MEMCLK] = mhz; g_ok[M_MEMCLK] = 1; }
    }
    if ((wantCore && !g_ok[M_GPUCLK]) || (wantMem && !g_ok[M_MEMCLK])) adl = adl_query(&log);
    if (adl) {
        if (wantCore && !g_ok[M_GPUCLK] && log.sensors[1].supported && log.sensors[1].value > 0) {
            g_val[M_GPUCLK] = log.sensors[1].value; g_ok[M_GPUCLK] = 1;
        }
        if (wantMem && !g_ok[M_MEMCLK] && log.sensors[2].supported && log.sensors[2].value > 0) {
            g_val[M_MEMCLK] = log.sensors[2].value; g_ok[M_MEMCLK] = 1;
        }
    }
    if (wantCore && !g_ok[M_GPUCLK] && g_kmt && pKmtQuery) {
        ZeroMemory(&nd, sizeof nd);
        KMT_QAI q = { g_kmt, KMTQAITYPE_NODEPERFDATA, &nd, sizeof nd };
        if (pKmtQuery(&q) == 0 && nd.Freq >= 1000000) { g_val[M_GPUCLK] = nd.Freq / 1e6; g_ok[M_GPUCLK] = 1; }
    }
    if (wantMem && !g_ok[M_MEMCLK] && kmt_perf(&p) && p.MemFreq >= 1000000) {
        g_val[M_MEMCLK] = p.MemFreq / 1e6; g_ok[M_MEMCLK] = 1;
    }
}

static void read_disk_activity(void)
{
    DWORD n;
    wchar_t drive[4] = L"C:", win[MAX_PATH];
    if (GetWindowsDirectoryW(win, MAX_PATH) >= 2) drive[0] = win[0];
    PDH_FMT_COUNTERVALUE_ITEM_W *it = pdh_items(g_cDisk, &n);
    g_ok[M_DISKA] = 0;
    if (!it) return;
    for (DWORD i = 0; i < n; i++) {
        if (!good(&it[i]) || !wcsstr(it[i].szName, drive)) continue;
        double busy = 100.0 - it[i].FmtValue.doubleValue;
        g_val[M_DISKA] = busy < 0 ? 0 : busy > 100 ? 100 : busy;
        g_ok[M_DISKA] = 1;
        return;
    }
}

static void sample(void)
{
    if (g_mask & (1u << M_CPU)) read_cpu();
    if (g_mask & (1u << M_RAM)) read_ram();
    if (g_q && PdhCollectQueryData(g_q) == ERROR_SUCCESS) {
        if (g_cTherm) read_therm();
        if (g_cEng)   read_gpu_usage();
        if (g_cMem)   read_vram();
        if (g_cDisk)  read_disk_activity();
    }
    if (g_mask & (1u << M_GPUT)) read_gpu_temp();
    if (g_mask & (1u << M_CPUT)) {
        double t = 0;
        if (pio_temp(&t)) { g_val[M_CPUT] = t; g_ok[M_CPUT] = 1; }
        else if (!g_cTherm) g_ok[M_CPUT] = 0;
    }
    if (g_mask & (1u << M_DISKT)) {
        static unsigned k;
        if (k++ % 5 == 0 || !g_ok[M_DISKT]) read_disk();
    }
    if (g_mask & (1u << M_CPUW)) read_cpu_power();
    if (g_mask & (1u << M_GPUW)) read_gpu_power();
    if (g_mask & ((1u << M_GPUCLK) | (1u << M_MEMCLK))) read_gpu_clocks();
}

enum { SH_CPU, SH_RAM, SH_GPU };
static const int SHAPE[M_TRAYN]  = { SH_CPU, SH_CPU, SH_RAM, SH_GPU, SH_GPU, SH_RAM, SH_RAM };
static const int ISTEMP[M_TRAYN] = { 0, 1, 0, 0, 1, 0, 1 };
#define SS 4
static HDC   g_ldc;
static int   g_S;
static HFONT g_font[3][4];

static void reset_fonts(void)
{
    for (int a = 0; a < 3; a++)
        for (int b = 0; b < 4; b++)
            if (g_font[a][b]) { DeleteObject(g_font[a][b]); g_font[a][b] = 0; }
}

static void read_env(void)
{
    DWORD v = 0, sz = sizeof v;
    g_size = GetSystemMetrics(SM_CXSMICON);
    if (g_size < 16) g_size = 16;
    if (g_size > 64) g_size = 64;
    g_light = RegGetValueW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize",
                           L"SystemUsesLightTheme", RRF_RT_REG_DWORD, NULL, &v, &sz) == ERROR_SUCCESS && v;
    reset_fonts();
}

static int P(float v) { return (int)(v * g_S / 16.0f + 0.5f); }
static void box(float x0, float y0, float x1, float y1, int on)
{
    RECT r = { P(x0), P(y0), P(x1), P(y1) };
    FillRect(g_ldc, &r, (HBRUSH)GetStockObject(on ? WHITE_BRUSH : BLACK_BRUSH));
}
static void rbox(float x0, float y0, float x1, float y1, float rad, int on)
{
    SelectObject(g_ldc, GetStockObject(on ? WHITE_BRUSH : BLACK_BRUSH));
    SelectObject(g_ldc, GetStockObject(NULL_PEN));
    RoundRect(g_ldc, P(x0), P(y0), P(x1) + 1, P(y1) + 1, P(rad * 2), P(rad * 2));
}

static void shape(int sh, int solid, float in[4])
{
    switch (sh) {
    case SH_CPU:
        for (int i = 0; i < 4; i++) {
            float a = (float)(3 + 3 * i);
            box(a, 0, a + 1, 1.25f, 1);  box(a, 14.75f, a + 1, 16, 1);
            box(0, a, 1.25f, a + 1, 1);  box(14.75f, a, 16, a + 1, 1);
        }
        rbox(1, 1, 15, 15, 1.5f, 1);
        if (!solid) rbox(2, 2, 14, 14, 0.6f, 0);
        in[0] = 1.75f; in[1] = 1.75f; in[2] = 14.25f; in[3] = 14.25f;
        break;
    case SH_RAM: {
        static const float tx[6] = { 1, 3, 5, 10, 12, 14 };
        for (int i = 0; i < 6; i++) box(tx[i], 13, tx[i] + 1, 15.5f, 1);
        rbox(0, 0.5f, 16, 13.5f, 1, 1);
        if (!solid) rbox(1, 1.5f, 15, 12.5f, 0.4f, 0);
        in[0] = 0.75f; in[1] = 1.25f; in[2] = 15.25f; in[3] = 12.75f;
        break; }
    default:
        box(0, 0.5f, 1, 16, 1);
        box(0, 0.5f, 2, 1.5f, 1);
        box(5, 13, 9, 15.5f, 1);
        box(10, 13, 14, 15.5f, 1);
        rbox(1.75f, 0.5f, 16, 13.5f, 1, 1);
        if (!solid) rbox(2.75f, 1.5f, 15, 12.5f, 0.4f, 0);
        in[0] = 2.5f; in[1] = 1.25f; in[2] = 15.25f; in[3] = 12.75f;
    }
}

static HFONT font_for(int sh, int len, int iw, int ih)
{
    if (g_font[sh][len]) return g_font[sh][len];
    static const wchar_t z[] = L"000";
    for (int h = ih * 3 / 2; h > 4; h -= 1 + h / 24) {
        HFONT f = CreateFontW(-h, 0, 0, 0, FW_BOLD, 0, 0, 0, DEFAULT_CHARSET, 0, 0,
                              NONANTIALIASED_QUALITY, 0, L"Bahnschrift SemiBold Condensed");
        HGDIOBJ o = SelectObject(g_ldc, f);
        SIZE s; TEXTMETRICW tm;
        GetTextExtentPoint32W(g_ldc, z, len, &s);
        GetTextMetricsW(g_ldc, &tm);
        SelectObject(g_ldc, o);
        if (s.cx <= iw && (tm.tmAscent - tm.tmInternalLeading) <= ih) return g_font[sh][len] = f;
        DeleteObject(f);
    }
    return g_font[sh][len] = (HFONT)GetStockObject(DEFAULT_GUI_FONT);
}

static COLORREF heat(double t)
{
    static const double   T[5] = { 35, 55, 70, 80, 90 };
    static const COLORREF C[5] = { RGB(60,170,255), RGB(70,210,110), RGB(250,205,50), RGB(255,135,40), RGB(255,45,45) };
    if (t <= T[0]) return C[0];
    for (int i = 1; i < 5; i++)
        if (t < T[i]) {
            double k = (t - T[i - 1]) / (T[i] - T[i - 1]);
            COLORREF a = C[i - 1], b = C[i];
            return RGB(GetRValue(a) + (GetRValue(b) - GetRValue(a)) * k,
                       GetGValue(a) + (GetGValue(b) - GetGValue(a)) * k,
                       GetBValue(a) + (GetBValue(b) - GetBValue(a)) * k);
        }
    return C[4];
}

static void over(double *r, double *g, double *b, double *a, COLORREF c, double ca)
{
    double na = ca + *a * (1 - ca);
    if (na <= 0) return;
    *r = (GetRValue(c) * ca + *r * *a * (1 - ca)) / na;
    *g = (GetGValue(c) * ca + *g * *a * (1 - ca)) / na;
    *b = (GetBValue(c) * ca + *b * *a * (1 - ca)) / na;
    *a = na;
}

static HICON make_icon(int m, const wchar_t *txt)
{
    static BYTE maskBits[8 * 64];
    static BYTE cov[3][64 * 64];
    int s = g_size, S = s * SS, len = lstrlenW(txt), sh = SHAPE[m];
    int solid = ISTEMP[m] && g_ok[m];
    g_S = S;

    BITMAPINFO bi; ZeroMemory(&bi, sizeof bi);
    bi.bmiHeader.biSize = sizeof bi.bmiHeader;
    bi.bmiHeader.biWidth = S; bi.bmiHeader.biHeight = -S;
    bi.bmiHeader.biPlanes = 1; bi.bmiHeader.biBitCount = 32;
    DWORD *px;
    g_ldc = CreateCompatibleDC(NULL);
    HBITMAP big = CreateDIBSection(g_ldc, &bi, DIB_RGB_COLORS, (void **)&px, NULL, 0);
    if (!big) { DeleteDC(g_ldc); return NULL; }
    HGDIOBJ ob = SelectObject(g_ldc, big);
    SetBkMode(g_ldc, TRANSPARENT);
    SetTextColor(g_ldc, RGB(255, 255, 255));

    float in[4] = { 0 };
    for (int layer = 0; layer < 3; layer++) {
        ZeroMemory(px, (SIZE_T)S * S * 4);
        if (layer == 0) shape(sh, solid, in);
        else if (layer == 1) {
            if (!ISTEMP[m] && g_ok[m]) {
                double p = g_val[m] < 0 ? 0 : g_val[m] > 100 ? 100 : g_val[m];
                float y = in[3] - (in[3] - in[1]) * (float)p / 100.0f;
                if (p > 0.5) box(in[0], y, in[2], in[3], 1);
            }
        } else {
            int ix = P(in[0]), iy = P(in[1]), iw = P(in[2]) - ix, ih = P(in[3]) - iy;
            int pad = S / 64;
            HGDIOBJ of = SelectObject(g_ldc, font_for(sh, len > 3 ? 3 : len, iw - 2 * pad, ih - 2 * pad));
            TEXTMETRICW tm; SIZE ts;
            GetTextMetricsW(g_ldc, &tm);
            GetTextExtentPoint32W(g_ldc, txt, len, &ts);
            int cap = tm.tmAscent - tm.tmInternalLeading;
            TextOutW(g_ldc, ix + (iw - ts.cx) / 2, iy + (ih - cap) / 2 - tm.tmInternalLeading, txt, len);
            SelectObject(g_ldc, of);
        }
        GdiFlush();
        for (int y = 0; y < s; y++)
            for (int x = 0; x < s; x++) {
                unsigned sum = 0;
                for (int j = 0; j < SS; j++) {
                    const DWORD *row = px + (y * SS + j) * S + x * SS;
                    for (int i = 0; i < SS; i++) sum += row[i] & 0xFF;
                }
                cov[layer][y * s + x] = (BYTE)(sum / (SS * SS));
            }
    }
    SelectObject(g_ldc, ob);
    DeleteObject(big);
    DeleteDC(g_ldc);

    COLORREF col = !g_ok[m] ? RGB(140, 140, 140) : ISTEMP[m] ? heat(g_val[m]) : (g_light ? COL_L : COL_D)[m];
    COLORREF fg  = g_light ? RGB(25, 25, 25) : RGB(255, 255, 255);
    bi.bmiHeader.biWidth = s; bi.bmiHeader.biHeight = -s;
    HBITMAP bmp = CreateDIBSection(NULL, &bi, DIB_RGB_COLORS, (void **)&px, NULL, 0);
    if (!bmp) return NULL;
    for (int i = 0; i < s * s; i++) {
        double F = cov[0][i] / 255.0, B = cov[1][i] / 255.0, T = cov[2][i] / 255.0;
        double r = 0, g = 0, b = 0, a = 0;
        if (solid) over(&r, &g, &b, &a, col, F * (1 - T));
        else {
            over(&r, &g, &b, &a, col, B * 0.42);
            over(&r, &g, &b, &a, col, F);
            over(&r, &g, &b, &a, fg, T);
        }
        DWORD A = (DWORD)(a * 255 + 0.5);
        px[i] = A ? (A << 24) | ((DWORD)(r + .5) << 16) | ((DWORD)(g + .5) << 8) | (DWORD)(b + .5) : 0;
    }
    HBITMAP mask = CreateBitmap(s, s, 1, 1, maskBits);
    ICONINFO ii = { TRUE, 0, 0, mask, bmp };
    HICON ic = CreateIconIndirect(&ii);
    DeleteObject(mask);
    DeleteObject(bmp);
    return ic;
}

static void tip_for(int m, wchar_t *t)
{
    if (!g_ok[m]) { _snwprintf(t, 128, L"%s: không có dữ liệu", NAMES[m]); return; }
    switch (m) {
    case M_RAM:  _snwprintf(t, 128, L"RAM: %.0f%%  (%.1f / %.1f GB)", g_val[m], g_ramUsed, g_ramTotal); break;
    case M_VRAM: _snwprintf(t, 128, L"VRAM: %.0f%%  (%.1f / %.1f GB)", g_val[m], g_vramUsed, g_vramTotal / 1073741824.0); break;
    case M_GPU:  _snwprintf(t, 128, L"GPU: %.0f%%  %s", g_val[m], g_gpuName); break;
    case M_GPUT: _snwprintf(t, 128, L"Nhiệt độ GPU: %.0f\x00B0" L"C", g_val[m]); break;
    case M_CPUT: _snwprintf(t, 128, L"Nhiệt độ CPU: %.0f\x00B0" L"C", g_val[m]); break;
    case M_DISKT: _snwprintf(t, 128, L"Nhiệt độ SSD: %.0f\x00B0" L"C", g_val[m]); break;
    default:     _snwprintf(t, 128, L"CPU: %.0f%%", g_val[m]);
    }
    t[127] = 0;
}

static void tray(int m, DWORD op)
{
    NOTIFYICONDATAW n; ZeroMemory(&n, sizeof n);
    n.cbSize = sizeof n; n.hWnd = g_wnd; n.uID = m + 1;
    n.uFlags = NIF_ICON | NIF_TIP | NIF_MESSAGE;
    n.uCallbackMessage = WM_TRAY;
    n.hIcon = g_icon[m];
    tip_for(m, n.szTip);
    Shell_NotifyIconW(op, &n);
}

enum { MODE_BAR, MODE_TRAY };
static DWORD          g_mode = MODE_BAR;
static LONG           g_offset;
static volatile int   g_paused;
static volatile LONG  g_rebuild = 1, g_quit, g_scanDirty = 1;
static HANDLE         g_wake;
#define WM_SAMPLED (WM_APP + 2)
#define WM_SPEEDDONE (WM_APP + 3)

#define ST_HOST L"speed.cloudflare.com"
static volatile LONG    g_stRunning;
static volatile LONG64  g_stBytes, g_stFirst;
static ULONG64          g_stDeadline;
static double           g_stDown, g_stUp;
static ULONG64          g_stShowUntil;
static int              g_stFailed;

static DWORD WINAPI st_worker(void *arg)
{
    static BYTE blank[65536];
    int up = arg != NULL;
    HINTERNET s = WinHttpOpen(L"TraySense", 4, NULL, NULL, 0);
    if (!s) s = WinHttpOpen(L"TraySense", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, NULL, NULL, 0);
    HINTERNET c = s ? WinHttpConnect(s, ST_HOST, INTERNET_DEFAULT_HTTPS_PORT, 0) : NULL;
    HINTERNET r = c ? WinHttpOpenRequest(c, up ? L"POST" : L"GET", up ? L"/__up" : L"/__down?bytes=60000000",
                                         NULL, NULL, NULL, WINHTTP_FLAG_SECURE) : NULL;
    if (r && !up && WinHttpSendRequest(r, NULL, 0, NULL, 0, 0, 0) && WinHttpReceiveResponse(r, NULL)) {
        BYTE *buf = HeapAlloc(GetProcessHeap(), 0, sizeof blank);
        DWORD rd;
        while (buf && GetTickCount64() < g_stDeadline && WinHttpReadData(r, buf, sizeof blank, &rd) && rd) {
            InterlockedCompareExchange64(&g_stFirst, (LONG64)GetTickCount64(), 0);
            InterlockedAdd64(&g_stBytes, rd);
        }
        if (buf) HeapFree(GetProcessHeap(), 0, buf);
    } else if (r && up) {
        DWORD total = 25000000, done = 0, w;
        if (WinHttpSendRequest(r, L"Content-Type: application/octet-stream", (DWORD)-1, NULL, 0, total, 0))
            while (done < total && GetTickCount64() < g_stDeadline &&
                   WinHttpWriteData(r, blank, total - done < sizeof blank ? total - done : sizeof blank, &w) && w) {
                InterlockedCompareExchange64(&g_stFirst, (LONG64)GetTickCount64(), 0);
                InterlockedAdd64(&g_stBytes, w);
                done += w;
            }
    }
    if (r) WinHttpCloseHandle(r);
    if (c) WinHttpCloseHandle(c);
    if (s) WinHttpCloseHandle(s);
    return 0;
}

static double st_phase(int up)
{
    HANDLE th[4];
    int n = 0;
    g_stBytes = 0;
    g_stFirst = 0;
    g_stDeadline = GetTickCount64() + 8000;
    for (int i = 0; i < 4; i++)
        if ((th[n] = CreateThread(NULL, 64 * 1024, st_worker, up ? (void *)1 : NULL, STACK_SIZE_PARAM_IS_A_RESERVATION, NULL))) n++;
    if (n) WaitForMultipleObjects(n, th, TRUE, 15000);
    for (int i = 0; i < n; i++) CloseHandle(th[i]);
    ULONG64 end = GetTickCount64(), first = (ULONG64)g_stFirst;
    if (!first || end <= first || g_stBytes < 100000) return 0;
    return (double)g_stBytes * 8.0 / ((end - first) / 1000.0);
}

static DWORD WINAPI st_main(void *unused)
{
    (void)unused;
    double down = 0, up = 0;
    if (load_net()) {
        down = st_phase(0);
        if (down > 0) up = st_phase(1);
    }
    g_stDown = down;
    g_stUp = up;
    PostMessageW(g_wnd, WM_SPEEDDONE, down > 0, 0);
    return 0;
}

static void fmt_speed(wchar_t *out, int n, double bits)
{
    if (bits >= 1e9) _snwprintf(out, n, L"%.2f Gbps", bits / 1e9);
    else _snwprintf(out, n, L"%.0f Mbps", bits / 1e6);
    out[n - 1] = 0;
}

static void refresh(int force);

static void speed_test(void)
{
    DWORD one = 1, v = 0, sz = sizeof v;
    if (g_stRunning) return;
    RegGetValueW(HKEY_CURRENT_USER, REGKEY, L"SpeedTestOk", RRF_RT_REG_DWORD, NULL, &v, &sz);
    if (!v) {
        if (MessageBoxW(g_wnd, L"Kiểm tra tốc độ sẽ tải xuống và tải lên dữ liệu tạm thời từ máy chủ kiểm tra tốc độ "
                               L"của Cloudflare (speed.cloudflare.com) trong vài giây.\n\nVới kết nối nhanh, dữ liệu có thể "
                               L"lên tới vài trăm MB; trò chơi hoặc tải xuống sẽ chậm hơn khi đang kiểm tra.\n\nChạy ngay?",
                        APP L" \x2013 Kiểm tra tốc độ", MB_YESNO | MB_ICONQUESTION) != IDYES) return;
        RegSetKeyValueW(HKEY_CURRENT_USER, REGKEY, L"SpeedTestOk", REG_DWORD, &one, sizeof one);
    }
    g_stRunning = 1;
    g_stFailed = 0;
    refresh(0);
    HANDLE t = CreateThread(NULL, 64 * 1024, st_main, NULL, STACK_SIZE_PARAM_IS_A_RESERVATION, NULL);
    if (t) CloseHandle(t);
    else g_stRunning = 0;
}

static void tray_refresh(int force)
{
    for (int m = 0; m < M_TRAYN; m++) {
        int on = g_mode == MODE_TRAY && ((g_mask >> m) & 1);
        if (!on) {
            if (g_shown[m]) { tray(m, NIM_DELETE); g_shown[m] = 0; }
            continue;
        }
        wchar_t t[4];
        if (!g_ok[m]) lstrcpyW(t, L"--");
        else {
            int v = (int)(g_val[m] + 0.5);
            if (v < 0) v = 0;
            if (v > 999) v = 999;
            _snwprintf(t, 4, L"%d", v); t[3] = 0;
        }
        if (!force && g_shown[m] && !lstrcmpW(t, g_txt[m])) continue;
        lstrcpyW(g_txt[m], t);
        HICON old = g_icon[m];
        g_icon[m] = make_icon(m, t);
        if (!g_shown[m]) { tray(m, NIM_ADD); g_shown[m] = 1; }
        else tray(m, NIM_MODIFY);
        if (old) DestroyIcon(old);
    }
}

#define MAX_BARS 8
typedef struct {
    HWND wnd, tb;
    int child, primary, W, H, compact, wideW, fontDpi, icoOK[4];
    RECT lastPos, grc[8];
    int ngrp, gid[8], vert;
    wchar_t sig[320];
    HFONT font, small, ico;
    HBITMAP big;
    DWORD *bp;
    int bigW, bigH;
} BAR;
enum { SHOW_MAIN, SHOW_ALL, SHOW_OTHERS };
enum { POS_TRAY, POS_APPS, POS_LEFT };
enum { ROWS_AUTO, ROWS_ONE, ROWS_TWO };
static BAR   g_bars[MAX_BARS];
static BAR  *bar = g_bars;
static int   g_dpi = 96;
static DWORD g_where = SHOW_MAIN, g_pos = POS_TRAY, g_rows = ROWS_AUTO;

typedef struct { int glyph, sh, x, y, w, h, al, f; wchar_t t[16]; COLORREF c; } SEG;
enum { G_CPU, G_RAM, G_GPU, G_DISK, G_NET };
#define DRAWN(sh) ((sh) == G_GPU || (sh) == G_NET)

static int SC(int v) { return MulDiv(v, g_dpi, 96); }

static void get_dpi(void)
{
    typedef UINT (WINAPI *GDW)(HWND);
    static GDW f; static int tried;
    if (!tried) { tried = 1; f = (GDW)(void *)GetProcAddress(GetModuleHandleW(L"user32.dll"), "GetDpiForWindow"); }
    UINT d = (f && bar->tb) ? f(bar->tb) : 0;
    if (!d) { HDC dc = GetDC(NULL); d = GetDeviceCaps(dc, LOGPIXELSY); ReleaseDC(NULL, dc); }
    g_dpi = d < 96 ? 96 : (int)d;
}

static void glyph_cov(int sh, int gs, BYTE *out)
{
    int S = gs * SS;
    g_S = S;
    BITMAPINFO bi; ZeroMemory(&bi, sizeof bi);
    bi.bmiHeader.biSize = sizeof bi.bmiHeader;
    bi.bmiHeader.biWidth = S; bi.bmiHeader.biHeight = -S;
    bi.bmiHeader.biPlanes = 1; bi.bmiHeader.biBitCount = 32;
    DWORD *px;
    g_ldc = CreateCompatibleDC(NULL);
    HBITMAP big = CreateDIBSection(g_ldc, &bi, DIB_RGB_COLORS, (void **)&px, NULL, 0);
    ZeroMemory(out, (SIZE_T)gs * gs);
    if (big) {
        HGDIOBJ ob = SelectObject(g_ldc, big);
        ZeroMemory(px, (SIZE_T)S * S * 4);
        float in[4];
        shape(sh, 0, in);
        GdiFlush();
        for (int y = 0; y < gs; y++)
            for (int x = 0; x < gs; x++) {
                unsigned sum = 0;
                for (int j = 0; j < SS; j++) {
                    const DWORD *row = px + (y * SS + j) * S + x * SS;
                    for (int i = 0; i < SS; i++) sum += row[i] & 0xFF;
                }
                out[y * gs + x] = (BYTE)(sum / (SS * SS));
            }
        SelectObject(g_ldc, ob);
        DeleteObject(big);
    }
    DeleteDC(g_ldc);
}

static LRESULT CALLBACK barproc(HWND w, UINT msg, WPARAM wp, LPARAM lp);

static void bar_create(HWND tb, int primary)
{
    if (bar->font) DeleteObject(bar->font);
    if (bar->small) DeleteObject(bar->small);
    if (bar->ico) DeleteObject(bar->ico);
    if (bar->big) DeleteObject(bar->big);
    ZeroMemory(bar, sizeof *bar);
    bar->tb = tb;
    bar->primary = primary;
    bar->wnd = CreateWindowExW(WS_EX_LAYERED | WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE, L"TraySenseBar", L"",
                               WS_POPUP, 0, 0, 1, 1, NULL, NULL, GetModuleHandleW(NULL), NULL);
    if (bar->wnd) {
        SetWindowLongPtrW(bar->wnd, GWL_STYLE, WS_CHILD | WS_CLIPSIBLINGS);
        if (SetParent(bar->wnd, tb)) bar->child = 1;
        else SetWindowLongPtrW(bar->wnd, GWL_STYLE, WS_POPUP);
    }
}

static void bar_to_popup(void)
{
    SetParent(bar->wnd, NULL);
    SetWindowLongPtrW(bar->wnd, GWL_STYLE, WS_POPUP);
    SetWindowLongPtrW(bar->wnd, GWL_EXSTYLE, GetWindowLongPtrW(bar->wnd, GWL_EXSTYLE) | WS_EX_TOPMOST);
    bar->child = 0;
    ZeroMemory(&bar->lastPos, sizeof bar->lastPos);
}

static void bar_destroy(BAR *b)
{
    HWND w = b->wnd;
    b->wnd = NULL;
    if (w && IsWindow(w)) DestroyWindow(w);
    if (b->font) DeleteObject(b->font);
    if (b->small) DeleteObject(b->small);
    if (b->ico) DeleteObject(b->ico);
    if (b->big) DeleteObject(b->big);
    ZeroMemory(b, sizeof *b);
}

static void bars_destroy(void)
{
    for (int i = 0; i < MAX_BARS; i++) bar_destroy(&g_bars[i]);
}

static int find_taskbars(HWND *out, int max)
{
    int n = 0;
    HWND p = FindWindowW(L"Shell_TrayWnd", NULL), s = NULL;
    if (p) out[n++] = p;
    while (n < max && (s = FindWindowExW(NULL, s, L"Shell_SecondaryTrayWnd", NULL))) out[n++] = s;
    return n;
}

typedef struct { HWND tb; LONG ok, trayL, appsR, leftL, leftR; } SCAN;
static SCAN g_scan[MAX_BARS];
static CRITICAL_SECTION g_scanCs;
static IUIAutomation *g_uia;
static IUIAutomationCacheRequest *g_uiaCache;
static IUIAutomationCondition *g_uiaAll;

static const GUID CLSID_UIA = {0xff48dba4,0x60ef,0x4201,{0xaa,0x87,0x54,0x10,0x3e,0xef,0x59,0x4e}};
static const GUID IID_UIA   = {0x30cbe57d,0xd9d0,0x452a,{0xab,0x13,0x7a,0xc5,0xac,0x48,0x25,0xee}};
static const GUID IID_CF    = {0x00000001,0x0000,0x0000,{0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x46}};

static int uia_init(void)
{
    static int tried;
    if (tried) return g_uia != NULL;
    tried = 1;
    HMODULE m = sysdll(L"UIAutomationCore.dll");
    typedef HRESULT (WINAPI *DGCO)(const GUID *, const GUID *, void **);
    DGCO get = m ? (DGCO)(void *)GetProcAddress(m, "DllGetClassObject") : NULL;
    IClassFactory *cf = NULL;
    if (!get || FAILED(get(&CLSID_UIA, &IID_CF, (void **)&cf)) || !cf) return 0;
    HRESULT hr = IClassFactory_CreateInstance(cf, NULL, &IID_UIA, (void **)&g_uia);
    IClassFactory_Release(cf);
    if (FAILED(hr) || !g_uia) { g_uia = NULL; return 0; }
    if (FAILED(IUIAutomation_CreateCacheRequest(g_uia, &g_uiaCache)) ||
        FAILED(IUIAutomation_CreateTrueCondition(g_uia, &g_uiaAll))) {
        IUIAutomation_Release(g_uia); g_uia = NULL; return 0;
    }
    IUIAutomationCacheRequest_AddProperty(g_uiaCache, UIA_ClassNamePropertyId);
    IUIAutomationCacheRequest_AddProperty(g_uiaCache, UIA_BoundingRectanglePropertyId);
    IUIAutomationCacheRequest_AddProperty(g_uiaCache, UIA_IsOffscreenPropertyId);
    IUIAutomationCacheRequest_put_AutomationElementMode(g_uiaCache, AutomationElementMode_None);
    return 1;
}

static int starts(const wchar_t *s, const wchar_t *p)
{
    return s && !wcsncmp(s, p, wcslen(p));
}

static int scan_one(HWND tb, int primary, LONG *outTray, LONG *outApps, LONG *outLeftL, LONG *outLeftR)
{
    static RECT rc[256];
    static BYTE app[256];
    RECT tr;
    if (!GetWindowRect(tb, &tr) ||
        !FindWindowExW(tb, NULL, L"Windows.UI.Composition.DesktopWindowContentBridge", NULL)) return 0;
    IUIAutomationElement *root = NULL;
    IUIAutomationElementArray *arr = NULL;
    int n = 0, cnt = 0;
    if (SUCCEEDED(IUIAutomation_ElementFromHandle(g_uia, (UIA_HWND)tb, &root)) && root &&
        SUCCEEDED(IUIAutomationElement_FindAllBuildCache(root, TreeScope_Descendants, g_uiaAll, g_uiaCache, &arr)) && arr)
        IUIAutomationElementArray_get_Length(arr, &cnt);
    int tbw = tr.right - tr.left;
    for (int i = 0; i < cnt && n < 256; i++) {
        IUIAutomationElement *e = NULL;
        if (FAILED(IUIAutomationElementArray_GetElement(arr, i, &e)) || !e) continue;
        BSTR cls = NULL; RECT r; BOOL off = FALSE;
        IUIAutomationElement_get_CachedClassName(e, &cls);
        IUIAutomationElement_get_CachedBoundingRectangle(e, &r);
        IUIAutomationElement_get_CachedIsOffscreen(e, &off);
        int w = r.right - r.left;
        if (!off && w > 0 && r.bottom > r.top && w < tbw / 3 && r.top < tr.bottom && r.bottom > tr.top &&
            !(cls && !lstrcmpW(cls, L"TraySenseBar"))) {
            rc[n] = r;
            app[n] = starts(cls, L"Taskbar.") || starts(cls, L"StartButton") || starts(cls, L"SearchBox");
            n++;
        }
        if (cls) SysFreeString(cls);
        IUIAutomationElement_Release(e);
    }
    if (arr) IUIAutomationElementArray_Release(arr);
    if (root) IUIAutomationElement_Release(root);

    int appsR = tr.left, trayL = tr.right, apps = 0;
    for (int i = 0; i < n; i++)
        if (app[i] && rc[i].right > appsR) { appsR = rc[i].right; apps = 1; }
    for (int i = 0; i < n; i++)
        if (!app[i] && rc[i].left >= appsR && rc[i].left < trayL) trayL = rc[i].left;
    HWND tn = FindWindowExW(tb, NULL, L"TrayNotifyWnd", NULL);
    RECT nr;
    if (tn && GetWindowRect(tn, &nr) && nr.right > nr.left && nr.left < trayL) trayL = nr.left;
    if ((primary && !apps) || trayL <= appsR) return 0;
    static BYTE used[256];
    int cur = tr.left, mid = tr.left + tbw / 2, bestL = 0, bestR = 0;
    ZeroMemory(used, sizeof used);
    for (;;) {
        int k = -1;
        for (int i = 0; i < n; i++)
            if (!used[i] && rc[i].left < appsR && (k < 0 || rc[i].left < rc[k].left)) k = i;
        if (k < 0) break;
        used[k] = 1;
        if (cur < mid && rc[k].left - cur > bestR - bestL) { bestL = cur; bestR = rc[k].left; }
        if (rc[k].right > cur) cur = rc[k].right;
    }
    *outTray = trayL;
    *outApps = appsR;
    *outLeftL = bestL;
    *outLeftR = bestR;
    return 1;
}

static void uia_scan(void)
{
    HWND tbs[MAX_BARS];
    SCAN res[MAX_BARS];
    HWND main = FindWindowW(L"Shell_TrayWnd", NULL);
    int n = find_taskbars(tbs, MAX_BARS), ok = uia_init();
    for (int i = 0; i < n; i++) {
        res[i].tb = tbs[i];
        res[i].trayL = res[i].appsR = res[i].leftL = res[i].leftR = 0;
        res[i].ok = ok && scan_one(tbs[i], tbs[i] == main, &res[i].trayL, &res[i].appsR, &res[i].leftL, &res[i].leftR);
    }
    EnterCriticalSection(&g_scanCs);
    ZeroMemory(g_scan, sizeof g_scan);
    memcpy(g_scan, res, sizeof res[0] * n);
    LeaveCriticalSection(&g_scanCs);
}

static int scan_for(HWND tb, int *trayL, int *appsR, int *leftL, int *leftR)
{
    int ok = 0;
    EnterCriticalSection(&g_scanCs);
    for (int i = 0; i < MAX_BARS; i++)
        if (g_scan[i].tb == tb && g_scan[i].ok) {
            *trayL = g_scan[i].trayL; *appsR = g_scan[i].appsR;
            *leftL = g_scan[i].leftL; *leftR = g_scan[i].leftR;
            ok = 1;
            break;
        }
    LeaveCriticalSection(&g_scanCs);
    return ok;
}

static void bar_place(void)
{
    RECT tr, nr;
    if (!bar->wnd) return;
    if (!bar->tb || !GetWindowRect(bar->tb, &tr)) {
        ShowWindow(bar->wnd, SW_HIDE);
        return;
    }
    get_dpi();
    if (tr.bottom - tr.top > tr.right - tr.left) {
        HWND tn = FindWindowExW(bar->tb, NULL, bar->primary ? L"TrayNotifyWnd" : L"ClockButton", NULL);
        int bottom = tn && GetWindowRect(tn, &nr) && nr.bottom > nr.top ? nr.top : tr.bottom - SC(120);
        int x = tr.left, y = bottom - SC(10) - bar->H + SC(g_offset);
        if (y < tr.top) y = tr.top;
        if (bar->child) { POINT p = { x, y }; ScreenToClient(bar->tb, &p); x = p.x; y = p.y; }
        RECT want = { x, y, x + bar->W, y + bar->H };
        int top = bar->child ? GetWindow(bar->tb, GW_CHILD) == bar->wnd : 1;
        if (memcmp(&want, &bar->lastPos, sizeof want) || !top || !IsWindowVisible(bar->wnd)) {
            SetWindowPos(bar->wnd, bar->child ? HWND_TOP : HWND_TOPMOST, x, y, bar->W, bar->H, SWP_NOACTIVATE | SWP_SHOWWINDOW);
            bar->lastPos = want;
        }
        return;
    }
    int trayL, appsR, leftL = 0, leftR = 0, scan = scan_for(bar->tb, &trayL, &appsR, &leftL, &leftR);
    if (!scan) {
        HWND tn = FindWindowExW(bar->tb, NULL, bar->primary ? L"TrayNotifyWnd" : L"ClockButton", NULL);
        if (tn && GetWindowRect(tn, &nr) && nr.right > nr.left) trayL = nr.left;
        else trayL = tr.right - (bar->primary ? SC(280) : SC(12));
        appsR = tr.left;
    }
    int pos = g_pos;
    if (!scan && pos != POS_TRAY) pos = POS_TRAY;
    if (pos == POS_LEFT && leftR - leftL < SC(60)) pos = POS_TRAY;
    int gapL = scan ? appsR + SC(10) : tr.left, gapR = trayL - SC(10);
    int avail = pos == POS_LEFT ? leftR - leftL - SC(20) : gapR - gapL;
    int compact = g_rows == ROWS_TWO ? 1 : g_rows == ROWS_ONE ? 0 :
                  bar->compact ? bar->wideW > avail - SC(10) : bar->wideW > avail;
    if (compact != bar->compact) {
        bar->compact = compact;
        bar->sig[0] = 0;
        PostMessageW(g_wnd, WM_SAMPLED, 0, 0);
    }
    if (pos != POS_TRAY && bar->W > avail) pos = POS_TRAY;
    int x = pos == POS_LEFT ? leftL + SC(10) : pos == POS_APPS ? gapL : gapR - bar->W;
    x += SC(g_offset);
    int h = tr.bottom - tr.top, y = tr.top;
    if (bar->child) { POINT p = { x, y }; ScreenToClient(bar->tb, &p); x = p.x; y = p.y; }
    RECT want = { x, y, x + bar->W, y + h };
    int top = bar->child ? GetWindow(bar->tb, GW_CHILD) == bar->wnd : 1;
    if (memcmp(&want, &bar->lastPos, sizeof want) || !top || !IsWindowVisible(bar->wnd)) {
        SetWindowPos(bar->wnd, bar->child ? HWND_TOP : HWND_TOPMOST, x, y, bar->W, h, SWP_NOACTIVATE | SWP_SHOWWINDOW);
        bar->lastPos = want;
    } else if (!bar->child)
        SetWindowPos(bar->wnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
}

static void seg_pct(SEG *s, int m, COLORREF fg)
{
    s->glyph = 0; s->c = fg; s->al = 255;
    if (!g_ok[m]) lstrcpyW(s->t, L"--");
    else _snwprintf(s->t, 16, L"%d%%", (int)(g_val[m] + 0.5));
    s->t[15] = 0;
}
static void seg_temp(SEG *s, int m, COLORREF fg)
{
    double hot = m == M_DISKT ? 65 : 80, crit = m == M_DISKT ? 75 : 90;
    s->glyph = 0; s->c = fg; s->al = 255;
    if (!g_ok[m]) { lstrcpyW(s->t, L"--\x00B0"); return; }
    double t = g_val[m];
    _snwprintf(s->t, 16, L"%d\x00B0", (int)(t + 0.5)); s->t[15] = 0;
    if (t >= crit) s->c = g_light ? RGB(200, 25, 25) : RGB(255, 75, 65);
    else if (t >= hot) s->c = g_light ? RGB(195, 95, 0) : RGB(255, 170, 55);
}
static void seg_label(SEG *s, const wchar_t *t, COLORREF fg)
{
    s->glyph = 0; s->c = fg; s->al = 150;
    lstrcpynW(s->t, t, 16);
}
static void seg_mhz(SEG *s, int m, COLORREF fg)
{
    s->glyph = 0; s->c = fg; s->al = 255;
    _snwprintf(s->t, 16, L"%d MHz", (int)(g_val[m] + 0.5)); s->t[15] = 0;
}
static void seg_watts(SEG *s, int m, COLORREF fg)
{
    s->glyph = 0; s->c = fg; s->al = 255;
    _snwprintf(s->t, 16, L"%dW", (int)(g_val[m] + 0.5)); s->t[15] = 0;
}

static void draw_net(HDC dc, int x0, int y0, int sz)
{
    int pw = sz / 16;
    if (pw < 1) pw = 1;
    HPEN pen = CreatePen(PS_SOLID, pw, RGB(255, 255, 255));
    HGDIOBJ op = SelectObject(dc, pen);
    POINT d[] = { { x0 + sz * 5 / 16, y0 + sz * 2 / 16 }, { x0 + sz * 5 / 16, y0 + sz * 14 / 16 } };
    POINT dh[] = { { x0 + sz * 2 / 16, y0 + sz * 11 / 16 }, { x0 + sz * 5 / 16, y0 + sz * 14 / 16 }, { x0 + sz * 8 / 16, y0 + sz * 11 / 16 } };
    POINT u[] = { { x0 + sz * 11 / 16, y0 + sz * 14 / 16 }, { x0 + sz * 11 / 16, y0 + sz * 2 / 16 } };
    POINT uh[] = { { x0 + sz * 8 / 16, y0 + sz * 5 / 16 }, { x0 + sz * 11 / 16, y0 + sz * 2 / 16 }, { x0 + sz * 14 / 16, y0 + sz * 5 / 16 } };
    Polyline(dc, d, 2);
    Polyline(dc, dh, 3);
    Polyline(dc, u, 2);
    Polyline(dc, uh, 3);
    SelectObject(dc, op);
    DeleteObject(pen);
}

static void draw_gpu(HDC dc, int x0, int y0, int sz)
{
#define GX(v) (x0 + (int)((v) * sz / 16.0f + 0.5f))
#define GY(v) (y0 + (int)((v) * sz / 16.0f + 0.5f))
    int pw = sz / 16; if (pw < 1) pw = 1;
    HPEN pen = CreatePen(PS_SOLID, pw, RGB(255, 255, 255));
    HGDIOBJ op = SelectObject(dc, pen), obr = SelectObject(dc, GetStockObject(NULL_BRUSH));
    RoundRect(dc, GX(2.5f), GY(3.5f), GX(14.5f), GY(12.5f), GX(3) - GX(0), GY(3) - GY(0));
    Ellipse(dc, GX(6), GY(5.5f), GX(11), GY(10.5f));
    SelectObject(dc, GetStockObject(NULL_PEN));
    SelectObject(dc, GetStockObject(WHITE_BRUSH));
    Ellipse(dc, GX(7.7f), GY(7.2f), GX(9.3f) + 1, GY(8.8f) + 1);
    RECT r1 = { GX(0), GY(2), GX(1), GY(14.5f) };
    RECT r2 = { GX(0), GY(2), GX(2.5f), GY(3) };
    RECT r3 = { GX(5), GY(13), GX(11), GY(14.5f) };
    FillRect(dc, &r1, (HBRUSH)GetStockObject(WHITE_BRUSH));
    FillRect(dc, &r2, (HBRUSH)GetStockObject(WHITE_BRUSH));
    FillRect(dc, &r3, (HBRUSH)GetStockObject(WHITE_BRUSH));
    SelectObject(dc, op); SelectObject(dc, obr);
    DeleteObject(pen);
#undef GX
#undef GY
}

static const wchar_t ICO_CH[4] = { 0xEEA1, 0xEEA0, 0, 0xEDA2 };
static const MAT2 MAT_ID = { {0,1}, {0,0}, {0,0}, {0,1} };

static HFONT mkfont(HDC dc, const wchar_t *face, int px, int weight)
{
    HFONT f = CreateFontW(-px, 0, 0, 0, weight, 0, 0, 0, DEFAULT_CHARSET, 0, 0, ANTIALIASED_QUALITY, 0, face);
    wchar_t got[LF_FACESIZE] = {0};
    HGDIOBJ o = SelectObject(dc, f);
    GetTextFaceW(dc, LF_FACESIZE, got);
    SelectObject(dc, o);
    if (lstrcmpiW(got, face)) { DeleteObject(f); return NULL; }
    return f;
}

static void bar_fonts(HDC dc)
{
    if (bar->font && bar->fontDpi == g_dpi) return;
    if (bar->font) DeleteObject(bar->font);
    if (bar->small) DeleteObject(bar->small);
    if (bar->ico) DeleteObject(bar->ico);
    int tp = SC(14) * SS, sp = SC(12) * SS, ip = SC(16) * SS;
    bar->font = mkfont(dc, L"Segoe UI Variable Text", tp, FW_NORMAL);
    if (!bar->font) bar->font = mkfont(dc, L"Segoe UI", tp, FW_NORMAL);
    if (!bar->font) bar->font = CreateFontW(-tp, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET, 0, 0, ANTIALIASED_QUALITY, 0, L"Tahoma");
    bar->small = mkfont(dc, L"Segoe UI Variable Text", sp, FW_NORMAL);
    if (!bar->small) bar->small = mkfont(dc, L"Segoe UI", sp, FW_NORMAL);
    if (!bar->small) bar->small = CreateFontW(-sp, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET, 0, 0, ANTIALIASED_QUALITY, 0, L"Tahoma");
    bar->ico = mkfont(dc, L"Segoe Fluent Icons", ip, FW_NORMAL);
    if (!bar->ico) bar->ico = mkfont(dc, L"Segoe MDL2 Assets", ip, FW_NORMAL);
    for (int k = 0; k < 4; k++) {
        WORD gi = 0xFFFF;
        bar->icoOK[k] = 0;
        if (!bar->ico || !ICO_CH[k]) continue;
        HGDIOBJ o = SelectObject(dc, bar->ico);
        if (GetGlyphIndicesW(dc, &ICO_CH[k], 1, &gi, GGI_MARK_NONEXISTING_GLYPHS) != GDI_ERROR && gi != 0xFFFF) bar->icoOK[k] = 1;
        SelectObject(dc, o);
    }
    bar->fontDpi = g_dpi;
}

static void ink(HDC dc, wchar_t ch, int *top, int *h, int *left, int *w)
{
    GLYPHMETRICS gm; TEXTMETRICW tm;
    GetTextMetricsW(dc, &tm);
    if (GetGlyphOutlineW(dc, ch, GGO_METRICS, &gm, 0, NULL, &MAT_ID) == GDI_ERROR) {
        *top = tm.tmInternalLeading; *h = tm.tmAscent - tm.tmInternalLeading; *left = 0; *w = tm.tmAveCharWidth; return;
    }
    *top = tm.tmAscent - gm.gmptGlyphOrigin.y; *h = gm.gmBlackBoxY;
    *left = gm.gmptGlyphOrigin.x; *w = gm.gmBlackBoxX;
}

static int text_w(HDC dc, const wchar_t *t)
{
    SIZE s;
    GetTextExtentPoint32W(dc, t, lstrlenW(t), &s);
    return s.cx;
}

static int layout(HDC dc, SEG *sg, int n, int compact, int HB)
{
    int gs = SC(16) * SS, top, h, d1, d2, X = SC(4) * SS;
    TEXTMETRICW tm;
    if (!compact) {
        SelectObject(dc, bar->font);
        ink(dc, L'0', &top, &h, &d1, &d2);
        GetTextMetricsW(dc, &tm);
        for (int i = 0; i < n; i++) {
            if (sg[i].glyph) {
                if (i) X += SC(14) * SS;
                sg[i].w = sg[i].h = gs;
                sg[i].y = HB / 2 - gs / 2;
            } else {
                X += (sg[i - 1].glyph ? SC(6) : sg[i].al < 255 || sg[i].t[0] == 0x2191 ? SC(9) :
                      sg[i - 1].al < 255 ? SC(4) : SC(5)) * SS;
                sg[i].w = text_w(dc, sg[i].t);
                sg[i].h = tm.tmHeight;
                sg[i].y = HB / 2 - (top + h / 2);
                sg[i].f = 0;
            }
            sg[i].x = X; X += sg[i].w;
        }
        return X + SC(4) * SS;
    }
    SelectObject(dc, bar->small);
    ink(dc, L'0', &top, &h, &d1, &d2);
    GetTextMetricsW(dc, &tm);
    int gap = SC(3) * SS, yTop = HB / 2 - gap / 2 - h - top, yBot = HB / 2 + gap / 2 - top, yMid = HB / 2 - h / 2 - top;
    for (int i = 0; i < n;) {
        if (sg[i].glyph) {
            if (i) X += SC(10) * SS;
            sg[i].x = X; sg[i].w = sg[i].h = gs; sg[i].y = HB / 2 - gs / 2; X += gs;
            i++;
            continue;
        }
        int a = i, b = (i + 1 < n && !sg[i + 1].glyph && sg[i + 1].al == 255) ? i + 1 : -1;
        X += (sg[a - 1].glyph ? SC(5) : SC(7)) * SS;
        int wa = text_w(dc, sg[a].t), wb = b >= 0 ? text_w(dc, sg[b].t) : 0;
        sg[a].x = X; sg[a].w = wa; sg[a].f = 1; sg[a].h = tm.tmHeight;
        if (b >= 0) {
            sg[a].y = yTop;
            sg[b].x = X; sg[b].w = wb; sg[b].f = 1; sg[b].y = yBot; sg[b].h = tm.tmHeight;
        } else sg[a].y = yMid;
        X += wa > wb ? wa : wb;
        i = b >= 0 ? b + 1 : a + 1;
    }
    return X + SC(4) * SS;
}

static int layout_col(HDC dc, SEG *sg, int n, int WB)
{
    int gs = SC(16) * SS, top, h, d1, d2, Y = SC(6) * SS;
    TEXTMETRICW tm;
    SelectObject(dc, bar->small);
    ink(dc, L'0', &top, &h, &d1, &d2);
    GetTextMetricsW(dc, &tm);
    for (int i = 0; i < n; i++) {
        sg[i].f = 1;
        if (sg[i].glyph) {
            if (i) Y += SC(10) * SS;
            sg[i].w = sg[i].h = gs;
            sg[i].x = (WB - gs) / 2;
            sg[i].y = Y;
            Y += gs + SC(4) * SS;
            continue;
        }
        sg[i].w = text_w(dc, sg[i].t);
        sg[i].h = tm.tmHeight;
        sg[i].x = (WB - sg[i].w) / 2;
        sg[i].y = Y - top;
        Y += h + SC(4) * SS;
    }
    return Y + SC(2) * SS;
}

static void find_groups(SEG *sg, int n)
{
    bar->ngrp = 0;
    for (int i = 0; i < n && bar->ngrp < 8; i++) {
        if (!sg[i].glyph) continue;
        RECT r = { sg[i].x / SS, sg[i].y / SS, (sg[i].x + sg[i].w) / SS, (sg[i].y + sg[i].h) / SS };
        for (int k = i + 1; k < n && !sg[k].glyph; k++) {
            if (sg[k].x / SS < r.left) r.left = sg[k].x / SS;
            if (sg[k].y / SS < r.top) r.top = sg[k].y / SS;
            if ((sg[k].x + sg[k].w) / SS > r.right) r.right = (sg[k].x + sg[k].w) / SS;
            if ((sg[k].y + sg[k].h) / SS > r.bottom) r.bottom = (sg[k].y + sg[k].h) / SS;
        }
        InflateRect(&r, SC(5), SC(4));
        bar->grc[bar->ngrp] = r;
        bar->gid[bar->ngrp++] = sg[i].sh;
    }
}

static void bar_draw(int force)
{
    static BYTE gc[64 * 64], lut[256];
    if (!lut[255]) for (int i = 0; i < 256; i++) lut[i] = (BYTE)(255.0 * pow(i / 255.0, 0.8) + 0.5);
    if (!bar->wnd) return;
    RECT tr = { 0, 0, 0, 40 };
    if (bar->tb) GetWindowRect(bar->tb, &tr);
    int vert = tr.bottom - tr.top > tr.right - tr.left;
    int H = vert ? 0 : tr.bottom - tr.top, VW = tr.right - tr.left;
    if (!vert && H < 16) H = 16;
    if (H > 400) H = 400;
    if (VW > 400) VW = 400;
    bar->vert = vert;
    get_dpi();
    COLORREF fg = g_light ? RGB(0, 0, 0) : RGB(255, 255, 255);

    SEG sg[24]; int n = 0;
    ZeroMemory(sg, sizeof sg);
    int cpuT = (g_mask & (1u << M_CPUT)) && g_ok[M_CPUT], cpuW = (g_mask & (1u << M_CPUW)) && g_ok[M_CPUW];
    if ((g_mask & (1u << M_CPU)) || cpuT || cpuW) {
        sg[n].glyph = 1; sg[n].sh = G_CPU; n++;
        if (g_mask & (1u << M_CPU)) seg_pct(&sg[n++], M_CPU, fg);
        if (cpuT) seg_temp(&sg[n++], M_CPUT, fg);
        if (cpuW) seg_watts(&sg[n++], M_CPUW, fg);
    }
    if (g_mask & (1u << M_RAM)) {
        sg[n].glyph = 1; sg[n].sh = G_RAM; n++;
        seg_pct(&sg[n++], M_RAM, fg);
    }
    int gpuT = (g_mask & (1u << M_GPUT)) && g_ok[M_GPUT], gpuW = (g_mask & (1u << M_GPUW)) && g_ok[M_GPUW];
    int gpuC = (g_mask & (1u << M_GPUCLK)) && g_ok[M_GPUCLK], memC = (g_mask & (1u << M_MEMCLK)) && g_ok[M_MEMCLK];
    if ((g_mask & ((1u << M_GPU) | (1u << M_VRAM))) || gpuT || gpuW || gpuC || memC) {
        sg[n].glyph = 1; sg[n].sh = G_GPU; n++;
        if (g_mask & (1u << M_GPU)) seg_pct(&sg[n++], M_GPU, fg);
        if (gpuT) seg_temp(&sg[n++], M_GPUT, fg);
        if (gpuW && g_gpuPowerPct) {
            seg_label(&sg[n++], L"TDP", fg);
            seg_pct(&sg[n++], M_GPUW, fg);
        } else if (gpuW) seg_watts(&sg[n++], M_GPUW, fg);
        if (gpuC) seg_mhz(&sg[n++], M_GPUCLK, fg);
        if (g_mask & (1u << M_VRAM)) {
            seg_label(&sg[n++], L"VRAM", fg);
            seg_pct(&sg[n++], M_VRAM, fg);
        }
        if (memC) {
            seg_label(&sg[n++], L"Mem", fg);
            seg_mhz(&sg[n++], M_MEMCLK, fg);
        }
    }
    if (g_stRunning || GetTickCount64() < g_stShowUntil) {
        sg[n].glyph = 1; sg[n].sh = G_NET; n++;
        if (g_stRunning) seg_label(&sg[n++], L"Đang kiểm tra...", fg);
        else if (g_stFailed) seg_label(&sg[n++], L"Kiểm tra thất bại", fg);
        else {
            SEG *d = &sg[n++], *u = &sg[n++];
            d->c = u->c = fg; d->al = u->al = 255;
            _snwprintf(d->t, 16, L"\x2193 %.0f", g_stDown / 1e6); d->t[15] = 0;
            _snwprintf(u->t, 16, L"\x2191 %.0f Mbps", g_stUp / 1e6); u->t[15] = 0;
        }
    }
    int diskT = (g_mask & (1u << M_DISKT)) && g_ok[M_DISKT], diskA = (g_mask & (1u << M_DISKA)) && g_ok[M_DISKA];
    if (diskT || diskA) {
        sg[n].glyph = 1; sg[n].sh = G_DISK; n++;
        if (diskA) seg_pct(&sg[n++], M_DISKA, fg);
        if (diskT) seg_temp(&sg[n++], M_DISKT, fg);
    }

    wchar_t sig[320]; int p = _snwprintf(sig, 320, L"%d|%d|%d|%d|%d|%d|", vert ? VW : H, vert, g_dpi, g_light, n, bar->compact);
    for (int i = 0; i < n && p > 0 && p < 290; i++)
        if (!sg[i].glyph) p += _snwprintf(sig + p, 320 - p, L"%s%06X|", sg[i].t, (unsigned)sg[i].c);
    sig[319] = 0;
    if (!force && !lstrcmpW(sig, bar->sig)) { bar_place(); return; }
    lstrcpyW(bar->sig, sig);

    HDC mdc = CreateCompatibleDC(NULL);
    bar_fonts(mdc);
    HGDIOBJ of = SelectObject(mdc, bar->font);
    int W, HB;
    if (vert) {
        W = VW;
        H = (layout_col(mdc, sg, n, W * SS) + SS - 1) / SS;
        if (H > 1200) H = 1200;
        HB = H * SS;
        bar->wideW = W;
    } else {
        HB = H * SS;
        bar->wideW = (layout(mdc, sg, n, 0, HB) + SS - 1) / SS;
        W = bar->compact ? (layout(mdc, sg, n, 1, HB) + SS - 1) / SS : bar->wideW;
        if (W > 1024) W = 1024;
    }
    int WB = W * SS;
    find_groups(sg, n);
    BYTE *segmap = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)W * H);
    if (!segmap) { SelectObject(mdc, of); DeleteDC(mdc); return; }

    BITMAPINFO bi; ZeroMemory(&bi, sizeof bi);
    bi.bmiHeader.biSize = sizeof bi.bmiHeader;
    bi.bmiHeader.biWidth = WB; bi.bmiHeader.biHeight = -HB;
    bi.bmiHeader.biPlanes = 1; bi.bmiHeader.biBitCount = 32;
    DWORD *bp, *px;
    if (!bar->big || bar->bigW != WB || bar->bigH != HB) {
        if (bar->big) DeleteObject(bar->big);
        bar->big = CreateDIBSection(mdc, &bi, DIB_RGB_COLORS, (void **)&bar->bp, NULL, 0);
        bar->bigW = WB;
        bar->bigH = HB;
    }
    HBITMAP big = bar->big;
    bp = bar->bp;
    bi.bmiHeader.biWidth = W; bi.bmiHeader.biHeight = -H;
    HBITMAP bmp = CreateDIBSection(mdc, &bi, DIB_RGB_COLORS, (void **)&px, NULL, 0);
    if (!big || !bmp) {
        if (bmp) DeleteObject(bmp);
        HeapFree(GetProcessHeap(), 0, segmap);
        SelectObject(mdc, of); DeleteDC(mdc); return;
    }
    HGDIOBJ ob = SelectObject(mdc, big);
    ZeroMemory(bp, (SIZE_T)WB * HB * 4);
    SetBkMode(mdc, TRANSPARENT);
    SetTextColor(mdc, RGB(255, 255, 255));
    for (int i = 0; i < n; i++) {
        if (sg[i].glyph) continue;
        SelectObject(mdc, sg[i].f ? bar->small : bar->font);
        TextOutW(mdc, sg[i].x, sg[i].y, sg[i].t, lstrlenW(sg[i].t));
        int x0 = sg[i].x / SS - 1, x1 = (sg[i].x + sg[i].w) / SS + 1, y0 = sg[i].y / SS, y1 = (sg[i].y + sg[i].h) / SS + 1;
        for (int y = y0 < 0 ? 0 : y0; y < y1 && y < H; y++)
            for (int x = x0 < 0 ? 0 : x0; x < x1 && x < W; x++) segmap[y * W + x] = (BYTE)(i + 1);
    }
    for (int i = 0; i < n; i++)
        if (sg[i].glyph && sg[i].sh == G_GPU) draw_gpu(mdc, sg[i].x, sg[i].y, sg[i].w);
        else if (sg[i].glyph && sg[i].sh == G_NET) draw_net(mdc, sg[i].x, sg[i].y, sg[i].w);
    SelectObject(mdc, bar->ico ? bar->ico : bar->font);
    for (int i = 0; i < n; i++) {
        if (!sg[i].glyph || DRAWN(sg[i].sh) || !bar->icoOK[sg[i].sh]) continue;
        int top, h, left, w;
        ink(mdc, ICO_CH[sg[i].sh], &top, &h, &left, &w);
        TextOutW(mdc, sg[i].x + (sg[i].w - w) / 2 - left, sg[i].y + sg[i].h / 2 - (top + h / 2), &ICO_CH[sg[i].sh], 1);
    }
    GdiFlush();

    for (int y = 0; y < H; y++)
        for (int x = 0; x < W; x++) {
            unsigned sum = 0;
            for (int j = 0; j < SS; j++) {
                const DWORD *row = bp + (y * SS + j) * WB + x * SS;
                for (int i = 0; i < SS; i++) sum += row[i] & 0xFF;
            }
            int k = segmap[y * W + x];
            DWORD a = lut[sum / (SS * SS)] * (k ? sg[k - 1].al : 255) / 255;
            COLORREF c = k ? sg[k - 1].c : fg;
            px[y * W + x] = a ? (a << 24) | ((GetRValue(c) * a / 255) << 16) | ((GetGValue(c) * a / 255) << 8) | (GetBValue(c) * a / 255)
                              : 0x01000000;
        }
    SelectObject(mdc, bmp);
    HeapFree(GetProcessHeap(), 0, segmap);

    int gs = SC(16);
    for (int i = 0; i < n; i++) {
        if (!sg[i].glyph || DRAWN(sg[i].sh) || bar->icoOK[sg[i].sh]) continue;
        glyph_cov(sg[i].sh == G_CPU ? SH_CPU : SH_RAM, gs > 64 ? 64 : gs, gc);
        int X0 = sg[i].x / SS;
        for (int y = 0; y < gs && y < 64; y++)
            for (int xx = 0; xx < gs && xx < 64; xx++) {
                DWORD a = gc[y * gs + xx];
                int Xp = X0 + xx, Y = sg[i].y / SS + y;
                if (!a || Xp >= W || Y < 0 || Y >= H) continue;
                px[Y * W + Xp] = (a << 24) | ((GetRValue(fg) * a / 255) << 16) | ((GetGValue(fg) * a / 255) << 8) | (GetBValue(fg) * a / 255);
            }
    }

    POINT src = { 0, 0 }; SIZE sz = { W, H };
    BLENDFUNCTION bf = { AC_SRC_OVER, 0, 255, AC_SRC_ALPHA };
    bar->W = W; bar->H = H;
    if (!UpdateLayeredWindow(bar->wnd, NULL, NULL, &sz, mdc, &src, 0, &bf, ULW_ALPHA) && bar->child) {
        bar_to_popup();
        UpdateLayeredWindow(bar->wnd, NULL, NULL, &sz, mdc, &src, 0, &bf, ULW_ALPHA);
    }
    SelectObject(mdc, ob);
    SelectObject(mdc, of);
    DeleteObject(bmp);
    DeleteDC(mdc);
    bar_place();
}

#define HIST 150
static float g_hist[M_N][HIST];
static BYTE  g_histOk[M_N][HIST];
static int   g_hpos, g_hcount;
static HWND  g_graph;
static BAR  *g_graphBar;
static int   g_graphGid = -1, g_graphFontDpi;
static HFONT g_graphFont, g_graphBold;

static void hist_push(void)
{
    for (int m = 0; m < M_N; m++) {
        g_hist[m][g_hpos] = (float)g_val[m];
        g_histOk[m][g_hpos] = (BYTE)g_ok[m];
    }
    g_hpos = (g_hpos + 1) % HIST;
    if (g_hcount < HIST) g_hcount++;
}

enum { K_PCT, K_TEMP, K_WATT, K_MHZ };
typedef struct { int m, kind; const wchar_t *name; COLORREF col; } SERIES;

static int group_series(int gid, SERIES *o)
{
    int n = 0;
#define ADD(mm, k, nm, c) if (g_mask >> (mm) & 1) { o[n].m = (mm); o[n].kind = (k); o[n].name = (nm); o[n].col = (c); n++; }
    COLORREF hot = RGB(255, 160, 60), pw = RGB(240, 200, 60), clk = RGB(80, 200, 190);
    if (gid == G_CPU) {
        ADD(M_CPU, K_PCT, L"Mức dùng CPU", RGB(80, 190, 255));
        ADD(M_CPUT, K_TEMP, L"Nhiệt độ CPU", hot);
        ADD(M_CPUW, K_WATT, L"Công suất CPU", pw);
    } else if (gid == G_RAM) {
        ADD(M_RAM, K_PCT, L"Mức dùng RAM", RGB(185, 145, 255));
    } else if (gid == G_GPU) {
        ADD(M_GPU, K_PCT, L"Mức dùng GPU", RGB(118, 215, 90));
        ADD(M_GPUT, K_TEMP, L"Nhiệt độ GPU", hot);
        ADD(M_GPUW, g_gpuPowerPct ? K_PCT : K_WATT, g_gpuPowerPct ? L"Công suất GPU (TDP)" : L"Công suất GPU", pw);
        ADD(M_GPUCLK, K_MHZ, L"Xung nhịp GPU", clk);
        ADD(M_VRAM, K_PCT, L"Mức dùng VRAM", RGB(118, 215, 90));
        ADD(M_MEMCLK, K_MHZ, L"Xung nhịp VRAM", clk);
    } else if (gid == G_DISK) {
        ADD(M_DISKA, K_PCT, L"Mức dùng ổ đĩa", RGB(150, 170, 255));
        ADD(M_DISKT, K_TEMP, L"Nhiệt độ SSD", hot);
    }
#undef ADD
    return n;
}

static void value_text(const SERIES *sr, double v, wchar_t *t)
{
    switch (sr->kind) {
    case K_PCT:  _snwprintf(t, 24, L"%d%%", (int)(v + 0.5)); break;
    case K_TEMP: _snwprintf(t, 24, L"%d\x00B0" L"C", (int)(v + 0.5)); break;
    case K_WATT: _snwprintf(t, 24, L"%d W", (int)(v + 0.5)); break;
    default:     _snwprintf(t, 24, L"%d MHz", (int)(v + 0.5)); break;
    }
    t[23] = 0;
}

static void blend(DWORD *px, int W, int H, int x0, int y0, const BYTE *cov, int cw, int ch, COLORREF c, int alpha)
{
    for (int y = 0; y < ch; y++)
        for (int x = 0; x < cw; x++) {
            int X = x0 + x, Y = y0 + y, a = cov[y * cw + x] * alpha / 255;
            if (!a || X < 0 || Y < 0 || X >= W || Y >= H) continue;
            DWORD d = px[Y * W + X];
            int r = (GetRValue(c) * a + ((d >> 16) & 0xFF) * (255 - a)) / 255;
            int g = (GetGValue(c) * a + ((d >> 8) & 0xFF) * (255 - a)) / 255;
            int b = (GetBValue(c) * a + (d & 0xFF) * (255 - a)) / 255;
            px[Y * W + X] = (DWORD)(r << 16 | g << 8 | b);
        }
}

static void coverage(int w, int h, int mode, const POINT *pts, int np, int pen, BYTE *out)
{
    int S = SS;
    BITMAPINFO bi; ZeroMemory(&bi, sizeof bi);
    bi.bmiHeader.biSize = sizeof bi.bmiHeader;
    bi.bmiHeader.biWidth = w * S; bi.bmiHeader.biHeight = -h * S;
    bi.bmiHeader.biPlanes = 1; bi.bmiHeader.biBitCount = 32;
    DWORD *p;
    HDC dc = CreateCompatibleDC(NULL);
    HBITMAP bm = CreateDIBSection(dc, &bi, DIB_RGB_COLORS, (void **)&p, NULL, 0);
    ZeroMemory(out, (SIZE_T)w * h);
    if (!bm) { DeleteDC(dc); return; }
    HGDIOBJ ob = SelectObject(dc, bm);
    ZeroMemory(p, (SIZE_T)w * h * S * S * 4);
    if (mode == 0) {
        SelectObject(dc, GetStockObject(WHITE_BRUSH));
        SelectObject(dc, GetStockObject(NULL_PEN));
        Polygon(dc, pts, np);
    } else if (mode == 1) {
        HPEN pn = CreatePen(PS_SOLID, pen, RGB(255, 255, 255));
        HGDIOBJ op = SelectObject(dc, pn);
        Polyline(dc, pts, np);
        SelectObject(dc, op);
        DeleteObject(pn);
    } else {
        SelectObject(dc, GetStockObject(WHITE_BRUSH));
        SelectObject(dc, GetStockObject(NULL_PEN));
        RoundRect(dc, 0, 0, w * S + 1, h * S + 1, pen, pen);
    }
    GdiFlush();
    for (int y = 0; y < h; y++)
        for (int x = 0; x < w; x++) {
            unsigned sum = 0;
            for (int j = 0; j < S; j++)
                for (int i = 0; i < S; i++) sum += p[(y * S + j) * w * S + x * S + i] & 0xFF;
            out[y * w + x] = (BYTE)(sum / (S * S));
        }
    SelectObject(dc, ob);
    DeleteObject(bm);
    DeleteDC(dc);
}

static void graph_hide(void)
{
    if (g_graph) ShowWindow(g_graph, SW_HIDE);
    g_graphBar = NULL;
    g_graphGid = -1;
}

static void graph_draw(void)
{
    SERIES sr[8];
    BAR *b = g_graphBar;
    if (!g_graph || !b || !b->wnd || g_graphGid < 0) return;
    int ns = group_series(g_graphGid, sr);
    if (!ns) { graph_hide(); return; }
    bar = b;
    get_dpi();
    if (!g_graphFont || g_graphFontDpi != g_dpi) {
        if (g_graphFont) DeleteObject(g_graphFont);
        if (g_graphBold) DeleteObject(g_graphBold);
        g_graphFont = CreateFontW(-SC(12), 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET, 0, 0, ANTIALIASED_QUALITY, 0, L"Segoe UI");
        g_graphBold = CreateFontW(-SC(12), 0, 0, 0, FW_SEMIBOLD, 0, 0, 0, DEFAULT_CHARSET, 0, 0, ANTIALIASED_QUALITY, 0, L"Segoe UI");
        g_graphFontDpi = g_dpi;
    }
    int pad = SC(10), gw = SC(240), gh = SC(30), lh = SC(17), row = lh + gh + SC(8);
    int W = gw + 2 * pad, H = pad + ns * row - SC(8) + pad;
    COLORREF bg = g_light ? RGB(249, 249, 249) : RGB(38, 38, 38), fg = g_light ? RGB(20, 20, 20) : RGB(240, 240, 240);
    COLORREF dim = g_light ? RGB(110, 110, 110) : RGB(160, 160, 160), grid = g_light ? RGB(225, 225, 225) : RGB(62, 62, 62);

    BITMAPINFO bi; ZeroMemory(&bi, sizeof bi);
    bi.bmiHeader.biSize = sizeof bi.bmiHeader;
    bi.bmiHeader.biWidth = W; bi.bmiHeader.biHeight = -H;
    bi.bmiHeader.biPlanes = 1; bi.bmiHeader.biBitCount = 32;
    DWORD *px;
    HDC dc = CreateCompatibleDC(NULL);
    HBITMAP bm = CreateDIBSection(dc, &bi, DIB_RGB_COLORS, (void **)&px, NULL, 0);
    BYTE *cov = HeapAlloc(GetProcessHeap(), 0, (SIZE_T)W * H);
    POINT *pts = HeapAlloc(GetProcessHeap(), 0, sizeof(POINT) * (HIST + 2));
    if (!bm || !cov || !pts) goto done;
    HGDIOBJ ob = SelectObject(dc, bm);
    for (int i = 0; i < W * H; i++) px[i] = (DWORD)(GetRValue(bg) << 16 | GetGValue(bg) << 8 | GetBValue(bg));
    SetBkMode(dc, TRANSPARENT);

    for (int k = 0; k < ns; k++) {
        int y0 = pad + k * row, gy = y0 + lh;
        int last = (g_hpos + HIST - 1) % HIST;
        double cur = g_hist[sr[k].m][last], mx = 0;
        wchar_t val[24] = L"--";
        if (g_hcount && g_histOk[sr[k].m][last]) value_text(&sr[k], cur, val);
        SelectObject(dc, g_graphFont);
        SetTextColor(dc, dim);
        TextOutW(dc, pad, y0, sr[k].name, lstrlenW(sr[k].name));
        SelectObject(dc, g_graphBold);
        SetTextColor(dc, fg);
        SIZE vs; GetTextExtentPoint32W(dc, val, lstrlenW(val), &vs);
        TextOutW(dc, pad + gw - vs.cx, y0, val, lstrlenW(val));
        for (int x = 0; x < gw; x++) {
            px[(gy + gh - 1) * W + pad + x] = (DWORD)(GetRValue(grid) << 16 | GetGValue(grid) << 8 | GetBValue(grid));
            if (x % 6 < 3) px[(gy + gh / 2) * W + pad + x] = px[(gy + gh - 1) * W + pad + x];
        }
        int cnt = g_hcount;
        for (int i = 0; i < cnt; i++) {
            int idx = (g_hpos + HIST - cnt + i) % HIST;
            if (g_histOk[sr[k].m][idx] && g_hist[sr[k].m][idx] > mx) mx = g_hist[sr[k].m][idx];
        }
        double lo = 0, hi = sr[k].kind == K_PCT ? 100 : sr[k].kind == K_TEMP ? (mx > 100 ? mx : 100) : (mx > 0 ? mx * 1.15 : 1);
        int np = 0;
        for (int i = 0; i < cnt; i++) {
            int idx = (g_hpos + HIST - cnt + i) % HIST;
            if (!g_histOk[sr[k].m][idx]) continue;
            double v = g_hist[sr[k].m][idx];
            if (v < lo) v = lo;
            if (v > hi) v = hi;
            pts[np].x = (LONG)((double)(HIST - cnt + i) * (gw - 1) / (HIST - 1) * SS);
            pts[np].y = (LONG)((gh - 2) * (1.0 - (v - lo) / (hi - lo)) * SS) + SS;
            np++;
        }
        if (np >= 2) {
            pts[np].x = pts[np - 1].x; pts[np].y = gh * SS;
            pts[np + 1].x = pts[0].x;  pts[np + 1].y = gh * SS;
            coverage(gw, gh, 0, pts, np + 2, 0, cov);
            blend(px, W, H, pad, gy, cov, gw, gh, sr[k].col, 60);
            coverage(gw, gh, 1, pts, np, SC(2) * SS * 3 / 4, cov);
            blend(px, W, H, pad, gy, cov, gw, gh, sr[k].col, 255);
        }
    }
    GdiFlush();
    coverage(W, H, 2, NULL, 0, SC(16) * SS, cov);
    for (int i = 0; i < W * H; i++) {
        DWORD a = cov[i], c = px[i];
        px[i] = a << 24 | (((c >> 16) & 0xFF) * a / 255) << 16 | (((c >> 8) & 0xFF) * a / 255) << 8 | ((c & 0xFF) * a / 255);
    }

    RECT gr = b->grc[0], tr, mr;
    for (int i = 0; i < b->ngrp; i++) if (b->gid[i] == g_graphGid) gr = b->grc[i];
    MapWindowPoints(b->wnd, NULL, (POINT *)&gr, 2);
    GetWindowRect(b->tb, &tr);
    MONITORINFO mi = { sizeof mi };
    GetMonitorInfoW(MonitorFromWindow(b->tb, MONITOR_DEFAULTTONEAREST), &mi);
    mr = mi.rcMonitor;
    int x, y, gap = SC(8);
    if (b->vert) {
        y = (gr.top + gr.bottom) / 2 - H / 2;
        x = tr.left > (mr.left + mr.right) / 2 ? tr.left - W - gap : tr.right + gap;
    } else {
        x = (gr.left + gr.right) / 2 - W / 2;
        y = tr.top > (mr.top + mr.bottom) / 2 ? tr.top - H - gap : tr.bottom + gap;
    }
    if (x < mr.left + gap) x = mr.left + gap;
    if (x + W > mr.right - gap) x = mr.right - gap - W;
    if (y < mr.top + gap) y = mr.top + gap;
    if (y + H > mr.bottom - gap) y = mr.bottom - gap - H;
    POINT src = { 0, 0 }, dst = { x, y };
    SIZE sz = { W, H };
    BLENDFUNCTION bf = { AC_SRC_OVER, 0, 255, AC_SRC_ALPHA };
    UpdateLayeredWindow(g_graph, NULL, &dst, &sz, dc, &src, 0, &bf, ULW_ALPHA);
    SetWindowPos(g_graph, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE | SWP_SHOWWINDOW);
    SelectObject(dc, ob);
done:
    if (bm) DeleteObject(bm);
    if (cov) HeapFree(GetProcessHeap(), 0, cov);
    if (pts) HeapFree(GetProcessHeap(), 0, pts);
    DeleteDC(dc);
}

static void graph_hover(HWND w, int x, int y)
{
    BAR *b = NULL;
    int gid = -1;
    for (int i = 0; i < MAX_BARS; i++) if (g_bars[i].wnd == w) b = &g_bars[i];
    if (!b) return;
    POINT pt = { x, y };
    for (int i = 0; i < b->ngrp; i++) if (PtInRect(&b->grc[i], pt)) gid = b->gid[i];
    if (gid < 0) { graph_hide(); return; }
    if (b == g_graphBar && gid == g_graphGid) return;
    g_graphBar = b;
    g_graphGid = gid;
    graph_draw();
}

static int wanted(HWND tb, HWND main, int others)
{
    if (g_where == SHOW_ALL) return 1;
    if (g_where == SHOW_OTHERS && others) return tb != main;
    return tb == main;
}

static void refresh(int force)
{
    HWND tbs[MAX_BARS], main = FindWindowW(L"Shell_TrayWnd", NULL);
    tray_refresh(force);
    if (g_mode != MODE_BAR) { bars_destroy(); return; }
    int n = find_taskbars(tbs, MAX_BARS), others = n > (main != NULL);
    for (int i = 0; i < MAX_BARS; i++) {
        BAR *b = &g_bars[i];
        if (!b->wnd) continue;
        int keep = IsWindow(b->wnd) && IsWindow(b->tb) && wanted(b->tb, main, others);
        for (int k = 0; keep && k < n; k++) if (tbs[k] == b->tb) keep = 2;
        if (keep != 2) bar_destroy(b);
    }
    for (int k = 0; k < n; k++) {
        if (!wanted(tbs[k], main, others)) continue;
        int have = 0, free = -1;
        for (int i = 0; i < MAX_BARS; i++) {
            if (g_bars[i].wnd && g_bars[i].tb == tbs[k]) have = 1;
            else if (!g_bars[i].wnd && free < 0) free = i;
        }
        if (have || free < 0) continue;
        bar = &g_bars[free];
        bar_create(tbs[k], tbs[k] == main);
    }
    for (int i = 0; i < MAX_BARS; i++)
        if (g_bars[i].wnd) { bar = &g_bars[i]; bar_draw(force); }
}

static DWORD WINAPI sampler(void *unused)
{
    (void)unused;
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_BELOW_NORMAL);
    int com = SUCCEEDED(CoInitializeEx(NULL, COINIT_MULTITHREADED));
    typedef BOOL (WINAPI *SWTE)(HANDLE, const LARGE_INTEGER *, LONG, PTIMERAPCROUTINE, LPVOID, void *, ULONG);
    SWTE setTimerEx = (SWTE)(void *)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "SetWaitableTimerEx");
    HANDLE timer = CreateWaitableTimerW(NULL, FALSE, NULL), waits[2] = { g_wake, timer };
    DWORD armed = 0;
    ULONG64 lastScan = 0;
    read_cpu();
    for (;;) {
        if (g_quit) break;
        if (InterlockedExchange(&g_rebuild, 0)) build_query();
        if (!g_paused) {
            sample();
            ULONG64 now = GetTickCount64();
            if (com && g_mode == MODE_BAR && (InterlockedExchange(&g_scanDirty, 0) || now - lastScan >= 15000)) {
                uia_scan();
                lastScan = now;
            }
            PostMessageW(g_wnd, WM_SAMPLED, 0, 0);
        }
        if (g_paused || !timer) {
            if (timer && armed) { CancelWaitableTimer(timer); armed = 0; }
            WaitForSingleObject(g_wake, g_paused ? INFINITE : g_interval);
            continue;
        }
        if (armed != g_interval) {
            LARGE_INTEGER due;
            due.QuadPart = -(LONGLONG)g_interval * 10000;
            if (!setTimerEx || !setTimerEx(timer, &due, (LONG)g_interval, NULL, NULL, NULL, g_interval / 10))
                SetWaitableTimer(timer, &due, (LONG)g_interval, NULL, NULL, FALSE);
            armed = g_interval;
        }
        WaitForMultipleObjects(2, waits, FALSE, INFINITE);
    }
    if (timer) CloseHandle(timer);
    if (g_q) PdhCloseQuery(g_q);
    if (g_uiaAll) IUIAutomationCondition_Release(g_uiaAll);
    if (g_uiaCache) IUIAutomationCacheRequest_Release(g_uiaCache);
    if (g_uia) IUIAutomation_Release(g_uia);
    if (com) CoUninitialize();
    return 0;
}

static void save(void)
{
    RegSetKeyValueW(HKEY_CURRENT_USER, REGKEY, L"Mask3", REG_DWORD, &g_mask, sizeof g_mask);
    RegSetKeyValueW(HKEY_CURRENT_USER, REGKEY, L"Interval", REG_DWORD, &g_interval, sizeof g_interval);
    RegSetKeyValueW(HKEY_CURRENT_USER, REGKEY, L"Mode", REG_DWORD, &g_mode, sizeof g_mode);
    RegSetKeyValueW(HKEY_CURRENT_USER, REGKEY, L"Offset", REG_DWORD, &g_offset, sizeof g_offset);
    RegSetKeyValueW(HKEY_CURRENT_USER, REGKEY, L"ShowOn", REG_DWORD, &g_where, sizeof g_where);
    RegSetKeyValueW(HKEY_CURRENT_USER, REGKEY, L"Position", REG_DWORD, &g_pos, sizeof g_pos);
    RegSetKeyValueW(HKEY_CURRENT_USER, REGKEY, L"Rows", REG_DWORD, &g_rows, sizeof g_rows);
}
static void load(void)
{
    DWORD v, sz = sizeof v;
    if (!RegGetValueW(HKEY_CURRENT_USER, REGKEY, L"Mask3", RRF_RT_REG_DWORD, NULL, &v, &sz) && (v & ((1u << M_N) - 1)))
        g_mask = v & ((1u << M_N) - 1);
    else {
        sz = sizeof v;
        if (!RegGetValueW(HKEY_CURRENT_USER, REGKEY, L"Mask2", RRF_RT_REG_DWORD, NULL, &v, &sz) && (v & ((1u << M_TRAYN) - 1)))
            g_mask = v & ((1u << M_TRAYN) - 1);
    }
    sz = sizeof v;
    if (!RegGetValueW(HKEY_CURRENT_USER, REGKEY, L"Interval", RRF_RT_REG_DWORD, NULL, &v, &sz) && v >= 500 && v <= 60000)
        g_interval = v;
    sz = sizeof v;
    if (!RegGetValueW(HKEY_CURRENT_USER, REGKEY, L"Mode", RRF_RT_REG_DWORD, NULL, &v, &sz) && v <= MODE_TRAY)
        g_mode = v;
    sz = sizeof v;
    if (!RegGetValueW(HKEY_CURRENT_USER, REGKEY, L"Offset", RRF_RT_REG_DWORD, NULL, &v, &sz))
        g_offset = (LONG)v;
    sz = sizeof v;
    if (!RegGetValueW(HKEY_CURRENT_USER, REGKEY, L"ShowOn", RRF_RT_REG_DWORD, NULL, &v, &sz) && v <= SHOW_OTHERS)
        g_where = v;
    sz = sizeof v;
    if (!RegGetValueW(HKEY_CURRENT_USER, REGKEY, L"Position", RRF_RT_REG_DWORD, NULL, &v, &sz) && v <= POS_LEFT)
        g_pos = v;
    sz = sizeof v;
    if (!RegGetValueW(HKEY_CURRENT_USER, REGKEY, L"Rows", RRF_RT_REG_DWORD, NULL, &v, &sz) && v <= ROWS_TWO)
        g_rows = v;
}
static int is_admin(void);

static int is_admin(void)
{
    BOOL a = FALSE; PSID g;
    SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&nt, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &g)) {
        CheckTokenMembership(NULL, g, &a);
        FreeSid(g);
    }
    return a;
}
static DWORD reg_dword(const wchar_t *name)
{
    DWORD v = 0, sz = sizeof v;
    RegGetValueW(HKEY_CURRENT_USER, REGKEY, name, RRF_RT_REG_DWORD, NULL, &v, &sz);
    return v;
}
static void schtasks(const wchar_t *args)
{
    wchar_t app[MAX_PATH], cmd[MAX_PATH * 2 + 64];
    if (!sys_path(app, L"schtasks.exe")) return;
    _snwprintf(cmd, MAX_PATH * 2 + 64, L"\"%s\" %s", app, args); cmd[MAX_PATH * 2 + 63] = 0;
    STARTUPINFOW si; PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof si); si.cb = sizeof si;
    if (CreateProcessW(app, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, 10000);
        CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    }
}
static void task_create(const wchar_t *exe);
static void task_remove_copy(void);
static void relaunch_admin(const wchar_t *args);
static int autostart_on(void)
{
    return reg_dword(L"Task") ||
           RegGetValueW(HKEY_CURRENT_USER, RUNKEY, APP, RRF_RT_REG_SZ, NULL, NULL, NULL) == ERROR_SUCCESS;
}
static void autostart_toggle(void)
{
    wchar_t exe[MAX_PATH], cmd[MAX_PATH * 2 + 128];
    DWORD n = GetModuleFileNameW(NULL, exe, MAX_PATH), zero = 0;
    if (!n || n >= MAX_PATH) return;
    if (autostart_on()) {
        if (reg_dword(L"Task") && !is_admin()) {
            if (MessageBoxW(g_wnd, L"TraySense khởi động với quyền quản trị viên khi đăng nhập. Việc tắt tùy chọn này cần "
                                   L"quyền quản trị viên.\n\nKhởi động lại TraySense với quyền quản trị viên?", APP, MB_YESNO | MB_ICONQUESTION) == IDYES)
                relaunch_admin(L"/restart");
            return;
        }
        RegDeleteKeyValueW(HKEY_CURRENT_USER, RUNKEY, APP);
        if (reg_dword(L"Task")) {
            schtasks(L"/Delete /F /TN TraySense");
            task_remove_copy();
            RegSetKeyValueW(HKEY_CURRENT_USER, REGKEY, L"Task", REG_DWORD, &zero, sizeof zero);
        }
        return;
    }
    if (!is_admin()) {
        _snwprintf(cmd, MAX_PATH + 4, L"\"%s\"", exe); cmd[MAX_PATH + 3] = 0;
        RegSetKeyValueW(HKEY_CURRENT_USER, RUNKEY, APP, REG_SZ, cmd, (lstrlenW(cmd) + 1) * sizeof(wchar_t));
        return;
    }
    task_create(exe);
}

static void xml_escape(wchar_t *out, int n, const wchar_t *in)
{
    int o = 0;
    for (; *in && o < n - 7; in++) {
        const wchar_t *r = *in == L'&' ? L"&amp;" : *in == L'<' ? L"&lt;" : *in == L'>' ? L"&gt;" : NULL;
        if (r) { lstrcpyW(out + o, r); o += lstrlenW(r); }
        else out[o++] = *in;
    }
    out[o] = 0;
}

static int user_sid(wchar_t *out, int n)
{
    HANDLE t; BYTE b[256]; DWORD got; LPWSTR str; int ok = 0;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &t)) return 0;
    if (GetTokenInformation(t, TokenUser, b, sizeof b, &got) && ConvertSidToStringSidW(((TOKEN_USER *)b)->User.Sid, &str)) {
        lstrcpynW(out, str, n);
        LocalFree(str);
        ok = 1;
    }
    CloseHandle(t);
    return ok;
}

static void task_remove_copy(void)
{
    wchar_t dir[MAX_PATH], dst[MAX_PATH], self[MAX_PATH];
    if (!is_admin() || !app_dir(dir)) return;
    _snwprintf(dst, MAX_PATH, L"%s\\TraySense.exe", dir); dst[MAX_PATH - 1] = 0;
    GetModuleFileNameW(NULL, self, MAX_PATH);
    if (!lstrcmpiW(self, dst) || !DeleteFileW(dst)) {
        MoveFileExW(dst, NULL, MOVEFILE_DELAY_UNTIL_REBOOT);
        MoveFileExW(dir, NULL, MOVEFILE_DELAY_UNTIL_REBOOT);
    } else RemoveDirectoryW(dir);
}

static void task_create(const wchar_t *exe)
{
    wchar_t dir[MAX_PATH], dst[MAX_PATH], xmlPath[MAX_PATH], sid[184], esc[MAX_PATH * 5], xml[3072], args[MAX_PATH + 48];
    DWORD one = 1, w;
    if (!app_dir(dir) || !user_sid(sid, 184)) return;
    _snwprintf(dst, MAX_PATH, L"%s\\TraySense.exe", dir); dst[MAX_PATH - 1] = 0;
    if (lstrcmpiW(exe, dst) && !copy_self(dst)) return;
    xml_escape(esc, MAX_PATH * 5, dst);
    _snwprintf(xmlPath, MAX_PATH, L"%s\\task.xml", dir); xmlPath[MAX_PATH - 1] = 0;
    _snwprintf(xml, 3072,
        L"\xFEFF<?xml version=\"1.0\" encoding=\"UTF-16\"?>\r\n"
        L"<Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">"
        L"<Triggers><LogonTrigger><Enabled>true</Enabled><UserId>%s</UserId></LogonTrigger></Triggers>"
        L"<Principals><Principal id=\"Author\"><UserId>%s</UserId><LogonType>InteractiveToken</LogonType>"
        L"<RunLevel>HighestAvailable</RunLevel></Principal></Principals>"
        L"<Settings><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>"
        L"<StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><ExecutionTimeLimit>PT0S</ExecutionTimeLimit>"
        L"<MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><Priority>5</Priority></Settings>"
        L"<Actions Context=\"Author\"><Exec><Command>%s</Command></Exec></Actions></Task>", sid, sid, esc);
    xml[3071] = 0;
    HANDLE f = CreateFileW(xmlPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    if (f == INVALID_HANDLE_VALUE) return;
    WriteFile(f, xml, lstrlenW(xml) * sizeof(wchar_t), &w, NULL);
    CloseHandle(f);
    _snwprintf(args, MAX_PATH + 48, L"/Create /F /TN TraySense /XML \"%s\"", xmlPath); args[MAX_PATH + 47] = 0;
    schtasks(args);
    DeleteFileW(xmlPath);
    RegDeleteKeyValueW(HKEY_CURRENT_USER, RUNKEY, APP);
    RegSetKeyValueW(HKEY_CURRENT_USER, REGKEY, L"Task", REG_DWORD, &one, sizeof one);
}

static void autostart_migrate(void)
{
    wchar_t exe[MAX_PATH];
    if (!is_admin() || reg_dword(L"Task") ||
        RegGetValueW(HKEY_CURRENT_USER, RUNKEY, APP, RRF_RT_REG_SZ, NULL, NULL, NULL) != ERROR_SUCCESS) return;
    DWORD n = GetModuleFileNameW(NULL, exe, MAX_PATH);
    if (n && n < MAX_PATH) task_create(exe);
}

static void relaunch_admin(const wchar_t *args)
{
    wchar_t exe[MAX_PATH];
    GetModuleFileNameW(NULL, exe, MAX_PATH);
    SHELLEXECUTEINFOW e; ZeroMemory(&e, sizeof e);
    e.cbSize = sizeof e; e.lpVerb = L"runas"; e.lpFile = exe; e.lpParameters = args; e.nShow = SW_SHOWNORMAL;
    if (ShellExecuteExW(&e)) DestroyWindow(g_wnd);
}

static void cpu_temp_setup(int ask)
{
    DWORD one = 1;
    if (ask) {
        if (reg_dword(L"AskedCpuTemp")) return;
        RegSetKeyValueW(HKEY_CURRENT_USER, REGKEY, L"AskedCpuTemp", REG_DWORD, &one, sizeof one);
    }
    pio_init();
    InterlockedExchange(&g_rebuild, 1);
    SetEvent(g_wake);
    switch (g_pioState) {
    case PIO_OK:
        if (!ask) MessageBoxW(g_wnd, L"Đã bật nhiệt độ CPU.", APP, MB_ICONINFORMATION);
        return;
    case PIO_UNSUPPORTED:
    case PIO_FAILED:
    case PIO_NOMODULE:
        if (!ask) MessageBoxW(g_wnd, L"Bộ xử lý này không hỗ trợ nhiệt độ CPU "
                                     L"(hỗ trợ Intel Core hoặc AMD Ryzen / EPYC).", APP, MB_ICONINFORMATION);
        return;
    case PIO_NOADMIN:
        if (MessageBoxW(g_wnd, L"Đọc cảm biến nhiệt độ CPU cần quyền quản trị viên.\n\n"
                               L"Khởi động lại TraySense với quyền quản trị viên? Từ giờ chương trình sẽ tự khởi động theo cách này.",
                        APP, MB_YESNO | MB_ICONQUESTION) == IDYES)
            relaunch_admin(L"/restart");
        return;
    default:
        if (MessageBoxW(g_wnd, L"Hiển thị nhiệt độ CPU?\n\n"
                               L"Windows không cho ứng dụng tự đọc cảm biến nhiệt độ của CPU, vì vậy TraySense "
                               L"sẽ cài PawnIO: một trình điều khiển mã nguồn mở, nhỏ gọn và đã ký số (được LibreHardwareMonitor sử dụng). "
                               L"Trình điều khiển được xác minh trước khi chạy và có thể gỡ bất kỳ lúc nào trong Cài đặt > Ứng dụng.\n\n"
                               L"Windows sẽ yêu cầu cấp quyền.",
                        APP L" \x2013 Nhiệt độ CPU", MB_YESNO | MB_ICONQUESTION) == IDYES)
            relaunch_admin(L"/restart /install-pawnio");
    }
}

static void menu(void)
{
    static const DWORD iv[3] = { 1000, 2000, 5000 };
    HMENU h = CreatePopupMenu(), sub = CreatePopupMenu();
    for (int m = 0; m < M_N; m++) {
        wchar_t lbl[80];
        lstrcpyW(lbl, NAMES[m]);
        if (m >= M_TRAYN && g_mode == MODE_TRAY) continue;
        if (m == M_CPUT && g_pioState == PIO_OK) lstrcatW(lbl, L"  (cảm biến CPU)");
        else if (m == M_CPUW && g_pioState != PIO_OK) lstrcatW(lbl, L"  (cần cảm biến CPU)");
        else if (m == M_GPUW && !pNvPower && !pNvEnergy && !pNvFields && !pAdlPMLog && !g_kmtPower) {
            lstrcatW(lbl, L"  (GPU này không hỗ trợ)");
            AppendMenuW(h, MF_STRING | MF_GRAYED, 100 + m, lbl);
            continue;
        }
        else if ((m == M_CPUT || m == M_GPUT || m == M_DISKT) && (g_mask >> m & 1) && !g_ok[m]) lstrcatW(lbl, L"  (không tìm thấy cảm biến)");
        AppendMenuW(h, MF_STRING | ((g_mask >> m & 1) ? MF_CHECKED : 0), 100 + m, lbl);
    }
    if (g_stRunning) AppendMenuW(h, MF_STRING | MF_GRAYED, 370, L"Đang kiểm tra tốc độ...");
    else if (g_stDown > 0) {
        wchar_t st[96], a[32], b[32];
        fmt_speed(a, 32, g_stDown);
        fmt_speed(b, 32, g_stUp);
        _snwprintf(st, 96, L"Kiểm tra tốc độ  (lần trước: \x2193%s  \x2191%s)", a, b);
        st[95] = 0;
        AppendMenuW(h, MF_STRING, 370, st);
    } else AppendMenuW(h, MF_STRING, 370, L"Kiểm tra tốc độ");
    if (g_pioState != PIO_OK && g_pioState != PIO_UNSUPPORTED) AppendMenuW(h, MF_STRING, 320, L"Bật nhiệt độ CPU...");
    AppendMenuW(h, MF_SEPARATOR, 0, NULL);
    AppendMenuW(h, MF_STRING | (g_mode == MODE_BAR ? MF_CHECKED : 0), 310, L"Nhãn lớn trên thanh tác vụ");
    if (g_mode == MODE_BAR) {
        HMENU on = CreatePopupMenu();
        AppendMenuW(on, MF_STRING | (g_where == SHOW_MAIN ? MF_CHECKED : 0), 330, L"Thanh tác vụ chính");
        AppendMenuW(on, MF_STRING | (g_where == SHOW_ALL ? MF_CHECKED : 0), 331, L"Tất cả thanh tác vụ");
        AppendMenuW(on, MF_STRING | (g_where == SHOW_OTHERS ? MF_CHECKED : 0), 332, L"Chỉ màn hình khác");
        AppendMenuW(h, MF_POPUP, (UINT_PTR)on, L"Hiển thị trên");
        HMENU ps = CreatePopupMenu(), rw = CreatePopupMenu();
        AppendMenuW(ps, MF_STRING | (g_pos == POS_TRAY ? MF_CHECKED : 0), 340, L"Cạnh khay hệ thống");
        AppendMenuW(ps, MF_STRING | (g_pos == POS_APPS ? MF_CHECKED : 0), 341, L"Sau ứng dụng");
        AppendMenuW(ps, MF_STRING | (g_pos == POS_LEFT ? MF_CHECKED : 0), 342, L"Bên trái");
        AppendMenuW(h, MF_POPUP, (UINT_PTR)ps, L"Vị trí");
        AppendMenuW(rw, MF_STRING | (g_rows == ROWS_AUTO ? MF_CHECKED : 0), 350, L"Tự động");
        AppendMenuW(rw, MF_STRING | (g_rows == ROWS_ONE ? MF_CHECKED : 0), 351, L"Một hàng");
        AppendMenuW(rw, MF_STRING | (g_rows == ROWS_TWO ? MF_CHECKED : 0), 352, L"Hai hàng");
        AppendMenuW(h, MF_POPUP, (UINT_PTR)rw, L"Bố cục");

        int anyVert = 0;
        for (int i = 0; i < MAX_BARS; i++) if (g_bars[i].wnd && g_bars[i].vert) anyVert = 1;
        AppendMenuW(h, MF_STRING, 311, anyVert ? L"Di chuyển lên" : L"Di chuyển sang trái");
        AppendMenuW(h, MF_STRING, 312, anyVert ? L"Di chuyển xuống" : L"Di chuyển sang phải");
        AppendMenuW(h, MF_STRING, 313, L"Đặt lại vị trí");
    }
    AppendMenuW(sub, MF_STRING | (g_interval == 1000 ? MF_CHECKED : 0), 200, L"1 giây");
    AppendMenuW(sub, MF_STRING | (g_interval == 2000 ? MF_CHECKED : 0), 201, L"2 giây");
    AppendMenuW(sub, MF_STRING | (g_interval == 5000 ? MF_CHECKED : 0), 202, L"5 giây (tiết kiệm điện nhất)");
    AppendMenuW(h, MF_POPUP, (UINT_PTR)sub, L"Tần suất làm mới");
    AppendMenuW(h, MF_STRING | (autostart_on() ? MF_CHECKED : 0), 300, L"Khởi động cùng Windows");
    AppendMenuW(h, MF_SEPARATOR, 0, NULL);
    AppendMenuW(h, MF_STRING, 399, L"Thoát");

    POINT pt; GetCursorPos(&pt);
    SetForegroundWindow(g_wnd);
    int cmd = TrackPopupMenu(h, TPM_RIGHTBUTTON | TPM_RETURNCMD | TPM_NONOTIFY, pt.x, pt.y, 0, g_wnd, NULL);
    PostMessageW(g_wnd, WM_NULL, 0, 0);
    DestroyMenu(h);

    if (cmd >= 100 && cmd < 100 + M_N) {
        DWORD nm = g_mask ^ (1u << (cmd - 100));
        if (!nm) return;
        g_mask = nm;
        if (cmd - 100 == M_CPUW && (nm >> M_CPUW & 1) && g_pioState != PIO_OK) cpu_temp_setup(0);
        InterlockedExchange(&g_rebuild, 1);
        SetEvent(g_wake);
        refresh(1);
        save();
    } else if (cmd >= 200 && cmd <= 202) {
        g_interval = iv[cmd - 200];
        SetEvent(g_wake);
        save();
    } else if (cmd == 300) autostart_toggle();
    else if (cmd == 310) { g_mode = g_mode == MODE_BAR ? MODE_TRAY : MODE_BAR; refresh(1); save(); }
    else if (cmd >= 311 && cmd <= 313) {
        g_offset = cmd == 313 ? 0 : g_offset + (cmd == 311 ? -10 : 10);
        for (int i = 0; i < MAX_BARS; i++)
            if (g_bars[i].wnd) {
                bar = &g_bars[i];
                ZeroMemory(&bar->lastPos, sizeof bar->lastPos);
                bar_place();
            }
        save();
    }
    else if (cmd >= 330 && cmd <= 332) { g_where = cmd - 330; refresh(1); save(); }
    else if (cmd >= 340 && cmd <= 342) { g_pos = cmd - 340; g_offset = 0; refresh(1); save(); }
    else if (cmd >= 350 && cmd <= 352) { g_rows = cmd - 350; refresh(1); save(); }
    else if (cmd == 370) speed_test();
    else if (cmd == 320) cpu_temp_setup(0);
    else if (cmd == 399) DestroyWindow(g_wnd);
}

static LRESULT CALLBACK barproc(HWND w, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg) {
    case WM_MOUSEACTIVATE: return MA_NOACTIVATE;
    case WM_MOUSEMOVE: {
        TRACKMOUSEEVENT t = { sizeof t, TME_LEAVE, w, 0 };
        TrackMouseEvent(&t);
        graph_hover(w, (short)LOWORD(lp), (short)HIWORD(lp));
        return 0;
    }
    case WM_MOUSELEAVE:    graph_hide(); return 0;
    case WM_RBUTTONUP:     graph_hide(); menu(); return 0;
    case WM_LBUTTONUP: {
        wchar_t tm[MAX_PATH];
        if (sys_path(tm, L"taskmgr.exe")) ShellExecuteW(NULL, L"open", tm, NULL, NULL, SW_SHOWNORMAL);
        return 0;
    }
    case WM_NCDESTROY:
        for (int i = 0; i < MAX_BARS; i++) if (g_bars[i].wnd == w) {
            if (g_graphBar == &g_bars[i]) graph_hide();
            g_bars[i].wnd = NULL;
        }
        break;
    }
    return DefWindowProcW(w, msg, wp, lp);
}

static void CALLBACK on_window_event(HWINEVENTHOOK hook, DWORD ev, HWND hwnd, LONG obj, LONG child, DWORD thread, DWORD time)
{
    (void)hook; (void)ev; (void)thread; (void)time;
    if (obj != OBJID_WINDOW || child != CHILDID_SELF || !hwnd || GetAncestor(hwnd, GA_ROOT) != hwnd) return;
    LONG_PTR ex = GetWindowLongPtrW(hwnd, GWL_EXSTYLE);
    if ((ex & WS_EX_APPWINDOW) || (!(ex & WS_EX_TOOLWINDOW) && !GetWindow(hwnd, GW_OWNER)))
        InterlockedExchange(&g_scanDirty, 1);
}

static LRESULT CALLBACK wndproc(HWND w, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg) {
    case WM_SAMPLED:
        hist_push();
        refresh(0);
        if (g_graphBar) graph_draw();
        return 0;
    case WM_SPEEDDONE:
        g_stRunning = 0;
        g_stFailed = !wp;
        g_stShowUntil = GetTickCount64() + (wp ? 60000 : 10000);
        refresh(0);
        return 0;
    case WM_TRAY:
        if (lp == WM_RBUTTONUP || lp == WM_LBUTTONUP || lp == WM_CONTEXTMENU) menu();
        return 0;
    case WM_SETTINGCHANGE:
    case WM_DISPLAYCHANGE:
    case WM_DPICHANGED:
        read_env(); refresh(1);
        return 0;
    case WM_POWERBROADCAST:
        if (wp == PBT_POWERSETTINGCHANGE) {
            POWERBROADCAST_SETTING *ps = (POWERBROADCAST_SETTING *)lp;
            if (IsEqualGUID(&ps->PowerSetting, &G_DISPLAY)) {
                g_paused = *(DWORD *)ps->Data == 0;
                SetEvent(g_wake);
            }
        }
        return TRUE;
    case WM_DESTROY:
        for (int m = 0; m < M_N; m++) if (g_shown[m]) tray(m, NIM_DELETE);
        bars_destroy();
        PostQuitMessage(0);
        return 0;
    }
    if (msg == g_msgQuit && msg) {
        DestroyWindow(w);
        return 0;
    }
    if (msg == g_taskbarCreated && msg) {
        for (int m = 0; m < M_N; m++) g_shown[m] = 0;
        bars_destroy();
        refresh(1);
        return 0;
    }
    return DefWindowProcW(w, msg, wp, lp);
}

int WINAPI WinMain(HINSTANCE hi, HINSTANCE prev, LPSTR cmd, int show)
{
    (void)prev; (void)cmd; (void)show;
    {
        typedef BOOL (WINAPI *SDDD)(DWORD);
        SDDD f = (SDDD)(void *)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "SetDefaultDllDirectories");
        if (f) f(LOAD_LIBRARY_SEARCH_SYSTEM32);
        SetDllDirectoryW(L"");
    }
    if (is_admin()) lock_self();
    int restart = wcsstr(GetCommandLineW(), L"/restart") != NULL;
    g_msgQuit = RegisterWindowMessageW(L"TraySense.Quit");
    for (int tries = 0;; tries++) {
        HANDLE mx = CreateMutexW(NULL, TRUE, L"Local\\TraySense.single");
        if (GetLastError() != ERROR_ALREADY_EXISTS) break;
        CloseHandle(mx);
        if (tries == 0 && !restart) {
            HWND old = FindWindowW(APP, APP);
            if (old) PostMessageW(old, g_msgQuit, 0, 0);
        }
        if (tries > 40) {
            if (!restart)
                MessageBoxW(NULL, L"TraySense đang chạy.\n\nNhấp chuột phải vào ứng dụng trên thanh tác vụ và chọn Thoát, "
                                  L"sau đó mở lại ứng dụng này.", APP, MB_ICONINFORMATION);
            return 0;
        }
        Sleep(150);
    }

    SetProcessDPIAware();
    {
        typedef BOOL (WINAPI *SPI)(HANDLE, int, void *, DWORD);
        SPI spi = (SPI)(void *)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "SetProcessInformation");
        struct { ULONG Version, ControlMask, StateMask; } pt = { 1, 1, 1 };
        if (spi) spi(GetCurrentProcess(), 4 , &pt, sizeof pt);
    }

    InitializeCriticalSection(&g_pioCs);
    InitializeCriticalSection(&g_scanCs);
    load();
    read_env();
    init_gpu();
    init_disk();
    if (wcsstr(GetCommandLineW(), L"/install-pawnio") && is_admin()) {
        HANDLE probe = CreateFileW(L"\\\\?\\GLOBALROOT\\Device\\PawnIO", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                   NULL, OPEN_EXISTING, 0, NULL);
        if (probe != INVALID_HANDLE_VALUE) CloseHandle(probe);
        else {
            const wchar_t *why = L"";
            if (!pawnio_install(&why)) MessageBoxW(NULL, why, APP L" \x2013 CPU temperature", MB_ICONWARNING);
        }
    }
    pio_init();
    autostart_migrate();

    WNDCLASSW wc; ZeroMemory(&wc, sizeof wc);
    wc.lpfnWndProc = wndproc; wc.hInstance = hi; wc.lpszClassName = APP;
    RegisterClassW(&wc);
    wc.lpfnWndProc = DefWindowProcW; wc.lpszClassName = L"TraySenseGraph";
    RegisterClassW(&wc);
    wc.lpfnWndProc = barproc; wc.lpszClassName = L"TraySenseBar";
    wc.hCursor = LoadCursorW(NULL, (LPCWSTR)IDC_ARROW);
    RegisterClassW(&wc);
    g_wnd = CreateWindowExW(WS_EX_TOOLWINDOW, APP, APP, WS_POPUP, 0, 0, 0, 0, NULL, NULL, hi, NULL);
    g_taskbarCreated = RegisterWindowMessageW(L"TaskbarCreated");
    g_graph = CreateWindowExW(WS_EX_LAYERED | WS_EX_TOOLWINDOW | WS_EX_TOPMOST | WS_EX_NOACTIVATE | WS_EX_TRANSPARENT,
                              L"TraySenseGraph", L"", WS_POPUP, 0, 0, 1, 1, NULL, NULL, hi, NULL);
    {
        typedef BOOL (WINAPI *CWMF)(HWND, UINT, DWORD, void *);
        CWMF f = (CWMF)(void *)GetProcAddress(GetModuleHandleW(L"user32.dll"), "ChangeWindowMessageFilterEx");
        if (f) { f(g_wnd, g_taskbarCreated, 1, NULL); f(g_wnd, WM_TRAY, 1, NULL); f(g_wnd, g_msgQuit, 1, NULL); }
    }
    RegisterPowerSettingNotification(g_wnd, &G_DISPLAY, DEVICE_NOTIFY_WINDOW_HANDLE);
    SetWinEventHook(EVENT_OBJECT_SHOW, EVENT_OBJECT_HIDE, NULL, on_window_event, 0, 0,
                    WINEVENT_OUTOFCONTEXT | WINEVENT_SKIPOWNPROCESS);

    g_wake = CreateEventW(NULL, FALSE, FALSE, NULL);
    HANDLE th = CreateThread(NULL, 64 * 1024, sampler, NULL, STACK_SIZE_PARAM_IS_A_RESERVATION, NULL);
    refresh(1);

    MSG m;
    int trimmed = 0;
    while (GetMessageW(&m, NULL, 0, 0) > 0) {
        DispatchMessageW(&m);
        if (!trimmed && m.message == WM_SAMPLED) {
            trimmed = 1;
            if ((g_mask & (1u << M_CPUT)) && g_pioState != PIO_OK && g_pioState != PIO_UNSUPPORTED && !g_ok[M_CPUT])
                cpu_temp_setup(1);
            SetProcessWorkingSetSize(GetCurrentProcess(), (SIZE_T)-1, (SIZE_T)-1);
        }
    }
    g_quit = 1;
    SetEvent(g_wake);
    if (th) WaitForSingleObject(th, 2000);
    reset_fonts();
    return 0;
}
