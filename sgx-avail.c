#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

/*
 * This program checks SGX availability by checking CPUID
 * Relevant spec sections: 1.7 (and 1.7.1 and 1.7.2)
 * 2015-08-14 Nico Weichbrodt
 */

/*
 * Helper function for CPUID querying
 */
void cpuid(unsigned int eax, unsigned int ecx, unsigned int *eax_out, unsigned int *ebx_out, unsigned int *ecx_out, unsigned int *edx_out)
{
    asm("pushq %%rbx\n\t"
        "cpuid\n\t"
        "movl %%ebx,%1\n\t"
        "popq %%rbx\n\t"
        : "=a"(*eax_out), "=r"(*ebx_out), "=c"(*ecx_out), "=d"(*edx_out)
        : "a"(eax), "c"(ecx));
    //printf("EAX: %x\nEBX: %x\nECX: %x\nEDX: %x\n", eax, ebx, ecx, edx);
}

typedef struct
{
    unsigned int stepping:4;
    unsigned int model:4;
    unsigned int family:4;
    unsigned int type:2;
    int reserved_14:2;
    unsigned int ext_model:4;
    unsigned int ext_family:8;

} sgx_cap_1_0_eax_t;

/**
 * EAX 0x07 EXC 0x00
 */
typedef struct
{
    int fsgsbase:1;
    int reserved1:1;
    int sgx:1;
    int bmi1:1;
    int hle:1;
    int avx2:1;
    int reserved6:1;
    int smep:1;
    int bmi2:1;
    int erms:1;
    int invpcid:1;
    int rtm:1;
    int reserved12:1;
    int reserved13:1;
    int mpx:1;
    int reserved15:1;
    int avx512f:1;
    int avx512dq:1;
    int rdseed:1;
    int adx:1;
    int smap:1;
    int avx512ifma:1;
    int pcommit:1;
    int clflushopt:1;
    int clwb:1;
    int intel_processor_trace:1;
    int avx512pf:1;
    int avx512er:1;
    int avx512cd:1;
    int sha:1;
    int avx512bw:1;
    int avx512vl:1;
} sgx_cap_7_0_ebx_t;

/**
 * EAX 0x12 EXC 0x00
 */
typedef struct
{
    int sgxv1:1;
    int sgxv2:1;
    int reserved:30;
} sgx_cap_12_0__eax_t;

typedef struct
{
    int miscselect:32;
} sgx_cap_12_0__ebx_t;

typedef struct
{
    int reserved:32;
} sgx_cap_12_0__ecx_t;

typedef struct
{
    int max_enclave_size_32:8;
    int max_enclave_size_64:8;
    int reserved:16;
} sgx_cap_12_0__edx_t;

/**
 * EAX 0x12 ECX 0x01
 */
typedef struct {
    int secs_attr:32;
} sgx_cap_12_1__eax_t;

typedef struct {
    int secs_attr:32;
} sgx_cap_12_1__ebx_t;

typedef struct {
    int secs_attr:32;
} sgx_cap_12_1__ecx_t;

typedef struct {
    int secs_attr:32;
} sgx_cap_12_1__edx_t;

/**
 * EAX 0x12 ECX 0x02
 */
typedef struct {
    int epc_info_avail:4;
    int reserved:8;
    int epc_phys_base_bits_12_to_31:20;
} sgx_cap_12_2__eax_t;

typedef struct {
    int epc_phys_base_bits_31_to_51:20;
    int reserved:12;
} sgx_cap_12_2__ebx_t;

typedef struct {
    int epc_sec_avail:4;
    int reserved:8;
    int epc_prm_size_bits_12_to_31:20;
} sgx_cap_12_2__ecx_t;

typedef struct {
    int epc_prm_size_bits_31_to_51:20;
    int reserved:12;
} sgx_cap_12_2__edx_t;

char *RED = "\x1b[31m";
char *GREEN = "\x1b[32m";
char *YELLOW = "\x1b[33m";
char *NORMAL = "\x1b[0m";

void print_brand_string()
{
    char eax[4], ebx[4], ecx[4], edx[4];
    for (unsigned int i = 0; i < 3; i++)
    {
        cpuid(0x80000002+i, 0x00, (unsigned int *) eax, (unsigned int *) ebx, (unsigned int *) ecx, (unsigned int *) edx);
        for (int a = 0; a < 4; a++)
        {
            printf("%c", eax[a]);
        }
        for (int a = 0; a < 4; a++)
        {
            printf("%c", ebx[a]);
        }
        for (int a = 0; a < 4; a++)
        {
            printf("%c", ecx[a]);
        }
        for (int a = 0; a < 4; a++)
        {
            printf("%c", edx[a]);
        }
         //*/
    }
}

void general_cpu_info()
{
    printf("=====\nGeneral CPU information\n-----\n");
    unsigned int eax, ebx, ecx, edx;

    print_brand_string();
    printf("\n");

    cpuid(0x00, 0x00, &eax, &ebx, &ecx, &edx);
    char vendor[13];
    memcpy(vendor+0, &ebx, 4);
    memcpy(vendor+4, &edx, 4);
    memcpy(vendor+8, &ecx, 4);
    vendor[12] = '\0';
    printf("Vendor: %s\n", vendor);
    unsigned int max = eax;
    printf("CPUID level: %1$u (0x%1$x)\n", max);
    if (max < 0x07)
    {
        printf("Something is wrong, can't check for extended features! (max function number < 0x07");
        exit(0);
    }
    cpuid(0x01, 0x00, &eax, &ebx, &ecx, &edx);
    sgx_cap_1_0_eax_t *info = (sgx_cap_1_0_eax_t *)&eax;
    printf("Stepping: %1$u (0x%1$x)\n", info->stepping);

    if (info->family == 0x06)
    {
        printf("Family: %1$u (0x%1$x)\n", info->family);
        printf("Model: %1$u (0x%1$x)\n", info->model + (info->ext_model << 4));
    }
    else if (info->family == 0x0F){
        printf("Family: %1$u (0x%1$x)\n", info->family + info->ext_family);
        printf("Model: %1$u (0x%1$x)\n", info->model + (info->ext_model << 4));
    }
    else
    {
        printf("Family: %1$u (0x%1$x)\n", info->family);
        printf("Model: %1$u (0x%1$x)\n", info->model);
    }

    printf("Type: %1$u (0x%1$x)\n", info->type);

    printf("\n");
}

void printbin(int n)
{
    for (int i = 0; i < 32; i++)
    {
        if((n >> i) & 1)
            printf("1");
        else
            printf("0");
    }
}

void sgx_info()
{
    printf("=====\nSGX information\n-----\n");
    unsigned int eax, ebx, ecx, edx;
    unsigned int epc = 2;

    // Check general SGX availability
    // Bit 2 of EBX informs of SGX availability.
    // The spec does not say if they count from 0 or 1, but looking at the tables 1-4, 1-5 and 1-6
    // I assume they start counting at 0.
    cpuid(0x07, 0x00, &eax, &ebx, &ecx, &edx);
    sgx_cap_7_0_ebx_t *sgx_avail = (sgx_cap_7_0_ebx_t *) &ebx;

    printf("SGX available: ");
    if (!sgx_avail->sgx)
    {
        printf("%sNO%s\n", RED, NORMAL);
        return;
    }

    printf("%sYES%s\n", GREEN, NORMAL);

    // Check which SGX version is supported
    cpuid(0x12, 0x00, &eax, &ebx, &ecx, &edx);
    sgx_cap_12_0__eax_t *sgx_version = (sgx_cap_12_0__eax_t *) &eax;

    printf("SGX version support: ");
    if (sgx_version->sgxv1 && !sgx_version->sgxv2)
    {
        printf("%sv1 only%s\n", YELLOW, NORMAL);
    }
    else if (sgx_version->sgxv1 && sgx_version->sgxv2)
    {
        printf("%sv1 + v2%s\n", GREEN, NORMAL);
    }
    else if (!sgx_version->sgxv1 && sgx_version->sgxv2)
    {
        printf("%sv2 (and only 2, CPU does not report support for v1 which is weird)%s\n", YELLOW, NORMAL);
    }
    else if (!sgx_version->sgxv1 && !sgx_version->sgxv2)
    {
        printf("%sNONE%s\nSomething is wrong, CPU indicates SGX availability but reports neither SGX v1 or SGX v2 compatibility!\n", RED, NORMAL);
        return;
    }

    printf("\n");

    sgx_cap_12_0__ebx_t *miscselect = (sgx_cap_12_0__ebx_t *) &ebx;
    printf("MISCSELECT bit vector for extended features; written to SSA MISC region: \n");
    printbin(miscselect->miscselect);
    printf("\n\n");

    sgx_cap_12_0__edx_t *enc_info = (sgx_cap_12_0__edx_t *) &edx;
    unsigned char enc_size_32 = (unsigned char) enc_info->max_enclave_size_32;
    unsigned char enc_size_64 = (unsigned char) enc_info->max_enclave_size_64;
    unsigned long long enc_size_32_bytes = 1llu << enc_size_32;
    unsigned long long enc_size_64_bytes = 1llu << enc_size_64;
    printf("Max enclave size in non-64bit mode: 2^%u byte (%llu byte, %llu MiB, %llu GiB) \n", enc_size_32, enc_size_32_bytes, enc_size_32_bytes / (1024*1024), enc_size_32_bytes / (1024*1024*1024));
    printf("Max enclave size in     64bit mode: 2^%u byte (%llu byte, %llu MiB, %llu GiB) \n", enc_size_64, enc_size_64_bytes, enc_size_64_bytes / (1024*1024), enc_size_64_bytes / (1024*1024*1024));

    printf("\n");

    cpuid(0x12, 0x01, &eax, &ebx, &ecx, &edx);
    sgx_cap_12_1__eax_t *secs_attr_a = (sgx_cap_12_1__eax_t *)&eax;
    sgx_cap_12_1__ebx_t *secs_attr_b = (sgx_cap_12_1__ebx_t *)&ebx;
    sgx_cap_12_1__ecx_t *secs_attr_c = (sgx_cap_12_1__ecx_t *)&ecx;
    sgx_cap_12_1__edx_t *secs_attr_d = (sgx_cap_12_1__edx_t *)&edx;

    printf("Supported SECS attributes for ECREATE:\n");
    printbin(secs_attr_a->secs_attr);
    printf("\n");
    printbin(secs_attr_b->secs_attr);
    printf("\n");
    printbin(secs_attr_c->secs_attr);
    printf("\n");
    printbin(secs_attr_d->secs_attr);
    printf("\n\n");

    while(1)
    {
        printf("EPC region %u\n", epc - 1);
        cpuid(0x12, epc, &eax, &ebx, &ecx, &edx);
        sgx_cap_12_2__eax_t *epc_info = (sgx_cap_12_2__eax_t *) &eax;
        sgx_cap_12_2__ebx_t *epc_info_b = (sgx_cap_12_2__ebx_t *) &ebx;
        printf("EPC information available: ");
        if (!epc_info->epc_info_avail)
        {
            printf("%sNO%s\n", RED, NORMAL);
            return;
        }
        printf("%sYES%s\n", GREEN, NORMAL);

        __uint64_t epc_base = 0;
        epc_base |= ((uint64_t)epc_info->epc_phys_base_bits_12_to_31 << 0x0c) & 0x00000000ffffffff;
        epc_base |= ((uint64_t)epc_info_b->epc_phys_base_bits_31_to_51 << 0x20) & 0xffffffff00000000;
        printf("Physical EPC base address: %lx\n", epc_base);

        sgx_cap_12_2__ecx_t *epc_sec_info = (sgx_cap_12_2__ecx_t *) &ecx;
        sgx_cap_12_2__edx_t *epc_sec_info_b = (sgx_cap_12_2__edx_t *) &edx;

        printf("EPC is confidentiality, integrity and replay protected: ");
        if (!epc_sec_info->epc_sec_avail)
        {
            printf("%sNO%s\n", RED, NORMAL);
            return;
        }
        printf("%sYES%s\n", GREEN, NORMAL);

        __uint64_t epc_prm_size = 0;
        epc_prm_size |= ((uint64_t)epc_sec_info->epc_prm_size_bits_12_to_31 << 0x0c) & 0x00000000ffffffff;
        epc_prm_size |= ((uint64_t)epc_sec_info_b->epc_prm_size_bits_31_to_51 << 0x20) & 0xffffffff00000000;
        printf("Size of EPC inside Processor Reserved Memory: %lu B (%lu MiB)\n", epc_prm_size, epc_prm_size / 1024 / 1024);

        // Check next region
        cpuid(0x12, epc + 1, &eax, &ebx, &ecx, &edx);
        epc_info = (sgx_cap_12_2__eax_t *) &eax;
        if (!epc_info->epc_info_avail)
            break;
    }
}

int main()
{
    printf("SGX availability checker\n");

    general_cpu_info();

    sgx_info();

    return 0;
}

