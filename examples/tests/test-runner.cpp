//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include <getopt.h>
#include <cstdio>
#include <iostream>
#include "edge_wrapper.h"
#include "common/sha3.h"
#include "host/keystone.h"
#include "verifier/report.h"
#include "verifier/test_dev_key.h"

const char* longstr = "hellohellohellohellohellohellohellohellohellohello";

unsigned long
print_buffer(char* str) {
  printf("Enclave said: %s", str);
  return strlen(str);
}

void
print_value(unsigned long val) {
  printf("Enclave said value: %u\n", val);
  return;
}

const char*
get_host_string() {
  return longstr;
}

static struct report_t report;

void
print_hex(void* buffer, size_t len) {
  int i;
  for (i = 0; i < len; i += sizeof(uintptr_t)) {
    printf("%.16lx ", *((uintptr_t*)((uintptr_t)buffer + i)));
  }
  printf("\n");
}

int
compute_sm_hash(byte *sm_hash, const byte *fw_content, size_t fw_size) {
  // keystone/bootrom/bootloader.c#L81 for how it is computed in the bootloader.
  const size_t sanctum_sm_size = 0x1ff000;
  byte *buf = (byte *)malloc(sanctum_sm_size);
  if (!buf) {
      printf("Failed to allocate buffer\n");
      return -1;
  }
  memset(buf, 0, sanctum_sm_size);
  memcpy(buf, fw_content, fw_size);
  sha3_ctx_t hash_ctx;
  sha3_init(&hash_ctx, MDSIZE);
  sha3_update(&hash_ctx, buf, sanctum_sm_size);
  sha3_final(sm_hash, &hash_ctx);

  printf("unsigned char sm_expected_hash[] = {");
  for (int i=0; i < MDSIZE; i++) {
      if (i % 8 == 0) {
          printf("\n");
      }
      printf("0x%.2x,", sm_hash[i]);
  }
  printf("};\n");
  printf("unsigned int sm_expected_hash_len = %d;\n", MDSIZE);
}

void
copy_report(void* buffer) {
  Report report;

  report.fromBytes((unsigned char*)buffer);

  if (report.checkSignaturesOnly(_sanctum_dev_public_key)) {
    printf("Attestation report SIGNATURE is valid\n");
  } else {
    printf("Attestation report is invalid\n");
  }

  byte expected_enclave_hash[MDSIZE];
  byte expected_sm_hash[MDSIZE];

  compute_sm_hash(expected_sm_hash, expected_enclave_hash, MDSIZE);

  if(report.verify(expected_enclave_hash, expected_sm_hash,
                   _sanctum_dev_public_key)) {
      printf("Enclave and SM hashes match with expected.\n");
  } else {
      printf("Either the enclave hash or the SM hash (or both) does not "
             "match with expeced.\n");
      report.printPretty();
  }
}

int
main(int argc, char** argv) {
  if (argc < 3 || argc > 8) {
    printf(
        "Usage: %s <eapp> <runtime> [--utm-size SIZE(K)] [--freemem-size "
        "SIZE(K)] [--time] [--load-only] [--utm-ptr 0xPTR] [--retval EXPECTED]\n",
        argv[0]);
    return 0;
  }

  int self_timing = 0;
  int load_only   = 0;

  size_t untrusted_size = 2 * 1024 * 1024;
  size_t freemem_size   = 48 * 1024 * 1024;
  uintptr_t utm_ptr     = (uintptr_t)DEFAULT_UNTRUSTED_PTR;
  bool retval_exist = false;
  unsigned long retval = 0;

  static struct option long_options[] = {
      {"time", no_argument, &self_timing, 1},
      {"load-only", no_argument, &load_only, 1},
      {"utm-size", required_argument, 0, 'u'},
      {"utm-ptr", required_argument, 0, 'p'},
      {"freemem-size", required_argument, 0, 'f'},
      {"retval", required_argument, 0, 'r'},
      {0, 0, 0, 0}};

  char* eapp_file = argv[1];
  char* rt_file   = argv[2];

  int c;
  int opt_index = 3;
  while (1) {
    c = getopt_long(argc, argv, "u:p:f:", long_options, &opt_index);

    if (c == -1) break;

    switch (c) {
      case 0:
        break;
      case 'u':
        untrusted_size = atoi(optarg) * 1024;
        break;
      case 'p':
        utm_ptr = strtoll(optarg, NULL, 16);
        break;
      case 'f':
        freemem_size = atoi(optarg) * 1024;
        break;
      case 'r':
        retval_exist = true;
        retval = atoi(optarg);
        break;
    }
  }

  Keystone::Enclave enclave;
  Keystone::Params params;
  unsigned long cycles1, cycles2, cycles3, cycles4;

  params.setFreeMemSize(freemem_size);
  params.setUntrustedMem(utm_ptr, untrusted_size);

  if (self_timing) {
    asm volatile("rdcycle %0" : "=r"(cycles1));
  }

  enclave.init(eapp_file, rt_file, params);

  if (self_timing) {
    asm volatile("rdcycle %0" : "=r"(cycles2));
  }

  edge_init(&enclave);

  if (self_timing) {
    asm volatile("rdcycle %0" : "=r"(cycles3));
  }

  uintptr_t encl_ret;
  if (!load_only) enclave.run(&encl_ret);

  if (retval_exist && encl_ret != retval) {
    printf("[FAIL] enclave returned a wrong value (%d != %d)\r\n", encl_ret, retval);
  }

  if (self_timing) {
    asm volatile("rdcycle %0" : "=r"(cycles4));
    printf("[keystone-test] Init: %lu cycles\r\n", cycles2 - cycles1);
    printf("[keystone-test] Runtime: %lu cycles\r\n", cycles4 - cycles3);
  }

  return 0;
}
