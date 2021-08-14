//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include <cstdio>
#include <cerrno>
#include <iostream>
#include <stdexcept>

#include <getopt.h>

#include "edge_wrapper.h"
#include "common/sha3.h"
#include "host/keystone.h"
#include "verifier/report.h"
#include "verifier/test_dev_key.h"

int
compute_sm_hash(byte *sm_hash, const byte *firmware_content,
                size_t firmware_size) {
  // keystone/bootrom/bootloader.c#L81 for how it is computed in the bootloader.
  const size_t sanctum_sm_size = 0x1ff000;
  byte *buf = (byte *)malloc(sanctum_sm_size);
  if (!buf) throw std::runtime_error{"Failed to allocate buffer"};
  memset(buf, 0, sanctum_sm_size);
  memcpy(buf, firmware_content, firmware_size);
  sha3_ctx_t hash_ctx;
  sha3_init(&hash_ctx, MDSIZE);
  sha3_update(&hash_ctx, buf, sanctum_sm_size);
  sha3_final(sm_hash, &hash_ctx);
  free(buf);
  return 0;
}


Keystone::Params *g_params = NULL;
char* g_eapp_file = NULL;
char* g_rt_file   = NULL;
char* g_sm_bin_file   = NULL;

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

  {
      Keystone::Enclave enclave;
      Keystone::Params params = *g_params;
      params.setSimulated(true);
      // This will cause validate_and_hash_enclave to be called when
      // isSimulated() == true.
      enclave.init(g_eapp_file, g_rt_file, params);
      memcpy(expected_enclave_hash, enclave.getHash(), MDSIZE);
  }

  byte* sm_content = NULL;
  size_t sm_size = 0;
  // TODO(zchn): This open will fail because we have not yet added the fw bin to qemu's image.
  FILE* sm_bin = fopen(g_sm_bin_file, "rb");
  if (sm_bin == NULL)
      throw std::runtime_error{std::string("Failed to open SM bin file: ")
              + g_sm_bin_file + " Error: " + std::strerror(errno)};
  // obtain file size:
  fseek(sm_bin, 0 , SEEK_END);
  sm_size = ftell(sm_bin);
  rewind(sm_bin);

  // allocate memory to contain the whole file:
  sm_content = (byte*)malloc(sizeof(byte)*sm_size + 10);
  if (sm_content == NULL)
      throw std::runtime_error{
          std::string("Failed to allocate memory for SM content. Error: ")
              + std::strerror(errno)};

  // copy the file into the buffer:
  if (sm_size != fread(sm_content, 1, sm_size, sm_bin))
      throw std::runtime_error{
          "sm_size is not equal to the size of the content successfully read"};

  // terminate
  fclose(sm_bin);

  compute_sm_hash(expected_sm_hash, sm_content, sm_size);

  // TODO(zchn): Fix the "invalid pointer" error when uncommenting this.
  // free(sm_content);

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
        "SIZE(K)] [--time] [--load-only] [--utm-ptr 0xPTR] [--retval EXPECTED] [--sm-bin SM_BIN_PATH]\n",
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
      {"sm-bin", required_argument, 0, 's'},
      {0, 0, 0, 0}};

  char* eapp_file = argv[1];
  char* rt_file   = argv[2];

  int c;
  int opt_index = 3;
  while (1) {
    c = getopt_long(argc, argv, "u:p:f:s:", long_options, &opt_index);

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
    case 's':
        g_sm_bin_file = optarg;
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

  // TODO(zchn): use a real remote verifier instead.
  g_params = &params;
  g_eapp_file = eapp_file;
  g_rt_file = rt_file;

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
