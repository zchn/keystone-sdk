//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include <cstdio>
#include <cerrno>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <string>

#include <getopt.h>
#include <stdlib.h>

#include "edge_wrapper.h"
#include "common/sha3.h"
#include "host/keystone.h"
#include "verifier/report.h"
#include "verifier/test_dev_key.h"


std::unique_ptr<std::string> g_host_string = nullptr;
void set_host_string(const std::string& value) {
    if (g_host_string != nullptr) throw std::runtime_error("g_host_string set more than once");
    g_host_string = std::make_unique<std::string>(value);
}
std::string get_host_string() {
    if (g_host_string == nullptr) throw std::runtime_error("g_host_string used before set");
    return *g_host_string;
}

std::unique_ptr<Report> g_report = nullptr;
void copy_report(void* buffer) {
    if(g_report != nullptr) throw std::runtime_error("g_report set more than once");
    g_report = std::make_unique<Report>();
    g_report->fromBytes((byte*)buffer);
}
Report get_report() {
    if(g_report == nullptr) throw std::runtime_error("g_report used before set");
    return *g_report;
}

class Host {
public:
    Host(const Keystone::Params& params,
         const std::string& eapp_file,
         const std::string& rt_file)
        : params_(params), eapp_file_(eapp_file), rt_file_(rt_file) {}

    Report run(const std::string& nonce) {
        Keystone::Enclave enclave;
        enclave.init(eapp_file_.c_str(), rt_file_.c_str(), params_);

        set_host_string(nonce);
        edge_init(&enclave);

        uintptr_t encl_ret;
        enclave.run(&encl_ret);

        return get_report();
    }
private:
    const Keystone::Params params_;
    const std::string eapp_file_;
    const std::string rt_file_;
};

class Verifier {
public:
    Verifier(const Keystone::Params& params,
             const std::string& eapp_file,
             const std::string& rt_file,
             const std::string& sm_bin_file)
        : params_(params), eapp_file_(eapp_file), rt_file_(rt_file),
          sm_bin_file_(sm_bin_file) {}
    void run() {
        const std::string nonce = std::to_string(random() % 0x100000000);
        Host host(params_, eapp_file_, rt_file_);
        Report report = host.run(nonce);
        verify_report(report, nonce);
    }
private:
    static int compute_sm_hash(byte *sm_hash, const byte *firmware_content,
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
    void verify_report(Report& report, const std::string& nonce) {
        if (report.checkSignaturesOnly(_sanctum_dev_public_key)) {
            printf("Attestation report SIGNATURE is valid\n");
        } else {
            printf("Attestation report is invalid\n");
        }

        byte expected_enclave_hash[MDSIZE];
        byte expected_sm_hash[MDSIZE];

        {
            Keystone::Enclave enclave;
            Keystone::Params simulated_params = params_;
            simulated_params.setSimulated(true);
            // This will cause validate_and_hash_enclave to be called when
            // isSimulated() == true.
            enclave.init(eapp_file_.c_str(), rt_file_.c_str(), simulated_params);
            memcpy(expected_enclave_hash, enclave.getHash(), MDSIZE);
        }

        byte* sm_content = NULL;
        size_t sm_size = 0;

        FILE* sm_bin = fopen(sm_bin_file_.c_str(), "rb");
        if (sm_bin == NULL)
            throw std::runtime_error{std::string("Failed to open SM bin file: ")
                    + sm_bin_file_ + " Error: " + std::strerror(errno)};
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

        if(report.getDataSize() != nonce.length() + 1) {
            const char error[] = "The size of the data in the report is not equal to the size of the nonce initially sent.";
            printf(error);
            report.printPretty();
            throw std::runtime_error(error);
        }

        if(0 == strcmp(nonce.c_str(), (char*)report.getDataSection())) {
            printf("Returned data in the report match with the nonce sent.\n");
        } else {
            printf("Returned data in the report do NOT match with the nonce sent.\n");
        }

    }
    const Keystone::Params params_;
    const std::string eapp_file_;
    const std::string rt_file_;
    const std::string sm_bin_file_;
};


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

  if(self_timing) throw std::runtime_error("--time not implemented.");
  if(load_only) throw std::runtime_error("--load_only not implemented.");

  char* eapp_file = argv[1];
  char* rt_file   = argv[2];
  char* sm_bin_file = NULL;

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
        throw std::runtime_error("--retval not implemented.");
        break;
    case 's':
        sm_bin_file = optarg;
        break;
    }
  }

  Keystone::Params params;

  params.setFreeMemSize(freemem_size);
  params.setUntrustedMem(utm_ptr, untrusted_size);

  Verifier verifier{params, eapp_file, rt_file, sm_bin_file};
  verifier.run();

  return 0;
}
