//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include <getopt.h>
#include <stdlib.h>

#include <cerrno>
#include <cstdio>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <string>

// clang-format off
#include "edge_wrapper.h"
// clang-format on

#include "common/sha3.h"
#include "host/keystone.h"
#include "verifier/report.h"
#include "verifier/test_dev_key.h"

/****************************************************************
 * Helper functions to work with the handlers in edge_wrapper.h.
 ****************************************************************/
// For setting and getting the message for the enclave to fetch.
std::unique_ptr<std::string> g_host_string = nullptr;
void
set_host_string(const std::string& value) {
  if (g_host_string != nullptr)
    throw std::runtime_error("g_host_string set more than once");
  g_host_string = std::make_unique<std::string>(value);
}
std::string
get_host_string() {
  if (g_host_string == nullptr)
    throw std::runtime_error("g_host_string used before set");
  return *g_host_string;
}

// For copying and getting the attestation report from the enclave.
std::unique_ptr<Report> g_report = nullptr;
void
copy_report(void* buffer) {
  if (g_report != nullptr)
    throw std::runtime_error("g_report set more than once");
  g_report = std::make_unique<Report>();
  g_report->fromBytes((byte*)buffer);
}
Report
get_report() {
  if (g_report == nullptr) throw std::runtime_error("g_report used before set");
  return *g_report;
}

/****************************************************************
 * Declarations for the Host class and the Verifier class.
 ****************************************************************/

// The Host class mimicks a host interacting with the local enclave
// and the remote verifier.
class Host {
 public:
  Host(
      const Keystone::Params& params, const std::string& eapp_file,
      const std::string& rt_file)
      : params_(params), eapp_file_(eapp_file), rt_file_(rt_file) {}
  // Given a random nonce from the remote verifier, this method leaves
  // it for the enclave to fetch, and returns the attestation report
  // from the enclave to the verifier.
  Report run(const std::string& nonce);

 private:
  const Keystone::Params params_;
  const std::string eapp_file_;
  const std::string rt_file_;
};

class Verifier {
 public:
  Verifier(
      const Keystone::Params& params, const std::string& eapp_file,
      const std::string& rt_file, const std::string& sm_bin_file)
      : params_(params),
        eapp_file_(eapp_file),
        rt_file_(rt_file),
        sm_bin_file_(sm_bin_file) {}
  // This method generates a random nonce, invokes the run() method
  // of the Host, and verifies that the returned attestation report
  // is valid.
  void run();

 private:
  // Debug only: verifies just the signature but not the hashes.
  static void debug_verify(Report& report, const byte* dev_public_key);

  // Verifies that both the enclave hash and the SM hash in the
  // attestation report matches with the expected onces computed by
  // the Verifier.
  static void verify_hashes(
      Report& report, const byte* expected_enclave_hash,
      const byte* expected_sm_hash, const byte* dev_public_key);

  // Verifies that the nonce returned in the attestation report is
  // the same as the one sent.
  static void verify_data(Report& report, const std::string& nonce);

  // Verifies the hashes and the nonce in the attestation report.
  void verify_report(Report& report, const std::string& nonce);

  // Computes the hash of the expected EApp running in the enclave.
  void compute_expected_enclave_hash(byte* expected_enclave_hash);

  // Computes the hash of the expected Security Monitor (SM).
  void compute_expected_sm_hash(byte* expected_sm_hash);

  const Keystone::Params params_;
  const std::string eapp_file_;
  const std::string rt_file_;
  const std::string sm_bin_file_;
};

/****************************************************************
 * Class method definitions.
 ****************************************************************/

Report
Host::run(const std::string& nonce) {
  Keystone::Enclave enclave;
  enclave.init(eapp_file_.c_str(), rt_file_.c_str(), params_);

  // Leaves the nonce in a global variable so the enclave can get it
  // when making OCALL_GET_STRING ocall. See get_host_string_wrapper()
  // in edge_wrapper.cpp for how this is implemented under the hood.
  set_host_string(nonce);

  edge_init(&enclave);

  uintptr_t encl_ret;
  enclave.run(&encl_ret);

  // There should already be a report sent from the enclave after the
  // enclave finishes running. See copy_report_wrapper for how this is
  // implemented under the hood.
  return get_report();
}

void
Verifier::run() {
  const std::string nonce = std::to_string(random() % 0x100000000);
  Host host(params_, eapp_file_, rt_file_);
  Report report = host.run(nonce);
  verify_report(report, nonce);
}

void
Verifier::verify_report(Report& report, const std::string& nonce) {
  debug_verify(report, _sanctum_dev_public_key);

  byte expected_enclave_hash[MDSIZE];
  compute_expected_enclave_hash(expected_enclave_hash);

  byte expected_sm_hash[MDSIZE];
  compute_expected_sm_hash(expected_sm_hash);

  verify_hashes(
      report, expected_enclave_hash, expected_sm_hash, _sanctum_dev_public_key);

  verify_data(report, nonce);
}

void
Verifier::verify_hashes(
    Report& report, const byte* expected_enclave_hash,
    const byte* expected_sm_hash, const byte* dev_public_key) {
  if (report.verify(expected_enclave_hash, expected_sm_hash, dev_public_key)) {
    printf("Enclave and SM hashes match with expected.\n");
  } else {
    printf(
        "Either the enclave hash or the SM hash (or both) does not "
        "match with expeced.\n");
    report.printPretty();
  }
}

void
Verifier::verify_data(Report& report, const std::string& nonce) {
  if (report.getDataSize() != nonce.length() + 1) {
    const char error[] =
        "The size of the data in the report is not equal to the size of the "
        "nonce initially sent.";
    printf(error);
    report.printPretty();
    throw std::runtime_error(error);
  }

  if (0 == strcmp(nonce.c_str(), (char*)report.getDataSection())) {
    printf("Returned data in the report match with the nonce sent.\n");
  } else {
    printf("Returned data in the report do NOT match with the nonce sent.\n");
  }
}

void
Verifier::compute_expected_enclave_hash(byte* expected_enclave_hash) {
  Keystone::Enclave enclave;
  Keystone::Params simulated_params = params_;
  simulated_params.setSimulated(true);
  // This will cause validate_and_hash_enclave to be called when
  // isSimulated() == true.
  enclave.init(eapp_file_.c_str(), rt_file_.c_str(), simulated_params);
  memcpy(expected_enclave_hash, enclave.getHash(), MDSIZE);
}

void
Verifier::compute_expected_sm_hash(byte* expected_sm_hash) {
  // It is important to make sure the size of the SM buffer we are
  // measuring is the same as the size of the SM buffer allocated by
  // the bootloader. See keystone/bootrom/bootloader.c for how it is
  // computed in the bootloader.
  const size_t sanctum_sm_size = 0x1ff000;
  std::vector<byte> sm_content(sanctum_sm_size, 0);

  {
    // Reading SM content from file.
    FILE* sm_bin = fopen(sm_bin_file_.c_str(), "rb");
    if (!sm_bin)
      throw std::runtime_error(
          "Error opening sm_bin_file_: " + sm_bin_file_ + ", " +
          std::strerror(errno));
    if (fread(sm_content.data(), 1, sm_content.size(), sm_bin) <= 0)
      throw std::runtime_error(
          "Error reading sm_bin_file_: " + sm_bin_file_ + ", " +
          std::strerror(errno));
    fclose(sm_bin);
  }

  {
    // The actual SM hash computation.
    sha3_ctx_t hash_ctx;
    sha3_init(&hash_ctx, MDSIZE);
    sha3_update(&hash_ctx, sm_content.data(), sm_content.size());
    sha3_final(expected_sm_hash, &hash_ctx);
  }
}

void
Verifier::debug_verify(Report& report, const byte* dev_public_key) {
  if (report.checkSignaturesOnly(dev_public_key)) {
    printf("Attestation report SIGNATURE is valid\n");
  } else {
    printf("Attestation report is invalid\n");
  }
}

/****************************************************************
 * The main function.
 ****************************************************************/

int
main(int argc, char** argv) {
  if (argc < 3 || argc > 8) {
    printf(
        "Usage: %s <eapp> <runtime> [--utm-size SIZE(K)] [--freemem-size "
        "SIZE(K)] [--utm-ptr 0xPTR] [--sm-bin SM_BIN_PATH]\n",
        argv[0]);
    return 0;
  }

  int self_timing = 0;
  int load_only   = 0;

  size_t untrusted_size = 2 * 1024 * 1024;
  size_t freemem_size   = 48 * 1024 * 1024;
  uintptr_t utm_ptr     = (uintptr_t)DEFAULT_UNTRUSTED_PTR;
  bool retval_exist     = false;
  unsigned long retval  = 0;

  static struct option long_options[] = {
      {"utm-size", required_argument, 0, 'u'},
      {"utm-ptr", required_argument, 0, 'p'},
      {"freemem-size", required_argument, 0, 'f'},
      {"sm-bin", required_argument, 0, 's'},
      {0, 0, 0, 0}};

  char* eapp_file   = argv[1];
  char* rt_file     = argv[2];
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
