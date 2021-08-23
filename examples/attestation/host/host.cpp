//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include "host.h"

#include <getopt.h>
#include <stdlib.h>

#include <cerrno>
#include <cstdio>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <string>

#include "edge/edge_call.h"
#include "host/keystone.h"
#include "verifier/report.h"

#define OCALL_PRINT_BUFFER 1
#define OCALL_PRINT_VALUE 2
#define OCALL_COPY_REPORT 3
#define OCALL_GET_STRING 4

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
copy_report(Report report) {
  if (g_report != nullptr)
    throw std::runtime_error("g_report set more than once");
  g_report = std::make_unique<Report>();
  *g_report = std::move(report);
}
Report
get_report() {
  if (g_report == nullptr) throw std::runtime_error("g_report used before set");
  return *g_report;
}

class SharedBuffer {
 public:
  SharedBuffer(void* buffer)
      /* For now we assume the call struct is at the front of the shared
       * buffer. This will have to change to allow nested calls. */
      : edge_call_((struct edge_call*)buffer) {}

  void set_ok() { edge_call_->return_data.call_status = CALL_STATUS_OK; }
  void set_bad_offset() {
    edge_call_->return_data.call_status = CALL_STATUS_BAD_OFFSET;
  }
  void set_bad_ptr() {
    edge_call_->return_data.call_status = CALL_STATUS_BAD_PTR;
  }

  std::optional<std::pair<uintptr_t, size_t>>
  get_call_args_ptr_or_set_bad_offset() {
    uintptr_t call_args;
    size_t arg_len;
    if (edge_call_args_ptr(edge_call_, &call_args, &arg_len) != 0) {
      set_bad_offset();
      return std::nullopt;
    }
    return std::pair{call_args, arg_len};
  }

  std::optional<char*> get_c_string_or_set_bad_offset() {
    auto v = get_call_args_ptr_or_set_bad_offset();
    return v.has_value() ? std::optional{(char*)v.value().first} : std::nullopt;
  }

  std::optional<unsigned long> get_unsigned_long_or_set_bad_offset() {
    auto v = get_call_args_ptr_or_set_bad_offset();
    return v.has_value() ? std::optional{*(unsigned long*)v.value().first}
                         : std::nullopt;
  }

  std::optional<Report> get_report_or_set_bad_offset() {
    auto v = get_call_args_ptr_or_set_bad_offset();
    if (!v.has_value()) return std::nullopt;
    Report ret;
    ret.fromBytes((byte*)v.value().first);
    return ret;
  }

  void setup_ret_or_bad_ptr(unsigned long ret_val) {
    // Assuming we are done with the data section for args, use as
    // return region.
    //
    // TODO safety check?
    uintptr_t data_section = edge_call_data_ptr();

    memcpy((void*)data_section, &ret_val, sizeof(unsigned long));

    if (edge_call_setup_ret(
            edge_call_, (void*)data_section, sizeof(unsigned long))) {
      set_bad_ptr();
    } else {
      set_ok();
    }
  }

  void setup_wrapped_ret_or_bad_ptr(const std::string& ret_val) {
    if (edge_call_setup_wrapped_ret(
            edge_call_, (void*)ret_val.c_str(), ret_val.length() + 1)) {
      set_bad_ptr();
    } else {
      set_ok();
    }
    return;
  }

 private:
  struct edge_call* const edge_call_;
};

void
print_buffer_wrapper(void* buffer) {
  SharedBuffer shared_buffer(buffer);

  auto t = shared_buffer.get_c_string_or_set_bad_offset();
  if (t.has_value()) {
    printf("Enclave said: %s", t.value());
    auto ret_val = strlen(t.value());
    shared_buffer.setup_ret_or_bad_ptr(ret_val);
  }
}

void
print_value_wrapper(void* buffer) {
  SharedBuffer shared_buffer(buffer);

  auto t = shared_buffer.get_unsigned_long_or_set_bad_offset();
  if (t.has_value()) {
    printf("Enclave said value: %u\n", t.value());
    shared_buffer.set_ok();
  }
  return;
}

void
copy_report_wrapper(void* buffer) {
  SharedBuffer shared_buffer(buffer);

  auto t = shared_buffer.get_report_or_set_bad_offset();
  if (t.has_value()) {
    copy_report(std::move(t.value()));
    shared_buffer.set_ok();
  }
  return;
}

void
get_host_string_wrapper(void* buffer) {
  SharedBuffer shared_buffer(buffer);
  shared_buffer.setup_wrapped_ret_or_bad_ptr(get_host_string());
  return;
}

int
edge_init(Keystone::Enclave* enclave) {
  enclave->registerOcallDispatch(incoming_call_dispatch);
  register_call(OCALL_PRINT_BUFFER, print_buffer_wrapper);
  register_call(OCALL_PRINT_VALUE, print_value_wrapper);
  register_call(OCALL_COPY_REPORT, copy_report_wrapper);
  register_call(OCALL_GET_STRING, get_host_string_wrapper);

  edge_call_init_internals(
      (uintptr_t)enclave->getSharedBuffer(), enclave->getSharedBufferSize());
  return 0;
}

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
