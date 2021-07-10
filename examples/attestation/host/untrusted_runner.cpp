//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include "edge/edge_call.h"
#include "host/keystone.h"
#include "verifier/report.h"
#include "verifier/test_dev_key.h"

using namespace Keystone;

// TODO: Share his with eapp.
#define OCALL_COPY_REPORT 3

void
copy_report(void* buffer) {
    Report report;

    report.fromBytes((unsigned char*)buffer);

    if (report.checkSignaturesOnly(_sanctum_dev_public_key)) {
        printf("Attestation report SIGNATURE is valid\n");
    } else {
        printf("Attestation report is invalid\n");
    }
}

void
copy_report_wrapper(void* buffer) {
    /* For now we assume the call struct is at the front of the shared
     * buffer. This will have to change to allow nested calls. */
    struct edge_call* edge_call = (struct edge_call*)buffer;

    uintptr_t data_section;
    unsigned long ret_val;
      // TODO check the other side of this
    if (edge_call_get_ptr_from_offset(
            edge_call->call_arg_offset, sizeof(report_t), &data_section) != 0) {
        edge_call->return_data.call_status = CALL_STATUS_BAD_OFFSET;
        return;
    }

    copy_report((void*)data_section);

    edge_call->return_data.call_status = CALL_STATUS_OK;

    return;
}

int
main(int argc, char** argv) {
  Enclave enclave;
  Params params;

  params.setFreeMemSize(1024 * 1024);
  params.setUntrustedMem(DEFAULT_UNTRUSTED_PTR, 1024 * 1024);

  enclave.init(argv[1], argv[2], params);

  enclave.registerOcallDispatch(incoming_call_dispatch);
  register_call(OCALL_COPY_REPORT, copy_report_wrapper);

  edge_call_init_internals(
      (uintptr_t)enclave.getSharedBuffer(), enclave.getSharedBufferSize());

  uintptr_t encl_ret;
  enclave.run(&encl_ret);
  printf("Enclave returned %d.\r\n", encl_ret);

  return 0;
}
