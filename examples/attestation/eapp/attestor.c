//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include "app/eapp_utils.h"
#include "app/string.h"
#include "app/syscall.h"
#include "app/malloc.h"
#include "edge/edge_call.h"
#include "edge_wrapper.h"

int main(){
  edge_init();

  struct edge_data retdata;
  ocall_get_string(&retdata);

  for(int i = 1; i <= 10000; i++) {
      if (i % 5000 == 0) {
          ocall_print_value(i);
      }
  }

  char nonce[2048];
  if (retdata.size > 2048) retdata.size = 2048;
  copy_from_shared(nonce, retdata.offset, retdata.size);

  char buffer[2048];
  attest_enclave((void*) buffer, nonce, retdata.size);

  ocall_copy_report(buffer, 2048);

  return 0;
}
