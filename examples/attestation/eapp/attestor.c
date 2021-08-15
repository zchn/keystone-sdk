#include <stdio.h>

#include "app/syscall.h"

// TODO: Share his with host.
#define OCALL_COPY_REPORT 3

void ocall_copy_report(void* report, size_t len) {
    ocall(OCALL_COPY_REPORT, report, len, 0, 0);
}

int main()
{
  printf("I am the processor in the enclave!\n");

  char* data = "nonce";
  char buffer[2048];

  attest_enclave((void*) buffer, data, 5);

  ocall_copy_report(buffer, 2048);

  return 0;
}
