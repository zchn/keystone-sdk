#include <stdio.h>

#include "app/syscall.h"

void ocall_copy_report(void* report, size_t len) {
    ocall(3, report, len, 0, 0);
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
