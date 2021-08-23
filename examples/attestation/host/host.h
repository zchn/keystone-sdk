//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------

#ifndef _ATTESTATION_HOST_H_
#define _ATTESTATION_HOST_H_

#include "host/keystone.h"
#include "verifier/report.h"

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

#endif /* _ATTESTATION_HOST_H_ */
