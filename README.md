# Google Distributed Cloud Air-gapped CAS Node.js Client (`gdc-cas-nodejs-client`)

`gdc-cas-nodejs-client` provides the Node.js client library (`gdc-cas`) and testing utilities for interacting with the Google Distributed Cloud air-gapped (GDCag) Certificate Authority Service (CAS).

## Overview

This repository contains the CAS client module and developer utilities designed for enterprise workloads integrating with GDC air-gapped CAS:

* **[`gdc-cas`](./cas/gdc-cas)**: A Node.js client library for the Google Distributed Cloud air-gapped Certificate Authority Service (CAS). Supports RFC 8693 Security Token Service (STS) authentication, Kubernetes Resource Model (KRM) custom resources (`CertificateRequest`, `CertificateAuthority`, `RevokeCertificateRequest`), and direct gRPC dataplane communication.
* **[Load Test & Examples](./cas)**: Sample scripts and high-performance load testing utilities for validating Certificate Authority Service issuing and revocation throughput.

## Repository Structure

```
gdc-cas-nodejs-client/
├── .github/
│   └── CODEOWNERS            # Repository code owners
├── cas/
│   ├── gdc-cas/              # The 'gdc-cas' npm package source
│   │   ├── cas-client.js     # CAS client implementation (KRM & gRPC)
│   │   ├── cas-client.d.ts   # TypeScript definitions
│   │   ├── sts-auth.js       # STS token acquisition & JWT exchange
│   │   └── proto/            # Protocol buffer definitions & compiled descriptors
│   ├── run-example.js        # CAS client example and QPS benchmark runner
│   └── README.md             # Load testing guide and execution modes
├── CONTRIBUTING.md           # Guidelines for contributing to this project
├── LICENSE                   # Apache 2.0 license
├── NOTICE                    # Copyright and third-party attribution notices
└── README.md                 # Root documentation
```

## Quick Start

### Installation

Install the `gdc-cas` package in your Node.js application:

```bash
npm install gdc-cas
```

### Basic Usage

```javascript
import { CASClient } from 'gdc-cas';

const client = new CASClient({
  saFilePath: '/path/to/service-account.json',
  caFilePath: '/path/to/trust-bundle.crt',
  zone: 'us-west6-a',
});

// Initialize authentication and API clients
await client.init();

// Request a new TLS certificate
const certResult = await client.createCertificateRequest('my-project', {
  certificateAuthorityRef: 'my-ca',
  csr: base64EncodedCsrString,
});

console.log('Issued Certificate:', certResult.tlsCrt);
```

For full documentation, advanced options (connection pooling, custom HTTP middleware, direct gRPC mode), and certificate revocation, see the [gdc-cas package README](./cas/gdc-cas/README.md).

## Prerequisites

To interact with GDC air-gapped CAS using this library, you will need:

1. A project created in your GDC organization.
2. A service account key JSON file with appropriate permissions (e.g. `certificate-authority-service-admin`).
3. The GDC trust store root certificate (`ca.crt`).
4. An active Certificate Authority configured in your GDC namespace.

## Contributing

Contributions to this project are welcome! Please read [CONTRIBUTING.md](./CONTRIBUTING.md) for details on submitting pull requests and the Contributor License Agreement (CLA).

## License

This project is licensed under the Apache License, Version 2.0. See [LICENSE](./LICENSE) for full details.
