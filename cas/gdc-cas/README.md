# Google Distributed Cloud air-gapped CAS Node.js Client

This package provides a Node.js client to interact with the Google Distributed Cloud air-gapped (GDC) Certificate Authority Service (CAS).

## Installation

```sh
npm install gdc-cas
```

## Prerequisites
1. Create a [Project](https://cloud.google.com/distributed-cloud/hosted/docs/1.14-next/gdch/platform/pa-user/create-a-project) in your GDC cluster.
2. Follow the [Manage service accounts](https://cloud.google.com/distributed-cloud/hosted/docs/1.14-next/gdch/application/ao-user/iam/service-identities) steps to create a service account for your project:
    * Assign the `certificate-authority-service-admin` role to your service account.
    * Generate a key pair for your service account and store the private key as a JSON file. This JSON file will be used by the CAS client to authenticate with GDC.
3. Follow the [CAS user guide](https://cloud.google.com/distributed-cloud/hosted/docs/1.14-next/gdch/application/ao-user/ca-service/cas-overview) to create Certificate Authorities(CAs) for your project. The CAs will be referenced by the CAS client when requesting certificates.
4. [Fetch GDC trust bundles](https://cloud.google.com/distributed-cloud/hosted/docs/1.14-next/gdch/platform/pa-user/pki/fetch-trust-bundles) for `trust-store-global-root-ext`. The CAS client will need the trust bundle to connect to the GDC clusters.


## Usage
### Initialization
Provide the following configuration options to initialize the client:
```js
import { CASClient } from 'gdc-cas';

const clientConfig = {
    saFilePath: '/path/to/sa.json', // File path for the service account private key JSON file.
    caFilePath: '/path/to/ca.crt', // File path for the GDC trust store.
    zone: 'us-west6-a', // GDC zone name.
};

// Create and initialize the CASClient
const casClient = new CASClient(clientConfig);
await casClient.init();
```

### gRPC Mode (Bypass KRM)
By default, the client uses the Kubernetes API to manage certificate requests (KRM mode).
If you want to use the gRPC mode, initialize the client with `useGrpc: true`. This bypasses the Kubernetes API server and makes direct gRPC calls to the CAS proxy.

```js
const clientConfig = {
    saFilePath: '/path/to/sa.json',
    caFilePath: '/path/to/ca.crt',
    zone: 'us-west6-a',
    useGrpc: true, // Enable direct gRPC calls
    // casProxyUrl: 'https://cas.org.zone.domain.com' // Optional: Derived from token_uri if not specified
};

const casClient = new CASClient(clientConfig);
await casClient.init();
```

> [!NOTE]
> In gRPC mode, only `createCertificateRequest` and `createRevokeCertificateRequest` are supported. Other KRM operations (`getCertificateRequest`, `listCertificateRequests`, `deleteCertificateRequest`, `getCertificateAuthority`) are not supported over gRPC.

#### Certificate Revocation over gRPC

To request certificate revocation over gRPC:

```js
const revokeParams = {
  certificate: tlsCrtPemString, // The PEM-encoded certificate string to revoke
  reason: 'KEY_COMPROMISE',      // The reason for revocation (RevocationReason enum or string)
};

try {
  const revokeResult = await casClient.createRevokeCertificateRequest(project, revokeParams);
  console.log('Successfully revoked certificate. Reason:', revokeResult.reason);
} catch (error) {
  console.error('Revocation failed:', error.message);
}
```

#### Certificate Revocation over KRM

To request certificate revocation using KRM:

```js
const revokeParams = {
  certificateRequestRef: {
    name: 'original-certificate-request-name', // Name of the original CertificateRequest
    namespace: project,
  },
  reason: 'KEY_COMPROMISE',                     // The reason for revocation (RevocationReason enum or string)
};

try {
  const revokeResult = await casClient.createRevokeCertificateRequest(project, revokeParams, {
    timeoutMs: 15000,
    pollingIntervalMs: 200,
  });
  console.log('Successfully created RevokeCertificateRequest CR. Name:', revokeResult.revokeCertificateRequestName);
} catch (error) {
  console.error('Revocation failed:', error.message);
}
```

### Certificate Requests and Revocation Management
The client supports the following methods to manage certificate requests and revocation:

* `createCertificateRequest`
* `createRevokeCertificateRequest`
* `getRevokeCertificateRequest`
* `deleteRevokeCertificateRequest`
* `listRevokeCertificateRequests`
* `getCertificateRequest`
* `listCertificateRequests`
* `deleteCertificateRequest`
* `getCertificateAuthority`


---

## Development & Publishing Guide

When preparing a new release after local development or modifying the protobuf schema, follow these steps to securely build, bump the version, test the changes, and publish the package.

### 1. Updating the Protocol Buffer

If you modify `proto/cas.proto` to add new endpoints, fields, or services, you **must** recompile the static JSON descriptor so the gRPC client can serialize the payloads correctly at runtime:

```bash
# 1. Navigate to the package directory
cd ./cas/gdc-cas

# 2. Run the build:proto script to regenerate proto/cas-json.js
npm run build:proto
```
*Note: Make sure to commit the updated `proto/cas-json.js` file along with your `.proto` changes.*

### 2. Version Bumping

To safely bump the alpha pre-release version (e.g., from `alpha.1` to `alpha.2`) within the repository structure:

```bash
# 1. Navigate to the package directory
cd ./cas/gdc-cas

# 2. Increment the package version (without auto-tagging)
NEW_VERSION=$(npm version prerelease --preid=alpha --no-git-tag-version)
echo "Successfully bumped version to: $NEW_VERSION"

# 3. Stage the version change
git add .

# 4. Commit the new version
git commit -m "chore(gdc-cas): bump to $NEW_VERSION"
```

### 2. Local Testing with Verdaccio
Before publishing to the live registry, you can test the entire packaging and installation flow locally using Verdaccio.

**Start Verdaccio (Terminal 1):**
```bash
npx verdaccio
# This starts a local registry at http://localhost:4873
```

**Publish Locally (Terminal 2):**
1. Create a dummy test user on your local registry:
   ```bash
   npm addUser --registry http://localhost:4873 --auth-type=legacy
   # You will be prompted to enter a username and password. You can type anything as it does not matter to Verdaccio.
   ```
2. Publish `gdc-cas` to the local registry:
   ```bash
   # From the ./cas/gdc-cas directory
   npm publish --registry http://localhost:4873
   ```

**Test Installation (Terminal 3):**
Create a temporary directory anywhere on your computer to test the downloaded package:
```bash
mkdir ~/test-gdc-cas && cd ~/test-gdc-cas
npm init -y
npm install gdc-cas --registry http://localhost:4873
```

**Verify Functionality:**
Create a file named `test.js` in your `test-gdc-cas` directory to verify the package imports correctly:
```javascript
import { CASClient } from 'gdc-cas';

const clientConfig = {
    saFilePath: 'dummy.json', 
    caFilePath: 'dummy.crt', 
    zone: 'us-west6-a',
};

try {
    const casClient = new CASClient(clientConfig);
    console.log("Successfully imported and instantiated CASClient!");
} catch (error) {
    console.error("Failed to instantiate CASClient:", error);
}
```
Run it with `node test.js`. If it prints the success message, your package was bundled and published perfectly!

### 3. Publishing

To publish to the public npm registry:
```bash
# From the ./cas/gdc-cas directory
npm publish
```

Or to publish to an enterprise or private registry:
```bash
# From the ./cas/gdc-cas directory
npm publish --registry=https://<your-registry-url>
```
