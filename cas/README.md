# Google Distributed Cloud air-gapped CAS Node.js Client

This package provides a Node.js client to interact with the Google Distributed Cloud air-gapped (GDC) Certificate Authority Service (CAS).

## Repo Structure
```
cas/
├── gdc-cas/
│   ├── cas-client.js    // CAS Client implementation
│   ├── cas-client.d.ts  // Type information for the CAS Client
│   ├── sts-auth.js      // STS Token Auth for service account implementation
│   ├── index.js         // Entry point for the package
│   └── package.json     // Defines the gdc-cas package
├── package.json         // Defines the dependencies for run-example.js 
└── run-example.js       // Sample code / QPS load test to use the CAS client
```

## Documentation

For detailed package usage, prerequisites, and publishing instructions, please refer to the **[gdc-cas package README](./gdc-cas/README.md)**.

## Usage Example (`run-example.js`)

This directory includes a sample script `run-example.js` that demonstrates how to locally test the CAS client or run a QPS load test.

### 1. Install dependencies:
```bash
npm install
```

*(Ensure you have set up your service account JSON file, e.g., `sa.json`, and trust store bundle, e.g., `ca.crt`, as per the prerequisites in the main package README).*

### 2. Run Modes

The script supports three execution modes:

#### Demo Mode
Runs the original single-certificate lifecycle demonstration (create, show, list, and delete a single certificate request).

```bash
node run-example.js demo [flags]
```

#### QPS Burst Mode
Runs a parallel certificate request load test issuing requests concurrently as fast as possible in multiple runs.

```bash
node run-example.js qps-burst [flags]
```

#### QPS Duration Mode (Sustained)
Runs a sustained load test that dispatches a paced number of requests per second for a specified duration, reusing a pre-generated pool of CSRs to prevent client-side CPU bottlenecks.

```bash
node run-example.js qps-duration [flags]
```

### 3. Command Line Flags

You can customize the client config and test behavior using the following flags:

| Flag | Description | Default (Demo) | Default (QPS-Burst/Duration) |
|------|-------------|----------------|------------------------------|
| `--sa-file <path>` | Path to the service account private key JSON file | `sa.json` | `sa.json` |
| `--ca-file <path>` | Path to GDC trust store bundle | `ca.crt` | `ca.crt` |
| `--zone <name>` | GDC Zone name (e.g., `us-west6-a`) | `zone1` | `zone1` |
| `--project <name>` | GCP/GDC Project/Namespace | `cas-test` | `cas-load-test` |
| `--ca-name <name>` | Name of the Certificate Authority | `sub-ca-1` | `root-ca-ecdsa` |
| `--load <number>` | Total requests per run (Burst) / requests per second (Duration) | `50` | `50` |
| `--validity <duration>` | Certificate validity duration (e.g., `90d`, `2160h`, `10m`) | `90d` | `90d` |
| `--runs <number>` | Total number of runs (only applicable in `qps-burst` mode) | `10` | `10` |
| `--duration <duration>` | Sustained test duration (e.g., `30s`, `5m`) (only applicable in `qps-duration` mode) | `30s` | `30s` |
| `--polling-interval <dur>` | Polling interval for KRM certificate ready check (e.g., `200ms`, `1s`) | `200ms` | `200ms` |
| `--clean` | Clean up CertificateRequests and RevokeCertificateRequests in the namespace before/after test | `false` | `false` |
| `--rsa-key-size <number>` | RSA key size for generated certificates | `2048` | `2048` |
| `--use-grpc` | Use native gRPC to bypass KRM | `false` | `false` |
| `--cas-proxy-url <url>` | URL for the CAS proxy if using gRPC | `null` | `null` |
| `--revoke` | If true, revokes the certificate(s) after creation/issuance (supports both KRM and gRPC modes) | `false` | `false` |
| `--revoke-timeout <duration>` | Timeout for KRM revocation polling (e.g., `10m`, `30s`) | `10m` | `10m` |

### 4. Examples

Run the demo mode in a custom namespace:
```bash
node run-example.js demo --sa-file staging-sa.json --ca-file staging-ca.crt --zone us-west6-a --project my-project --ca-name my-ca
```

Run a QPS burst load test with 5 runs of 10 parallel requests:
```bash
node run-example.js qps-burst --sa-file staging-sa.json --ca-file staging-ca.crt --zone us-west6-a --project my-project --ca-name my-ca --load 10 --runs 5
```

Run a sustained QPS duration load test at a rate of 50 requests/sec for 30 seconds with a 1-second polling interval:
```bash
node run-example.js qps-duration --sa-file staging-sa.json --ca-file staging-ca.crt --zone us-west6-a --project my-project --ca-name my-ca --load 50 --duration 30s --polling-interval 1s
```

Run a QPS burst load test using direct gRPC calls to the CAS proxy (bypassing KRM):
```bash
node run-example.js qps-burst --sa-file staging-sa.json --ca-file staging-ca.crt --zone us-west6-a --project my-project --ca-name my-ca --load 10 --runs 5 --use-grpc
```

Run the demo mode with KRM and certificate revocation enabled:
```bash
node run-example.js demo --sa-file staging-sa.json --ca-file staging-ca.crt --zone us-west6-a --project my-project --ca-name my-ca --revoke
```

Run the demo mode with gRPC and certificate revocation enabled:
```bash
node run-example.js demo --sa-file staging-sa.json --ca-file staging-ca.crt --zone us-west6-a --project my-project --ca-name my-ca --use-grpc --revoke
```

Run a KRM QPS burst load test with 5 runs of 10 parallel requests, including KRM certificate revocation:
```bash
node run-example.js qps-burst --sa-file staging-sa.json --ca-file staging-ca.crt --zone us-west6-a --project my-project --ca-name my-ca --load 10 --runs 5 --revoke
```

Run a gRPC QPS burst load test with 5 runs of 10 parallel requests, including gRPC certificate revocation:
```bash
node run-example.js qps-burst --sa-file staging-sa.json --ca-file staging-ca.crt --zone us-west6-a --project my-project --ca-name my-ca --load 10 --runs 5 --use-grpc --revoke
```

Clean up all `CertificateRequests` and `RevokeCertificateRequests` in the load test namespace:
```bash
node run-example.js qps-burst --sa-file staging-sa.json --ca-file staging-ca.crt --zone us-west6-a --project my-project --clean
```

## Compiling to Standalone Binary

For executing the load test in ad-hoc environments without Node.js or `node_modules` dependencies, you can compile `run-example.js` into a standalone native binary:

1. **Install bundler and compiler tools** dynamically (without modifying `package.json`):
   ```bash
   npm install --no-save --registry=https://registry.npmjs.org/ esbuild pkg
   ```

2. **Bundle the script and dependencies**:
   ```bash
   ./node_modules/.bin/esbuild run-example.js --bundle --platform=node --format=cjs --outfile=dist/run-example.cjs
   ```

3. **Compile the bundle into a native Linux x64 binary using package.json config**:
   ```bash
   ./node_modules/.bin/pkg package.json --targets node18-linux-x64 --output run-example-bin
   ```

This generates a standalone binary named `run-example-bin` in the project root. To transfer and run this in your target environment:

1. **Compress the binary**:
   ```bash
   tar -czvf run-example-bin.tgz run-example-bin
   ```

2. **Upload the compressed binary and configuration files**:
   Transfer the archive to your target machine using `scp` or your environment's file transfer tool:
   ```bash
   scp run-example-bin.tgz user@remote-host:/tmp/
   ```

3. **Extract and execute the test on the remote environment**:
   ```bash
   cd /tmp
   tar -xzvf run-example-bin.tgz
   
   ./run-example-bin qps-burst --sa-file ~/sa.json --ca-file ca.crt --zone us-west6-a --project my-project --load 50 --runs 3
   ```
