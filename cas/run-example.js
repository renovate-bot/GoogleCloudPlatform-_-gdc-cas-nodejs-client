// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import { CASClient, RevocationReason } from './gdc-cas/index.js';
import forge from 'node-forge';
import crypto from 'crypto';

const delay = (ms) => new Promise(resolve => setTimeout(resolve, ms));

function randString(n) {
  return crypto.randomBytes(n).toString('hex').slice(0, n);
}


function generateCSR(commonName, keySize) {
  const keys = forge.pki.rsa.generateKeyPair({ bits: keySize, e: 0x10001 });
  const csr = forge.pki.createCertificationRequest();
  csr.setSubject([{ name: 'commonName', value: commonName }]);
  csr.publicKey = keys.publicKey;
  csr.sign(keys.privateKey, forge.md.sha256.create());
  return forge.pki.certificationRequestToPem(csr);
}

function convertDnToDerBase64(dnString) {
  const shortNameToOidName = {
    'CN': 'commonName',
    'C': 'countryName',
    'L': 'localityName',
    'ST': 'stateOrProvinceName',
    'O': 'organizationName',
    'OU': 'organizationalUnitName',
    'E': 'emailAddress'
  };

  const attributes = dnString.split(',').map(part => {
    const trimmedPart = part.trim();
    const match = trimmedPart.match(/^([^=]+)=(.*)$/);
    if (!match) {
      throw new Error(`Invalid attribute format: ${trimmedPart}`);
    }
    const [, shortName, value] = match;
    const oidName = shortNameToOidName[shortName];
    if (!oidName || !forge.pki.oids[oidName]) {
      throw new Error(`Unknown or unsupported attribute short name: ${shortName}`);
    }
    return { name: oidName, type: forge.pki.oids[oidName], value };
  });

  const subject = { attributes };
  const asn1Subject = forge.pki.distinguishedNameToAsn1(subject);
  const derBytes = forge.asn1.toDer(asn1Subject).getBytes();
  return forge.util.encode64(derBytes);
}

function formatCertificateToHumanReadable(pemString) {
  try {
    const cert = forge.pki.certificateFromPem(pemString);
    const formatDn = (dn) => dn.attributes.map(attr => `${attr.shortName || attr.name}=${attr.value}`).join(', ');

    let output = 'Certificate Details:\n';
    output += `  Subject: ${formatDn(cert.subject)}\n`;
    output += `  Issuer: ${formatDn(cert.issuer)}\n`;
    output += `  Serial Number: ${cert.serialNumber}\n`;
    output += `  Valid From: ${cert.validity.notBefore}\n`;
    output += `  Valid Until: ${cert.validity.notAfter}\n`;

    const san = cert.getExtension('subjectAltName');
    if (san && san.altNames) {
      const altNames = san.altNames.map(alt => {
        if (alt.type === 2) return `DNS:${alt.value}`;
        if (alt.type === 7) return `IP:${forge.util.bytesToIP(alt.value)}`;
        return `type ${alt.type}:${alt.value}`;
      }).join(', ');
      output += `  Subject Alternative Names: ${altNames}\n`;
    }

    return output;
  } catch (e) {
    console.error('Failed to parse certificate:', e);
    return `Could not parse certificate PEM. Raw PEM:\n${pemString}`;
  }
}

function formatDurationMs(ms) {
  if (ms === 0) return '0s';
  if (ms < 1000) return `${ms}ms`;
  return `${(ms / 1000).toFixed(2)}s`;
}

function printDurationStats(name, durationsMs) {
  if (durationsMs.length === 0) return;
  durationsMs.sort((a, b) => a - b);
  const sum = durationsMs.reduce((acc, val) => acc + val, 0);
  const avg = sum / durationsMs.length;
  const min = durationsMs[0];
  const max = durationsMs[durationsMs.length - 1];
  const p95 = durationsMs[Math.floor(durationsMs.length * 0.95)];

  console.log(`${name}:`);
  console.log(`  Min: ${formatDurationMs(min)}`);
  console.log(`  Max: ${formatDurationMs(max)}`);
  console.log(`  Avg: ${formatDurationMs(avg)}`);
  console.log(`  P95: ${formatDurationMs(p95)}`);
}

function printFloatStats(name, values) {
  if (values.length === 0) return;
  values.sort((a, b) => a - b);
  const sum = values.reduce((acc, val) => acc + val, 0);
  const avg = sum / values.length;
  const min = values[0];
  const max = values[values.length - 1];
  const p95 = values[Math.floor(values.length * 0.95)];

  console.log(`${name}:`);
  console.log(`  Min: ${min.toFixed(2)}`);
  console.log(`  Max: ${max.toFixed(2)}`);
  console.log(`  Avg: ${avg.toFixed(2)}`);
  console.log(`  P95: ${p95.toFixed(2)}`);
}

function processFinalResults(allResults, allRevocationResults, qpsValues, revocationQpsValues, totalDurationMs) {
  let successCount = 0;
  let failCount = 0;
  const creationLatencies = [];
  const reconcileLatencies = [];
  const issuanceLatencies = [];
  const totalTimes = [];

  for (const res of allResults) {
    if (res.error) {
      failCount++;
      if (failCount <= 10) {
        const errorDetail = res.error.body ? JSON.stringify(res.error.body) : res.error.message || res.error;
        console.log(`Issuance request ${res.name} failed: ${errorDetail}`);
      }
      continue;
    }
    successCount++;
    creationLatencies.push(res.creationLatency);
    reconcileLatencies.push(res.reconcileLatency);
    issuanceLatencies.push(res.issuanceLatency);
    totalTimes.push(res.totalDur);
  }

  let revokeSuccessCount = 0;
  let revokeFailCount = 0;
  const revokeCreationLatencies = [];
  const revokeReconcileLatencies = [];
  const revocationLatencies = [];

  for (const res of allRevocationResults) {
    if (res.error) {
      revokeFailCount++;
      if (revokeFailCount <= 10) {
        const errorDetail = res.error.body ? JSON.stringify(res.error.body) : res.error.message || res.error;
        console.log(`Revocation request failed: ${errorDetail}`);
      }
      continue;
    }
    revokeSuccessCount++;
    revokeCreationLatencies.push(res.creationLatency);
    revokeReconcileLatencies.push(res.reconcileLatency);
    revocationLatencies.push(res.revocationLatency);
  }

  console.log(`\n--- Final Statistics Summary ---`);
  console.log(`Issuance - Successful: ${successCount}, Failed: ${failCount}`);
  if (allRevocationResults.length > 0) {
    console.log(`Revocation - Successful: ${revokeSuccessCount}, Failed: ${revokeFailCount}`);
  }
  console.log(`Test Total Wall Clock Duration: ${formatDurationMs(totalDurationMs)}`);

  if (qpsValues.length > 0) {
    printFloatStats("Issuance QPS (Results per run)", qpsValues);
  }
  if (revocationQpsValues.length > 0) {
    printFloatStats("Revocation QPS (Results per run)", revocationQpsValues);
  }

  if (issuanceLatencies.length > 0) {
    console.log(`\n--- Final Issuance Latencies ---`);
    printDurationStats("Creation Latency (Start -> Created)", creationLatencies);
    printDurationStats("Processing Latency (Created -> Finish)", reconcileLatencies);
    printDurationStats("Total Latency (Start -> Finish)", issuanceLatencies);
  }

  if (revocationLatencies.length > 0) {
    console.log(`\n--- Final Revocation Latencies ---`);
    printDurationStats("Creation Latency (Start -> Created)", revokeCreationLatencies);
    printDurationStats("Processing Latency (Created -> Finish)", revokeReconcileLatencies);
    printDurationStats("Total Latency (Start -> Finish)", revocationLatencies);
  }

  if (totalTimes.length > 0) {
    console.log(`\n--- Final Total Latencies ---`);
    printDurationStats("Total Latency (Start -> Finish)", totalTimes);
  }
}

async function runDemo(config) {
  console.log("Running demo mode...");
  const clientConfig = {
    saFilePath: config.saFile,
    zone: config.zone,
    caFilePath: config.caFile,
    useGrpc: config.useGrpc,
    casProxyUrl: config.casProxyUrl
  };

  const casClient = new CASClient(clientConfig);
  await casClient.init();
  console.log("CASClient initialized successfully.");

  const project = config.project;
  const caName = config.caName;

  if (!config.useGrpc) {
    console.log(`\nGetting CertificateAuthority '${caName}' in namespace '${project}'...`);
    try {
      const caInfo = await casClient.getCertificateAuthority(project, caName);
      console.log(`Successfully retrieved CA '${caName}':`);
      console.log('  CA KRM object received.');
      console.log('  CA Spec (first 100 chars):', JSON.stringify(caInfo.certificateAuthority.spec).substring(0, 100) + '...');
      console.log('  CA Status (first 100 chars):', JSON.stringify(caInfo.certificateAuthority.status).substring(0, 100) + '...');
      console.log('  CA Certificate (first 50 chars):', caInfo.caCertificate.substring(0, 50) + '...');
      console.log('  Root CA Certificate (first 50 chars):', caInfo.rootCACertificate.substring(0, 50) + '...');
    } catch (err) {
      console.error(`Error getting CA:`, err.body ? err.body : err.message);
    }
  }

  const commonName = 'onetime.example.com';
  const csr = Buffer.from(generateCSR(commonName, config.rsaKeySize), 'utf8').toString('base64');
  const subjectString = 'C=US, O=Example Org, OU=Certificate Service Test Clients, OU=Dev, L=replaced, CN=replaced';
  const subjectOverride = convertDnToDerBase64(subjectString);

  let createdCertReqName;
  let certDataResponse;
  const certRequestParams = {
    certificateAuthorityRef: caName,
    csr: csr,
    notBefore: new Date(Date.now() + 2 * 60 * 1000),
    notAfter: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
    subjectOverride: subjectOverride
  };

  try {
    console.log('\nCreating a CertificateRequest and waiting for cert issuance...');
    const options = {
      timeoutMs: 30000,
      pollingIntervalMs: config.pollingInterval
    };
    certDataResponse = await casClient.createCertificateRequest(project, certRequestParams, options);
    createdCertReqName = certDataResponse.certificateRequestName;
    console.log(`CertificateRequest '${createdCertReqName}' created successfully and secret fetched:`);
    console.log('  Name:', certDataResponse.certificateRequestName);
    console.log('  tls.crt (first 50 chars):', certDataResponse.tlsCrt.substring(0, 50) + '...');
    console.log(formatCertificateToHumanReadable(certDataResponse.tlsCrt));
    console.log('  ca.crt (first 50 chars):', certDataResponse.caCert.substring(0, 50) + '...');
  } catch (err) {
    console.error('Error creating CertificateRequest:', err.body ? err.body : err.message);
  }

  if (!config.useGrpc) {
    console.log(`\nListing all CertificateRequests in namespace '${project}':`);
    try {
      const listResponse = await casClient.listCertificateRequests(project);
      console.log(`Found ${listResponse.items.length} CertificateRequests.`);
      listResponse.items.forEach(item => console.log('-', item.metadata.name, item.status && item.status.conditions ? `(Ready: ${item.status.conditions.find(c => c.type === 'Ready')?.status})` : '(No status)'));
    } catch (err) {
      console.error('Error listing CertificateRequests:', err.body ? err.body : err.message);
    }

    if (createdCertReqName) {
      console.log('\nGetting CertificateRequest...');
      try {
        const getResponse = await casClient.getCertificateRequest(project, createdCertReqName);
        console.log('Found CertificateRequest:', getResponse.metadata.name);
      } catch (err) {
        console.error('Error getting CertificateRequest:', err.body ? err.body : err.message);
      }
    }
  }

  if (config.revoke && certDataResponse) {
    if (config.useGrpc) {
      console.log('\nTesting createRevokeCertificateRequest over gRPC...');
      try {
        const revokeResponse = await casClient.createRevokeCertificateRequest(project, {
          certificate: certDataResponse.tlsCrt,
          reason: RevocationReason.KEY_COMPROMISE
        }, {
          timeoutMs: 60000
        });
        console.log('Successfully revoked certificate. Response reason:', revokeResponse.reason);
      } catch (err) {
        console.error('Error during certificate revocation:', err.message);
      }
    } else {
      console.log('\nTesting createRevokeCertificateRequest over KRM...');
      let revokeResponse;
      try {
        revokeResponse = await casClient.createRevokeCertificateRequest(project, {
          certificateRequestRef: {
            name: createdCertReqName,
            namespace: project,
          },
          reason: RevocationReason.KEY_COMPROMISE
        });
        console.log('Successfully created RevokeCertificateRequest KRM resource. Name:', revokeResponse.revokeCertificateRequestName);
      } catch (err) {
        console.error('Error during KRM certificate revocation:', err.message);
      }

      if (revokeResponse && revokeResponse.revokeCertificateRequestName) {
        console.log(`\nDeleting RevokeCertificateRequest '${revokeResponse.revokeCertificateRequestName}'...`);
        try {
          await casClient.deleteRevokeCertificateRequest(project, revokeResponse.revokeCertificateRequestName);
          console.log(`RevokeCertificateRequest '${revokeResponse.revokeCertificateRequestName}' deleted.`);
        } catch (err) {
          console.error(`Error deleting RevokeCertificateRequest '${revokeResponse.revokeCertificateRequestName}':`, err.body ? err.body : err.message);
        }
      }
    }
  }

  if (!config.useGrpc && createdCertReqName) {
    console.log(`\nDeleting CertificateRequest '${createdCertReqName}'...`);
    try {
      await casClient.deleteCertificateRequest(project, createdCertReqName);
      console.log(`CertificateRequest '${createdCertReqName}' deleted.`);
    } catch (err) {
      console.error(`Error deleting CertificateRequest '${createdCertReqName}':`, err.body ? err.body : err.message);
    }
  }
}

async function runLoadTest(config) {
  console.log("Running QPS load test mode...");
  const clientConfig = {
    saFilePath: config.saFile,
    zone: config.zone,
    caFilePath: config.caFile,
    useGrpc: config.useGrpc,
    casProxyUrl: config.casProxyUrl
  };

  const casClient = new CASClient(clientConfig);
  await casClient.init();
  console.log("CASClient initialized successfully.");

  if (config.clean) {
    console.log(`Cleaning up all CertificateRequests and RevokeCertificateRequests in namespace ${config.project}...`);
    try {
      const listRes = await casClient.listCertificateRequests(config.project);
      const deletePromises = listRes.items.map(item =>
        casClient.deleteCertificateRequest(config.project, item.metadata.name)
          .catch(err => console.warn(`Warning: failed to delete CertificateRequest ${item.metadata.name}: ${err.message}`))
      );
      await Promise.all(deletePromises);
    } catch (err) {
      console.warn(`Warning: failed to clean CertificateRequests: ${err.message}`);
    }
    try {
      const listRes = await casClient.listRevokeCertificateRequests(config.project);
      const deletePromises = listRes.items.map(item =>
        casClient.deleteRevokeCertificateRequest(config.project, item.metadata.name)
          .catch(err => console.warn(`Warning: failed to delete RevokeCertificateRequest ${item.metadata.name}: ${err.message}`))
      );
      await Promise.all(deletePromises);
    } catch (err) {
      console.warn(`Warning: failed to clean RevokeCertificateRequests: ${err.message}`);
    }
    console.log("Cleanup completed successfully.");
    return;
  }

  console.log(`Pre-warming connection pool with ${config.load} concurrent connections...`);
  const warmPromises = Array.from({ length: config.load }).map(() =>
    casClient.listCertificateRequests(config.project).catch(() => { })
  );
  await Promise.all(warmPromises);
  console.log("Connection pool pre-warmed.");

  console.log(`Starting load test with ${config.runs} runs of ${config.load} requests...`);
  const allResults = [];
  const allRevocationResults = [];
  const qpsValues = [];
  const revocationQpsValues = [];

  const globalStartTime = Date.now();

  for (let r = 0; r < config.runs; r++) {
    console.log(`\n--- Run ${r + 1}/${config.runs} ---`);

    console.log(`Pre-generating ${config.load} CSRs...`);
    const requests = [];
    for (let i = 0; i < config.load; i++) {
      const name = `load-test-${randString(6)}-${r}-${i}`;
      const csr = Buffer.from(generateCSR(name, config.rsaKeySize), 'utf8').toString('base64');
      requests.push({ name, csr });
    }

    console.log(`Sending ${config.load} parallel requests as fast as possible...`);
    const runStartTime = Date.now();

    const promises = requests.map(async (reqData) => {
      const clientStartTime = Date.now();
      const certRequestParams = {
        certReqName: reqData.name,
        certificateAuthorityRef: config.caName,
        csr: reqData.csr,
        notBefore: new Date(),
        notAfter: new Date(Date.now() + config.validity),
      };

      const res = {
        name: reqData.name,
        creationLatency: 0,
        reconcileLatency: 0,
        issuanceLatency: 0,
        revocationLatency: 0,
        totalDur: 0,
        error: null,
        tlsCrt: null,
      };

      try {
        const certDataResponse = await casClient.createCertificateRequest(config.project, certRequestParams, {
          timeoutMs: 30000,
          pollingIntervalMs: config.pollingInterval
        });
        const afterIssuanceTime = Date.now();
        res.issuanceLatency = afterIssuanceTime - clientStartTime;
        res.tlsCrt = certDataResponse.tlsCrt;
        res.totalDur = res.issuanceLatency;

        if (!config.useGrpc) {
          // Fetch the KRM object to parse creationTimestamp
          const getResponse = await casClient.getCertificateRequest(config.project, reqData.name);
          if (getResponse && getResponse.metadata && getResponse.metadata.creationTimestamp) {
            const creationTimeMs = Date.parse(getResponse.metadata.creationTimestamp);
            const creationLatency = Math.max(0, creationTimeMs - clientStartTime);
            res.creationLatency = creationLatency;
            res.reconcileLatency = Math.max(0, res.issuanceLatency - creationLatency);
          }
        } else {
          res.creationLatency = 0;
          res.reconcileLatency = res.issuanceLatency;
        }
      } catch (err) {
        res.error = err;
        res.issuanceLatency = Date.now() - clientStartTime;
        res.totalDur = res.issuanceLatency;
      }
      return res;
    });

    const runResults = await Promise.all(promises);
    const runDuration = Date.now() - runStartTime;
    console.log(`Run ${r + 1} finished in ${formatDurationMs(runDuration)}`);

    if (casClient.keepAliveAgent) {
      const activeSockets = Object.values(casClient.keepAliveAgent.sockets).reduce((acc, arr) => acc + arr.length, 0);
      const freeSockets = Object.values(casClient.keepAliveAgent.freeSockets).reduce((acc, arr) => acc + arr.length, 0);
      const requestsQueue = Object.values(casClient.keepAliveAgent.requests).reduce((acc, arr) => acc + arr.length, 0);
      console.log(`[Agent Stats] Active sockets: ${activeSockets}, Free (Keep-Alive) sockets: ${freeSockets}, Queued requests: ${requestsQueue}`);
    } else {
      console.log("[Agent Stats] No keepAliveAgent configured on client.");
    }

    let successCount = 0;
    const creationLatencies = [];
    const reconcileLatencies = [];
    const issuanceLatencies = [];
    const successfulIssuances = [];

    for (const res of runResults) {
      allResults.push(res);
      if (!res.error) {
        successCount++;
        creationLatencies.push(res.creationLatency);
        reconcileLatencies.push(res.reconcileLatency);
        issuanceLatencies.push(res.issuanceLatency);
        if (res.tlsCrt) {
          successfulIssuances.push(res);
        }
      }
    }

    if (issuanceLatencies.length > 0) {
      console.log(`\n--- Run ${r + 1} Issuance Statistics ---`);
      if (!config.useGrpc) {
        printDurationStats("Creation Latency (Start -> Created)", creationLatencies);
        printDurationStats("Processing Latency (Created -> Finish)", reconcileLatencies);
      }
      printDurationStats("Total Latency (Start -> Finish)", issuanceLatencies);
    }

    if (successCount > 0 && runDuration > 0) {
      const qps = (successCount * 1000) / runDuration;
      qpsValues.push(qps);
      console.log(`Run ${r + 1} QPS: ${qps.toFixed(2)}`);
    }

    // Concurrent Revocation Phase
    if (config.revoke && successfulIssuances.length > 0) {
      console.log(`Starting revocation for ${successfulIssuances.length} certificates...`);
      const revokeStartTime = Date.now();

      const revokePromises = successfulIssuances.map(async (issuanceRes) => {
        const revokeCallStartTime = Date.now();
        const revokeRes = {
          creationLatency: 0,
          reconcileLatency: 0,
          revocationLatency: 0,
          error: null,
        };
        try {
          const params = config.useGrpc ? {
            certificate: issuanceRes.tlsCrt,
            reason: RevocationReason.KEY_COMPROMISE
          } : {
            certificateRequestRef: {
              name: issuanceRes.name,
              namespace: config.project,
            },
            reason: RevocationReason.KEY_COMPROMISE
          };
          const revokeResponse = await casClient.createRevokeCertificateRequest(config.project, params, {
            timeoutMs: config.revokeTimeout
          });
          const duration = Date.now() - revokeCallStartTime;
          revokeRes.revocationLatency = duration;

          if (!config.useGrpc && revokeResponse && revokeResponse.revokeCertificateRequestName) {
            const getResponse = await casClient.getRevokeCertificateRequest(config.project, revokeResponse.revokeCertificateRequestName);
            if (getResponse && getResponse.metadata && getResponse.metadata.creationTimestamp) {
              const creationTimeMs = Date.parse(getResponse.metadata.creationTimestamp);
              const creationLatency = Math.max(0, creationTimeMs - revokeCallStartTime);
              revokeRes.creationLatency = creationLatency;
              revokeRes.reconcileLatency = Math.max(0, duration - creationLatency);
            }
          } else {
            revokeRes.creationLatency = 0;
            revokeRes.reconcileLatency = duration;
          }

          issuanceRes.revocationLatency = duration;
          issuanceRes.totalDur = issuanceRes.issuanceLatency + duration;
        } catch (err) {
          revokeRes.error = err;
          revokeRes.revocationLatency = Date.now() - revokeCallStartTime;

          issuanceRes.revocationLatency = 0;
          issuanceRes.totalDur = issuanceRes.issuanceLatency;
        }
        return revokeRes;
  });

  const revokeResults = await Promise.all(revokePromises);
  const revokeDuration = Date.now() - revokeStartTime;
  console.log(`Revocation finished in ${formatDurationMs(revokeDuration)}`);

  const successfulRevocations = revokeResults.filter(r => !r.error);
  const revocationQps = (successfulRevocations.length * 1000) / revokeDuration;
  console.log(`Run ${r + 1} Revocation QPS: ${revocationQps.toFixed(2)}`);

  allRevocationResults.push(...revokeResults);
  if (successfulRevocations.length > 0 && revokeDuration > 0) {
    revocationQpsValues.push(revocationQps);
  }

  // Print Revocation Statistics
  const revokeLatencies = successfulRevocations.map(r => r.revocationLatency);
  const revokeReconcileLatencies = successfulRevocations.map(r => r.reconcileLatency);
  const revokeCreationLatencies = successfulRevocations.map(r => r.creationLatency);

  if (revokeLatencies.length > 0) {
    console.log(`\n--- Run ${r + 1} Revocation Statistics ---`);
    printDurationStats("Creation Latency (Start -> Created)", revokeCreationLatencies);
    printDurationStats("Processing Latency (Created -> Finish)", revokeReconcileLatencies);
    printDurationStats("Total Latency (Start -> Finish)", revokeLatencies);
  }
}

if (r < config.runs - 1) {
  await delay(1000);
}
  }

const totalDuration = Date.now() - globalStartTime;
console.log(`\nAll ${config.runs} runs finished in ${formatDurationMs(totalDuration)}`);

processFinalResults(allResults, allRevocationResults, qpsValues, revocationQpsValues, totalDuration);
}

async function runSustainedTest(config) {
  console.log("Running sustained QPS load test mode...");
  console.log(`Target: ${config.load} requests/sec for ${formatDurationMs(config.duration)}`);

  const clientConfig = {
    saFilePath: config.saFile,
    zone: config.zone,
    caFilePath: config.caFile,
    useGrpc: config.useGrpc,
    casProxyUrl: config.casProxyUrl
  };

  const casClient = new CASClient(clientConfig);
  await casClient.init();
  console.log("CASClient initialized successfully.");

  if (config.clean) {
    console.log(`Cleaning up all CertificateRequests and RevokeCertificateRequests in namespace ${config.project}...`);
    try {
      const listRes = await casClient.listCertificateRequests(config.project);
      const deletePromises = listRes.items.map(item =>
        casClient.deleteCertificateRequest(config.project, item.metadata.name)
          .catch(err => console.warn(`Warning: failed to delete CertificateRequest ${item.metadata.name}: ${err.message}`))
      );
      await Promise.all(deletePromises);
    } catch (err) {
      console.warn(`Warning: failed to clean CertificateRequests: ${err.message}`);
    }
    try {
      const listRes = await casClient.listRevokeCertificateRequests(config.project);
      const deletePromises = listRes.items.map(item =>
        casClient.deleteRevokeCertificateRequest(config.project, item.metadata.name)
          .catch(err => console.warn(`Warning: failed to delete RevokeCertificateRequest ${item.metadata.name}: ${err.message}`))
      );
      await Promise.all(deletePromises);
    } catch (err) {
      console.warn(`Warning: failed to clean RevokeCertificateRequests: ${err.message}`);
    }
    console.log("Cleanup completed successfully.");
    return;
  }

  console.log(`Pre-generating ${config.load} CSRs to reuse...`);
  const cachedCsrs = [];
  for (let i = 0; i < config.load; i++) {
    const name = `sustained-csr-${i}`;
    const csr = Buffer.from(generateCSR(name, config.rsaKeySize), 'utf8').toString('base64');
    cachedCsrs.push(csr);
  }
  console.log("CSRs pre-generated.");

  console.log(`Pre-warming connection pool with ${config.load} concurrent connections...`);
  const warmPromises = Array.from({ length: config.load }).map(() =>
    casClient.listCertificateRequests(config.project).catch(() => {})
  );
  await Promise.all(warmPromises);
  console.log("Connection pool pre-warmed.");

  const allResults = [];
  const promises = [];
  let requestCount = 0;

  const globalStartTime = Date.now();
  const durationSeconds = Math.ceil(config.duration / 1000);

  console.log(`Starting sustained load test...`);

  for (let s = 0; s < durationSeconds; s++) {
    const targetTime = globalStartTime + s * 1000;
    const now = Date.now();
    const delayTime = targetTime - now;

    if (delayTime > 0) {
      await delay(delayTime);
    }

    console.log(`[Second ${s + 1}/${durationSeconds}] Sending ${config.load} requests...`);

    for (let i = 0; i < config.load; i++) {
      const currentReqIndex = requestCount++;
      const csr = cachedCsrs[currentReqIndex % config.load];
      const reqName = `sustained-${randString(6)}-${currentReqIndex}`;

      const p = (async () => {
        const clientStartTime = Date.now();
        const certRequestParams = {
          certReqName: reqName,
          certificateAuthorityRef: config.caName,
          csr: csr,
          notBefore: new Date(),
          notAfter: new Date(Date.now() + config.validity),
        };

        const res = {
          name: reqName,
          creationLatency: 0,
          reconcileLatency: 0,
          issuanceLatency: 0,
          totalDur: 0,
          error: null,
          tlsCrt: null,
        };

        try {
          const certDataResponse = await casClient.createCertificateRequest(config.project, certRequestParams, {
            timeoutMs: 30000,
            pollingIntervalMs: config.pollingInterval
          });
          const afterIssuanceTime = Date.now();
          res.issuanceLatency = afterIssuanceTime - clientStartTime;
          res.tlsCrt = certDataResponse.tlsCrt;
          res.totalDur = res.issuanceLatency;

          if (!config.useGrpc) {
            // Fetch the KRM object to parse creationTimestamp
            const getResponse = await casClient.getCertificateRequest(config.project, reqName);
            if (getResponse && getResponse.metadata && getResponse.metadata.creationTimestamp) {
              const creationTimeMs = Date.parse(getResponse.metadata.creationTimestamp);
              const creationLatency = Math.max(0, creationTimeMs - clientStartTime);
              res.creationLatency = creationLatency;
              res.reconcileLatency = Math.max(0, res.issuanceLatency - creationLatency);
            }
          } else {
            res.creationLatency = 0;
            res.reconcileLatency = res.issuanceLatency;
          }
        } catch (err) {
          res.error = err;
          res.issuanceLatency = Date.now() - clientStartTime;
          res.totalDur = res.issuanceLatency;
        }
        allResults.push(res);
      })();
      promises.push(p);
    }
  }

  console.log("All requests dispatched. Waiting for outstanding requests to complete...");
  await Promise.all(promises);

  const totalDurationMs = Date.now() - globalStartTime;

  if (casClient.keepAliveAgent) {
    const activeSockets = Object.values(casClient.keepAliveAgent.sockets).reduce((acc, arr) => acc + arr.length, 0);
    const freeSockets = Object.values(casClient.keepAliveAgent.freeSockets).reduce((acc, arr) => acc + arr.length, 0);
    const requestsQueue = Object.values(casClient.keepAliveAgent.requests).reduce((acc, arr) => acc + arr.length, 0);
    console.log(`[Agent Stats] Active sockets: ${activeSockets}, Free (Keep-Alive) sockets: ${freeSockets}, Queued requests: ${requestsQueue}`);
  }

  let successCount = 0;
  let failCount = 0;
  const creationLatencies = [];
  const reconcileLatencies = [];
  const totalTimes = [];

  for (const res of allResults) {
    if (res.error) {
      failCount++;
      if (failCount <= 10) {
        const errorDetail = res.error.body ? JSON.stringify(res.error.body) : res.error.message || res.error;
        console.log(`Request ${res.name} failed: ${errorDetail}`);
      }
      continue;
    }
    successCount++;
    creationLatencies.push(res.creationLatency);
    reconcileLatencies.push(res.reconcileLatency);
    totalTimes.push(res.issuanceLatency);
  }

  const finalQps = (successCount * 1000) / totalDurationMs;

  console.log(`\n--- Sustained Load Test Results ---`);
  console.log(`Total Duration: ${formatDurationMs(totalDurationMs)}`);
  console.log(`Total Requests Dispatched: ${requestCount}`);
  console.log(`Successful: ${successCount}, Failed: ${failCount}`);
  console.log(`Sustained QPS: ${finalQps.toFixed(2)}`);

  if (totalTimes.length > 0) {
    if (!config.useGrpc) {
      printDurationStats("Creation Latency (Start -> Created)", creationLatencies);
      printDurationStats("Processing Latency (Created -> Finish)", reconcileLatencies);
    }
    printDurationStats("Total Latency (Start -> Finish)", totalTimes);
  }
}

function parseArgs(args) {
  const parsed = {
    saFile: 'sa.json',
    caFile: 'ca.crt',
    zone: 'zone1',
    project: 'cas-load-test',
    caName: 'root-ca-ecdsa',
    load: 50,
    validity: 90 * 24 * 60 * 60 * 1000,
    runs: 10,
    clean: false,
    rsaKeySize: 2048,
    useGrpc: false,
    casProxyUrl: null,
    revoke: false,
    revokeTimeout: 10 * 60 * 1000, // 10 minutes default
    duration: 30000,
    pollingInterval: 200
  };

  const parseDuration = (str) => {
    const match = str.match(/^(\d+)([smhd])$/);
    if (!match) {
      const val = parseFloat(str);
      if (isNaN(val)) throw new Error(`Invalid duration format: ${str}`);
      return val;
    }
    const val = parseInt(match[1], 10);
    const unit = match[2];
    switch (unit) {
      case 's': return val * 1000;
      case 'm': return val * 60 * 1000;
      case 'h': return val * 60 * 60 * 1000;
      case 'd': return val * 24 * 60 * 60 * 1000;
      default: return val;
    }
  };

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    let key = '';
    let val = '';
    if (arg.startsWith('--')) {
      const parts = arg.slice(2).split('=');
      key = parts[0];
      if (parts.length > 1) {
        val = parts.slice(1).join('=');
      } else {
        if (i + 1 < args.length && !args[i + 1].startsWith('--')) {
          val = args[++i];
        } else {
          val = 'true';
        }
      }
    } else {
      continue;
    }

    switch (key) {
      case 'sa-file':
        parsed.saFile = val;
        break;
      case 'ca-file':
        parsed.caFile = val;
        break;
      case 'zone':
        parsed.zone = val;
        break;
      case 'project':
        parsed.project = val;
        break;
      case 'ca-name':
        parsed.caName = val;
        break;
      case 'load':
        parsed.load = parseInt(val, 10);
        break;
      case 'validity':
        parsed.validity = parseDuration(val);
        break;
      case 'runs':
        parsed.runs = parseInt(val, 10);
        break;
      case 'clean':
        parsed.clean = (val === 'true' || val === true);
        break;
      case 'rsa-key-size':
        parsed.rsaKeySize = parseInt(val, 10);
        break;
      case 'duration':
        parsed.duration = parseDuration(val);
        break;
      case 'use-grpc':
        parsed.useGrpc = (val === 'true');
        break;
      case 'cas-proxy-url':
        parsed.casProxyUrl = val;
        break;
      case 'revoke':
        parsed.revoke = (val === 'true' || val === true);
        break;
      case 'revoke-timeout':
        parsed.revokeTimeout = parseDuration(val);
        break;
      case 'polling-interval':
        parsed.pollingInterval = parseDuration(val);
        break;
      default:
        console.warn(`Warning: Unknown flag: --${key}`);
    }
  }

  return parsed;
}

function printUsage() {
  console.log("Usage: node run-example.js <mode> [flags]");
  console.log("\nModes:");
  console.log("  demo                    Run original demo creating/listing/getting/deleting a single cert");
  console.log("  qps-burst               Run QPS burst load test");
  console.log("  qps-duration            Run sustained QPS load test");
  console.log("\nFlags:");
  console.log("  --sa-file <path>        Path to the service account private key json (default: sa.json)");
  console.log("  --ca-file <path>        Path to GDC trust bundles (default: ca.crt)");
  console.log("  --zone <name>           GDC Zone name (default: zone1)");
  console.log("  --project <name>        GCP/GDC Project/Namespace (default: demo: cas-test, qps-burst: cas-load-test)");
  console.log("  --ca-name <name>        Name of the CA (default: demo: sub-ca-1, qps-burst: root-ca-ecdsa)");
  console.log("  --load <number>         Total number of requests per run / requests per second (default: 50)");
  console.log("  --validity <duration>   Certificate validity duration (e.g. 90d, 2160h) (default: 90d)");
  console.log("  --runs <number>         Total number of runs for qps-burst mode (default: 10)");
  console.log("  --duration <duration>   Sustained test duration (e.g. 30s, 5m) (default: 30s)");
  console.log("  --polling-interval <dur> Polling interval for KRM cert ready check (e.g. 200ms, 1s) (default: 200ms)");
  console.log("  --clean                 Clean up CertificateRequests before/after test (default: false)");
  console.log("  --rsa-key-size <number> RSA key size for generated certificates (default: 2048)");
  console.log("  --use-grpc              Use native gRPC to bypass KRM (default: false)");
  console.log("  --cas-proxy-url <url>   URL for the CAS proxy if using gRPC");
  console.log("  --revoke                Revoke the certificate after creation in demo mode (default: false)");
  console.log("  --revoke-timeout <dur>  Timeout for revocation polling (e.g. 10m, 60s) (default: 10m)");
  console.log("  -h, --help              Print this help message");
}

async function main() {
  if (process.argv.includes('--help') || process.argv.includes('-h')) {
    printUsage();
    process.exit(0);
  }

  let mode = 'demo';
  let argsStartIdx = 2;

  if (process.argv[2] === 'demo' || process.argv[2] === 'qps-burst' || process.argv[2] === 'qps-duration') {
    mode = process.argv[2];
    argsStartIdx = 3;
  } else if (process.argv[2] && !process.argv[2].startsWith('-')) {
    console.error(`Unknown mode: ${process.argv[2]}`);
    printUsage();
    process.exit(1);
  }

  const args = process.argv.slice(argsStartIdx);
  const config = parseArgs(args);

  if (mode === 'demo') {
    if (!args.some(a => a.startsWith('--project'))) {
      config.project = 'cas-test';
    }
    if (!args.some(a => a.startsWith('--ca-name'))) {
      config.caName = 'sub-ca-1';
    }
    await runDemo(config);
  } else if (mode === 'qps-burst') {
    await runLoadTest(config);
  } else if (mode === 'qps-duration') {
    await runSustainedTest(config);
  }
}

main().catch(console.error);
