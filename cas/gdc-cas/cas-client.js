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

import * as k8s from '@kubernetes/client-node';
import fs from 'fs';
import { URL } from 'url';
import https from 'https';

import grpc from '@grpc/grpc-js';
import protoLoader from '@grpc/proto-loader';
import casProtoRoot from './proto/cas-json.js';



/**
 * @typedef {import('./cas-client').CASClientConfig} CASClientConfig
 * @typedef {import('./cas-client').CreateCertificateRequestParams} CreateCertificateRequestParams
 * @typedef {import('./cas-client').CreateCertificateRequestOptions} CreateCertificateRequestOptions
 * @typedef {import('./cas-client').CreateCertificateRequestResult} CreateCertificateRequestResult
 * @typedef {import('./cas-client').CertificateAuthorityInfoResult} CertificateAuthorityInfoResult
 */
import { getStsToken } from './sts-auth.js';

const CRD_GROUP = 'pki.security.gdc.goog';
const CRD_VERSION = 'v1';
const CERT_REQ_CRD_PLURAL = 'certificaterequests';
const CA_CRD_PLURAL = 'certificateauthorities';
const REVOKE_REQ_CRD_PLURAL = 'revokecertificaterequests';

const CERT_REQ_NAME_PREFIX = 'cas-sdk-req-';
const DEFAULT_CERT_REQ_TIMEOUT_MS = 30000; // 30 seconds
const DEFAULT_CERT_REQ_POLLING_INTERVAL_MS = 200; // 0.2 seconds
const DEFAULT_REVOKE_REQ_TIMEOUT_MS = 60000; // 60 seconds

// Default gRPC built-in retry policy for transient CAS proxy failures (https://grpc.io/docs/guides/retry/).
// Narrowed to UNAVAILABLE and RESOURCE_EXHAUSTED to avoid retrying non-idempotent side effects
// (e.g., duplicate certificate issuance or already-revoked errors on INTERNAL/DEADLINE_EXCEEDED).
const DEFAULT_GRPC_RETRY_POLICY = {
  maxAttempts: 4,
  initialBackoff: '0.1s',
  maxBackoff: '1s',
  backoffMultiplier: 2,
  retryableStatusCodes: ['UNAVAILABLE', 'RESOURCE_EXHAUSTED'],
};

// Default gRPC retry throttling (gRFC A6) to circuit-break retries during sustained outages.
const DEFAULT_GRPC_RETRY_THROTTLING = {
  maxTokens: 10,
  tokenRatio: 0.1,
};


const packageDefinition = protoLoader.fromJSON(casProtoRoot, {
  keepCase: true,
  longs: String,
  enums: String,
  defaults: true,
  oneofs: true
});
const pkiProto = grpc.loadPackageDefinition(packageDefinition).goog.gdc.security.pki.v1;

function extractEnum(packageDef, fullName, fallback) {
  const enumObj = {};
  const descriptor = packageDef[fullName];
  if (descriptor && descriptor.type && Array.isArray(descriptor.type.value)) {
    for (const val of descriptor.type.value) {
      enumObj[val.name] = val.number;
    }
    return enumObj;
  }
  return fallback;
}

export const RevocationReason = extractEnum(
  packageDefinition,
  'goog.gdc.security.pki.v1.RevocationReason',
  {
    UNSPECIFIED: 0,
    KEY_COMPROMISE: 1,
    CA_COMPROMISE: 2,
    AFFILIATION_CHANGED: 3,
    SUPERSEDED: 4,
    CESSATION_OF_OPERATION: 5,
    CERTIFICATE_HOLD: 6,
    PRIVILEGE_WITHDRAWN: 7,
    AA_COMPROMISE: 8,
  }
);


/**
 * Parses a certificate validity value into a valid Date.
 * @param {Date|string|number|undefined|null} date - A Date object, an RFC3339 string, or epoch milliseconds.
 * @param {string} fieldName - The name of the field being parsed (used in error messages).
 * @returns {Date|undefined} The parsed Date, or undefined if `date` is not set.
 * @throws {Error} If `date` is set but cannot be parsed into a valid Date.
 */
function parseValidityDate(date, fieldName) {
  if (date === undefined || date === null || date === '') return undefined;
  const d = date instanceof Date ? date : new Date(date);
  if (isNaN(d.getTime())) {
    const shown = date instanceof Date ? String(date) : JSON.stringify(date);
    throw new Error(`Invalid date for '${fieldName}': expected a Date object or an RFC3339 string (e.g., "2024-01-01T00:00:00Z"), got ${shown}`);
  }
  return d;
}

/**
 * Formats a Date object or RFC3339 string into YYYY-MM-DDTHH:mm:ssZ format.
 * @param {Date|string|undefined|null} date - The date to format.
 * @param {string} [fieldName='date'] - The name of the field being formatted (used in error messages).
 * @returns {string|undefined} The formatted date string, or undefined if `date` is not set.
 * @throws {Error} If `date` is set but cannot be parsed into a valid Date.
 */
function formatDateToRFC3339WithoutMs(date, fieldName = 'date') {
  const d = parseValidityDate(date, fieldName);
  if (!d) return undefined;
  return d.toISOString().split('.')[0] + 'Z';
}

function wrapKubeApiClient(apiClient, configuration) {
  return new Proxy(apiClient, {
    get(target, prop, receiver) {
      const origMethod = target[prop];
      if (typeof origMethod === 'function') {
        return function (...args) {
          let param = args[0] || {};
          let options = args[1] || {};

          if (!options.middleware && configuration.middleware && configuration.middleware.length > 0) {
            options = {
              ...options,
              middleware: configuration.middleware,
              middlewareMergeStrategy: 'replace',
            };
          }
          return origMethod.call(target, param, options);
        };
      }
      return Reflect.get(target, prop, receiver);
    }
  });
}

/**
 * Client for interacting with the GDC Certificate Authority Service (CAS).
 */
export class CASClient {
  /**
   * Creates an instance of CASClient.
   * @param {CASClientConfig} config Configuration for the CAS client.
   */
  constructor(config) {
    if (!config.zone) {
      throw new Error('Invalid CASClient configuration: zone is required.');
    }
    if (!config.saFilePath && !config.serviceAccount) {
      throw new Error('Invalid CASClient configuration: Either saFilePath or serviceAccount must be provided.');
    }
    this.config = config;
    this.stsTokenCache = null; // Stores { accessToken, tokenType, expiry }

    // Kube API server config
    this.kubeApiServerUrl = null
    this.kubeConfigInstance = null;
    this.customObjectsApi = null; // Holds the k8s.CustomObjectsApi client
    this.coreV1Api = null;

    // Parameters for STS token acquisition
    this.stsAuthParams = {
      serviceAccountConfig: null,
      stsCaCertContent: null,
      targetAudience: null, // Will be set in init() based on type
    };
  }

  /**
   * Initializes the client by fetching the token and setting up KubeConfig.
   * This should be called after constructing the client.
   * @returns {Promise<void>}
   */
  async init() {
    if (!this.config.saFilePath && !this.config.serviceAccount) {
      throw new Error("Missing required configuration for CASClient: either 'saFilePath' (string) or 'serviceAccount' (object) must be provided for service account authentication.");
    }
    let parsedSaJson;
    if (this.config.serviceAccount) {
      parsedSaJson = this.config.serviceAccount;
    } else {
      const saFileContent = fs.readFileSync(this.config.saFilePath, 'utf8');
      parsedSaJson = JSON.parse(saFileContent);
    }
    this.stsAuthParams.serviceAccountConfig = {
      name: parsedSaJson.name,
      project: parsedSaJson.project,
      tokenUri: parsedSaJson.token_uri,
      privateKeyId: parsedSaJson.private_key_id,
      privateKey: parsedSaJson.private_key,
    };
    this.kubeApiServerUrl = this._getManagementApiUrl(this.stsAuthParams.serviceAccountConfig.tokenUri, this.config.zone);
    this.stsAuthParams.targetAudience = this.kubeApiServerUrl; // STS audience is K8s API server
    // console.log(`CASClient initializing for management plane. Derived Kube API Server URL: ${this.kubeApiServerUrl}`);
    if (this.config.caFilePath) {
      this.stsAuthParams.stsCaCertContent = fs.readFileSync(this.config.caFilePath, 'utf8');
    }
    // console.log(`STS CA certificate loaded from ${this.config.caFilePath}.`);

    // K8s specific setup parameters (only relevant for management plane)
    this.kubeClientParams = {
      clusterName: 'gdc-cluster', // Generic name
      userName: 'cas-user',
      contextName: 'cas-context',
      defaultNamespace: 'default', // Can be overridden by methods
      skipTLSVerify: this.config.skipKubeTLSVerify || false, // Allow overriding via config. Set true only for debugging.
    };

    if (this.config.useGrpc) {
      if (!this.config.casProxyUrl) {
        this.config.casProxyUrl = this._getCasProxyUrl(this.stsAuthParams.serviceAccountConfig.tokenUri, this.config.zone);
      }
      let credentials;
      if (this.stsAuthParams.stsCaCertContent) {
        credentials = grpc.credentials.createSsl(Buffer.from(this.stsAuthParams.stsCaCertContent));
      } else {
        credentials = grpc.credentials.createSsl();
      }
      const targetUrl = this.config.casProxyUrl.replace(/^https?:\/\//, '');
      // Retries are on by default; set config.grpcRetries to false to disable them
      // completely (NO_RETRY), or pass config.grpcRetryPolicy to override individual fields.
      let channelOptions;
      if (this.config.grpcRetries === false) {
        channelOptions = { 'grpc.enable_retries': 0 };
      } else {
        const retryPolicyOverrides = this.config.grpcRetryPolicy
          ? Object.fromEntries(
              Object.entries(this.config.grpcRetryPolicy).filter(([, v]) => v !== undefined)
            )
          : {};
        const retryPolicy = { ...DEFAULT_GRPC_RETRY_POLICY, ...retryPolicyOverrides };
        channelOptions = {
          'grpc.enable_retries': 1,
          // Raise gRFC A6's default cap of 5 attempts when a higher maxAttempts is requested.
          'grpc-node.retry_max_attempts_limit': Number.isInteger(retryPolicy.maxAttempts)
            ? Math.max(5, retryPolicy.maxAttempts)
            : 5,
          'grpc.service_config': JSON.stringify({
            methodConfig: [{
              name: [{ service: 'goog.gdc.security.pki.v1.CertificateAuthorityService' }],
              retryPolicy,
            }],
            retryThrottling: DEFAULT_GRPC_RETRY_THROTTLING,
          }),
        };
      }
      this.grpcClient = new pkiProto.CertificateAuthorityService(targetUrl, credentials, channelOptions);
      this.stsAuthParams.targetAudience = this.config.casProxyUrl;
    }

    await this._ensureValidTokenAndClient(true); // true to force initial fetch
  }

  /**
   * Internal helper to parse the token URI and extract the organization name and domain suffix.
   *
   * @param {string} tokenUriString - The token URI from the service account JSON.
   * @returns {{orgName: string, domainSuffix: string}} The parsed organization name and domain suffix.
   * @throws {Error} If the URL cannot be parsed or derived.
   */
  _parseTokenUri(tokenUriString) {
    const serviceAccountsPrefix = "service-accounts.";

    let tokenHostname;
    try {
      tokenHostname = new URL(tokenUriString).hostname;
    } catch (e) {
      throw new Error(`Invalid tokenUri format: "${tokenUriString}". Error: ${e.message}`);
    }

    let effectiveHostname = tokenHostname;
    if (tokenHostname.startsWith(serviceAccountsPrefix)) {
      effectiveHostname = tokenHostname.substring(serviceAccountsPrefix.length);
    } else {
      throw new Error(
        `Cannot derive API URL from tokenHostname: "${tokenHostname}"`
      );
    }
    // At this point, effectiveHostname is expected to be in the format [OrgName].[DomainSuffix]
    const firstDotIndex = effectiveHostname.indexOf('.');

    // Validate that effectiveHostname is in the format OrgName.DomainSuffix
    // where OrgName and DomainSuffix are non-empty.
    if (firstDotIndex <= 0 || firstDotIndex >= effectiveHostname.length - 1) {
      throw new Error(
        `Cannot derive API URL from effectiveHostname: "${effectiveHostname}"`
      );
    }
    const orgName = effectiveHostname.substring(0, firstDotIndex);
    const domainSuffix = effectiveHostname.substring(firstDotIndex + 1);

    return { orgName, domainSuffix };
  }

  /**
   * Internal helper to generate the Kubernetes management API server URL.
   * Example:
   * tokenUri = "https://service-accounts.gdc1.example.gdc.domain.com/authenticate"
   * zone = "us-west6-a"
   * returns "https://management-kube.apiserver.gdc1.us-west6-a.example.gdc.domain.com"
   *
   * @param {string} tokenUriString - The token URI from the service account JSON.
   * @param {string} zone - The GDC zone name (e.g., "us-west6-a").
   * @returns {string} The constructed management API server URL.
   * @throws {Error} If the URL cannot be derived.
   */
  _getManagementApiUrl(tokenUriString, zone) {
    const managementApiFixedPrefix = "https://management-kube.apiserver.";
    const { orgName, domainSuffix } = this._parseTokenUri(tokenUriString);

    // If the domain suffix already starts with the zone, don't concatenate it again.
    if (domainSuffix.startsWith(zone + '.')) {
      return `${managementApiFixedPrefix}${orgName}.${domainSuffix}`;
    }
    return `${managementApiFixedPrefix}${orgName}.${zone}.${domainSuffix}`;
  }

  /**
   * Internal helper to generate the CAS proxy gRPC URL.
   * Example:
   * tokenUri = "https://service-accounts.gdc1.example.gdc.domain.com/authenticate"
   * zone = "us-west6-a"
   * returns "https://cas.gdc1.us-west6-a.example.gdc.domain.com"
   *
   * @param {string} tokenUriString - The token URI from the service account JSON.
   * @param {string} zone - The GDC zone name (e.g., "us-west6-a").
   * @returns {string} The constructed CAS proxy URL.
   * @throws {Error} If the URL cannot be derived.
   */
  _getCasProxyUrl(tokenUriString, zone) {
    const { orgName, domainSuffix } = this._parseTokenUri(tokenUriString);

    if (domainSuffix.startsWith(zone + '.')) {
      return `https://cas.${orgName}.${domainSuffix}`;
    }
    return `https://cas.${orgName}.${zone}.${domainSuffix}`;
  }

  /**
   * Internal helper to ensure the STS token is valid and the Kubernetes API client is configured.
   * Refreshes the token and reconfigures the client if necessary.
   * @param {boolean} forceRefresh - If true, forces a token refresh even if current token isn't expired.
   * @returns {Promise<void>}
   */
  async _ensureValidTokenAndClient(forceRefresh = false) {
    const now = new Date();
    const expiryBufferMs = 5 * 60 * 1000; // 5 minutes buffer

    if (
      forceRefresh ||
      !this.stsTokenCache ||
      !this.stsTokenCache.expiry ||
      this.stsTokenCache.expiry.getTime() - expiryBufferMs <= now.getTime()
    ) {
      if (this.stsTokenCache && !forceRefresh) {
        // console.log("\nSTS Token expired or nearing expiry. Refreshing for CASClient...");
      } else if (!forceRefresh) {
        // console.log("\nAttempting to get STS token (no valid token in cache for CASClient)...");
      }

      try {
        const newTokenInfo = await getStsToken(
          this.stsAuthParams.serviceAccountConfig,
          this.stsAuthParams.targetAudience,
          this.stsAuthParams.stsCaCertContent
        );
        this.stsTokenCache = newTokenInfo;
        // console.log("\nSuccessfully obtained/refreshed STS token for CASClient:");
        // console.log("Access Token:", this.stsTokenCache.accessToken);
        // console.log("Token Type:", this.stsTokenCache.tokenType);
        // console.log("Expires At:", this.stsTokenCache.expiry.toISOString());

        this.kubeConfigInstance = new k8s.KubeConfig();
        this.kubeConfigInstance.addCluster({
          name: this.kubeClientParams.clusterName,
          server: this.kubeApiServerUrl,
          caFile: this.config.caFilePath,
          skipTLSVerify: this.kubeClientParams.skipTLSVerify,
        });
        this.kubeConfigInstance.addUser({
          name: this.kubeClientParams.userName,
          token: this.stsTokenCache.accessToken,
        });
        this.kubeConfigInstance.addContext({
          name: this.kubeClientParams.contextName,
          cluster: this.kubeClientParams.clusterName,
          user: this.kubeClientParams.userName,
          namespace: this.kubeClientParams.defaultNamespace,
        });
        this.kubeConfigInstance.setCurrentContext(this.kubeClientParams.contextName);

        const middlewares = [];
        if (this.config.keepAlive !== false) {
          if (!this.keepAliveAgent) {
            this.keepAliveAgent = new https.Agent({
              keepAlive: true,
              maxSockets: this.config.maxSockets !== undefined ? this.config.maxSockets : 1000,
              maxFreeSockets: this.config.maxFreeSockets !== undefined ? this.config.maxFreeSockets : 256,
              ca: this.stsAuthParams.stsCaCertContent,
              rejectUnauthorized: !this.kubeClientParams.skipTLSVerify,
            });

            this.keepAliveMiddleware = {
              pre: async (context) => {
                context.setAgent(this.keepAliveAgent);
                return context;
              },
              post: async (response) => response
            };
          }
          middlewares.push(this.keepAliveMiddleware);
        }

        if (this.config.middleware) {
          middlewares.push(...this.config.middleware);
        }

        this.configurationObject = k8s.createConfiguration({
          baseServer: new k8s.ServerConfiguration(this.kubeApiServerUrl, {}),
          authMethods: { default: this.kubeConfigInstance },
          httpApi: this.config.httpApi,
          promiseMiddleware: middlewares,
        });

        this.customObjectsApi = wrapKubeApiClient(new k8s.CustomObjectsApi(this.configurationObject), this.configurationObject);
        this.coreV1Api = wrapKubeApiClient(new k8s.CoreV1Api(this.configurationObject), this.configurationObject);
        //console.log("Kubernetes API clients configured with new STS token.");
      } catch (error) {
        this.stsTokenCache = null;
        this.customObjectsApi = null;
        this.coreV1Api = null;
        // Construct a new error with a more descriptive message
        throw new Error(`Error refreshing STS token or configuring API client for CASClient: ${error.message}`);
      }
    } else {
      // console.log("\nReusing existing Kubernetes API client with a valid STS token for CASClient.");
    }
  }

  // --- CRUD Methods for CertificateRequests ---

  /**
   * Creates a CertificateRequest, waits for it to become Ready,
   * then fetches the corresponding TLS secret and returns its certificate data.
   *
   * @param {string} namespace The namespace for the CertificateRequest.
   * @param {CreateCertificateRequestParams} params The specification for the CertificateRequest.
   * @param {CreateCertificateRequestOptions} [options={}] Optional timeout parameters.
   * @returns {Promise<CreateCertificateRequestResult>} A promise that resolves to an object containing the certificate data:
   *                                                    { certificateRequestName, tlsCrt, caCert }
   * @throws {Error} If the CertificateRequest fails to become Ready within the timeout,
   *                 or if there's an error fetching the secret or certificate data.
   */
  async createCertificateRequest(namespace, params, options = {}) {
    await this._ensureValidTokenAndClient();
    if (!params || !params.certificateAuthorityRef || !params.csr) {
      throw new Error("Missing required parameters for createCertificateRequest: 'params' object with 'certificateAuthorityRef' and 'csr' must be provided.");
    }
    // Generate certificateRequest name if not provided
    const actualCertReqName = params.certReqName ||
      `${CERT_REQ_NAME_PREFIX}${Math.random().toString(36).substring(2, 10)}`; // Generate 11-character random suffix

    // Validate optional validity dates up front so an invalid value fails fast with a clear
    // error (instead of an unhandled TypeError or a NaN timestamp) in both gRPC and KRM modes.
    const notBefore = parseValidityDate(params.notBefore, 'notBefore');
    const notAfter = parseValidityDate(params.notAfter, 'notAfter');

    if (this.config.useGrpc && this.grpcClient) {
      return new Promise((resolve, reject) => {
        const metadata = new grpc.Metadata();
        if (this.stsTokenCache && this.stsTokenCache.accessToken) {
          metadata.add('authorization', `Bearer ${this.stsTokenCache.accessToken}`);
        }

        const grpcReq = {
          parent: `projects/${namespace}`,
          certificate_request: {
            name: actualCertReqName,
            ca_ref: params.certificateAuthorityRef,
            csr: Buffer.from(params.csr, 'base64'),
          }
        };

        if (notBefore) grpcReq.certificate_request.not_before_time = { seconds: Math.floor(notBefore.getTime() / 1000) };
        if (notAfter) grpcReq.certificate_request.not_after_time = { seconds: Math.floor(notAfter.getTime() / 1000) };
        if (params.certificateTemplate) grpcReq.certificate_request.certificate_template = params.certificateTemplate;
        if (params.subjectOverride) grpcReq.certificate_request.subject_override = Buffer.from(params.subjectOverride, 'base64');

        const timeoutMs = options.timeoutMs || DEFAULT_CERT_REQ_TIMEOUT_MS;
        const deadline = new Date(Date.now() + timeoutMs);
        this.grpcClient.CreateCertificateRequest(grpcReq, metadata, { deadline }, (err, response) => {
          if (err) {
            const wrappedError = new Error(`gRPC CreateCertificateRequest failed: ${err.message}`);
            // Expose the gRPC status code so callers can classify the failure
            wrappedError.code = err.code;
            return reject(wrappedError);
          }

          let tlsCrtStr, caCertStr;
          if (Buffer.isBuffer(response.certificate)) {
            tlsCrtStr = response.certificate.toString('utf8');
          } else {
            tlsCrtStr = Buffer.from(response.certificate || '', 'base64').toString('utf8');
          }

          if (Buffer.isBuffer(response.ca_certificate)) {
            caCertStr = response.ca_certificate.toString('utf8');
          } else {
            caCertStr = Buffer.from(response.ca_certificate || '', 'base64').toString('utf8');
          }

          resolve({
            certificateRequestName: actualCertReqName,
            tlsCrt: tlsCrtStr,
            caCert: caCertStr,
          });
        });
      });
    }

    const timeoutMs = options.timeoutMs || DEFAULT_CERT_REQ_TIMEOUT_MS;
    const pollingIntervalMs = options.pollingIntervalMs || DEFAULT_CERT_REQ_POLLING_INTERVAL_MS;

    const spec = {
      certificateAuthorityRef: {
        name: params.certificateAuthorityRef,
        namespace: namespace,
      },
      csr: params.csr,
      certificateTemplate: params.certificateTemplate,
      subjectOverride: params.subjectOverride,
    };
    // Only attach validity bounds when provided; otherwise the CA applies its defaults.
    if (notBefore) spec.notBefore = formatDateToRFC3339WithoutMs(notBefore, 'notBefore');
    if (notAfter) spec.notAfter = formatDateToRFC3339WithoutMs(notAfter, 'notAfter');

    const body = {
      apiVersion: `${CRD_GROUP}/${CRD_VERSION}`,
      kind: 'CertificateRequest',
      metadata: {
        name: actualCertReqName,
        namespace: namespace,
      },
      spec: spec,
    };
    // Set the secret name same as the certificateRequest name
    body.spec.signedCertificateSecret = actualCertReqName;

    // console.log(`Creating CertificateRequest '${actualCertReqName}' in namespace '${namespace}'...`);
    await this.customObjectsApi.createNamespacedCustomObject({
      group: CRD_GROUP,
      version: CRD_VERSION,
      namespace: namespace,
      plural: CERT_REQ_CRD_PLURAL,
      body: body,
    }).catch(e => {
      // If createNamespacedCustomObject fails, throw the error directly
      throw new Error(`Failed to create CertificateRequest '${actualCertReqName}' in namespace '${namespace}': ${e.body ? e.body : e.message}`);
    });

    // console.log(`CertificateRequest '${actualCertReqName}' created. Waiting for it to become Ready...`);

    // Wait for CertificateRequest to be Ready
    const startTime = Date.now();
    let isReady = false;
    let crResponse;
    while (Date.now() - startTime < timeoutMs) {
      // getCertificateRequest will call _ensureValidTokenAndClient again, which is fine.
      crResponse = await this.getCertificateRequest(namespace, actualCertReqName);
      if (crResponse && crResponse.status && crResponse.status.conditions) {
        const readyCondition = crResponse.status.conditions.find(c => c.type === 'Ready');
        if (readyCondition && readyCondition.status === 'True') {
          isReady = true;
          // console.log(`CertificateRequest '${actualCertReqName}' is Ready. Reason: ${readyCondition.reason}`);
          break;
        }
        if (readyCondition && readyCondition.status === 'False' && readyCondition.reason != 'ReconcileBackoff' && readyCondition.reason != 'Reconciling') {
          // certificate request failed on permanent error so we should fail fast
          throw new Error(`Failed to create CertificateRequest '${actualCertReqName}' in namespace '${namespace}'. Current status: ${crResponse.status ? JSON.stringify(crResponse.status) : 'Status not available'}`);
        }
      }
      await new Promise(resolve => setTimeout(resolve, pollingIntervalMs));
    }

    if (!isReady) {
      throw new Error(`Timeout: CertificateRequest '${actualCertReqName}' in namespace '${namespace}' did not become Ready within ${timeoutMs / 1000} seconds. Current status: ${crResponse.status ? JSON.stringify(crResponse.status) : 'Status not available'}`);
    }

    // Fetch the Kubernetes Secret
    // console.log(`Fetching TLS secret '${actualCertReqName}' from namespace '${namespace}'...`);

    let secretResponse;
    try {
      secretResponse = await this.coreV1Api.readNamespacedSecret({ name: actualCertReqName, namespace: namespace });
    } catch (err) {
      throw new Error(`Failed to fetch secret '${actualCertReqName}': ${err.body ? err.body : err.message}`);
    }

    const secretData = secretResponse.data;
    if (!secretData || !secretData['tls.crt'] || !secretData['ca.crt']) {
      throw new Error(`Secret '${actualCertReqName}' does not contain 'tls.crt' or 'ca.crt' data.`);
    }

    const tlsCrt = Buffer.from(secretData['tls.crt'], 'base64').toString('utf8');
    const caCert = Buffer.from(secretData['ca.crt'], 'base64').toString('utf8');

    // console.log(`Successfully fetched and decoded certificate data from secret '${actualCertReqName}'.`);
    return {
      certificateRequestName: actualCertReqName,
      tlsCrt: tlsCrt,
      caCert: caCert,
    };
  }

  /**
   * Creates a request to revoke a certificate.
   * Supports both KRM and gRPC modes.
   *
   * @param {string} namespace The namespace (project) under which revocation is requested.
   * @param {Object} params Parameters for revocation.
   * @param {string} [params.certificate] The PEM-encoded certificate to be revoked (gRPC mode only).
   * @param {string|number} params.reason The reason for revocation.
   * @param {Object} [options={}] Optional timeout parameters.
   * @param {number} [options.timeoutMs] Optional timeout in milliseconds.
   * @param {Object} [params.certificateRequestRef] Reference to the CertificateRequest (KRM mode only).
   * @param {string} [params.revokeReqName] Optional custom name for the RevokeCertificateRequest resource (KRM mode only).
   * @param {Object} [options={}] Optional settings like timeouts (KRM mode only).
   * @returns {Promise<Object>} A promise resolving to the revocation response.
   */
  async createRevokeCertificateRequest(namespace, params, options = {}) {
    await this._ensureValidTokenAndClient();

    if (this.config.useGrpc && this.grpcClient) {
      if (!params || !params.certificate || params.reason === undefined) {
        throw new Error("Missing required parameters for gRPC revocation: 'certificate' and 'reason' must be provided.");
      }

      return new Promise((resolve, reject) => {
        const metadata = new grpc.Metadata();
        if (this.stsTokenCache && this.stsTokenCache.accessToken) {
          metadata.add('authorization', `Bearer ${this.stsTokenCache.accessToken}`);
        }

        const grpcReq = {
          parent: `projects/${namespace}`,
          revoke_certificate_request: {
            certificate: Buffer.from(params.certificate, 'utf8'),
            reason: params.reason,
          }
        };

        const timeoutMs = options.timeoutMs || DEFAULT_REVOKE_REQ_TIMEOUT_MS;
        const deadline = new Date(Date.now() + timeoutMs);

        this.grpcClient.CreateRevokeCertificateRequest(grpcReq, metadata, { deadline }, (err, response) => {
          if (err) {
            // Expose the gRPC status code (see createCertificateRequest above).
            const wrappedError = new Error(`gRPC CreateRevokeCertificateRequest failed: ${err.message}`);
            wrappedError.code = err.code;
            return reject(wrappedError);
          }

          let certStr;
          if (Buffer.isBuffer(response.certificate)) {
            certStr = response.certificate.toString('utf8');
          } else {
            certStr = Buffer.from(response.certificate || '', 'base64').toString('utf8');
          }

          resolve({
            certificate: certStr,
            reason: response.reason,
          });
        });
      });
    }

    // KRM Mode
    if (!params || !params.certificateRequestRef || params.reason === undefined) {
      throw new Error("Missing required parameters for KRM revocation: 'certificateRequestRef' and 'reason' must be provided.");
    }

    const actualRevokeReqName = params.revokeReqName ||
      `cas-sdk-revoke-${Math.random().toString(36).substring(2, 10)}`;

    const body = {
      apiVersion: `${CRD_GROUP}/${CRD_VERSION}`,
      kind: 'RevokeCertificateRequest',
      metadata: {
        name: actualRevokeReqName,
        namespace: namespace,
      },
      spec: {
        certificateRequestRef: {
          name: params.certificateRequestRef.name,
          namespace: params.certificateRequestRef.namespace,
        },
        reason: (() => {
          let reasonStr;
          if (typeof params.reason === 'number' || !isNaN(Number(params.reason))) {
            const reasonNum = Number(params.reason);
            const foundKey = Object.keys(RevocationReason).find(key => RevocationReason[key] === reasonNum);
            reasonStr = foundKey || params.reason.toString();
          } else {
            reasonStr = params.reason.toString();
          }
          return reasonStr.toLowerCase().replace(/_/g, '');
        })(),
      },
    };

    await this.customObjectsApi.createNamespacedCustomObject({
      group: CRD_GROUP,
      version: CRD_VERSION,
      namespace: namespace,
      plural: REVOKE_REQ_CRD_PLURAL,
      body: body,
    }).catch(e => {
      throw new Error(`Failed to create RevokeCertificateRequest '${actualRevokeReqName}' in namespace '${namespace}': ${e.body ? e.body : e.message}`);
    });

    const timeoutMs = options.timeoutMs || DEFAULT_CERT_REQ_TIMEOUT_MS;
    const pollingIntervalMs = options.pollingIntervalMs || DEFAULT_CERT_REQ_POLLING_INTERVAL_MS;

    const startTime = Date.now();
    let isReady = false;
    let crResponse;
    while (Date.now() - startTime < timeoutMs) {
      crResponse = await this.getRevokeCertificateRequest(namespace, actualRevokeReqName);
      if (crResponse && crResponse.status && crResponse.status.conditions) {
        const readyCondition = crResponse.status.conditions.find(c => c.type === 'Ready');
        if (readyCondition && readyCondition.status === 'True') {
          isReady = true;
          break;
        }
        if (readyCondition && readyCondition.status === 'False' && readyCondition.reason !== 'ReconcileBackoff' && readyCondition.reason !== 'Reconciling') {
          throw new Error(`Failed to revoke certificate. Current status: ${crResponse.status ? JSON.stringify(crResponse.status) : 'Status not available'}`);
        }
      }
      await new Promise(resolve => setTimeout(resolve, pollingIntervalMs));
    }

    if (!isReady) {
      throw new Error(`Timeout: RevokeCertificateRequest '${actualRevokeReqName}' did not become Ready within ${timeoutMs / 1000} seconds. Current status: ${crResponse.status ? JSON.stringify(crResponse.status) : 'Status not available'}`);
    }

    return {
      revokeCertificateRequestName: actualRevokeReqName,
      reason: params.reason,
    };
  }

  /**
   * Gets a specific CertificateRequest.
   * @param {string} namespace The namespace of the CertificateRequest.
   * @param {string} name The name of the CertificateRequest.
   * @returns {Promise<any>} The CertificateRequest custom object.
   */
  async getCertificateRequest(namespace, name) {
    await this._ensureValidTokenAndClient();
    return this.customObjectsApi.getNamespacedCustomObject({
      group: CRD_GROUP,
      version: CRD_VERSION,
      namespace: namespace,
      plural: CERT_REQ_CRD_PLURAL,
      name: name,
    });
  }

  /**
   * Lists all CertificateRequests in a given namespace.
   * @param {string} namespace The namespace to list CertificateRequests from.
   * @returns {Promise<any>} A list of CertificateRequest custom objects.
   */
  async listCertificateRequests(namespace) {
    await this._ensureValidTokenAndClient();
    return this.customObjectsApi.listNamespacedCustomObject({
      group: CRD_GROUP,
      version: CRD_VERSION,
      namespace: namespace,
      plural: CERT_REQ_CRD_PLURAL,
    });
  }

  /**
   * Deletes a specific CertificateRequest.
   * @param {string} namespace The namespace of the CertificateRequest.
   * @param {string} name The name of the CertificateRequest to delete.
   * @returns {Promise<any>} The status of the deletion.
   */
  async deleteCertificateRequest(namespace, name) {
    await this._ensureValidTokenAndClient();
    return this.customObjectsApi.deleteNamespacedCustomObject({
      group: CRD_GROUP,
      version: CRD_VERSION,
      namespace: namespace,
      plural: CERT_REQ_CRD_PLURAL,
      name: name,
    });
  }

  /**
   * Retrieves a CertificateAuthority's KRM resource and public certificate.
   *
   * @param {string} namespace The namespace of the CertificateAuthority.
   * @param {string} name The name of the CertificateAuthority.
   * @returns {Promise<CertificateAuthorityInfoResult>} A promise that resolves to an object containing:
   *                                                    - certificateAuthority: The full KRM object for the CA (spec and status).
   *                                                    - caCertificate: The PEM-encoded CA certificate and intermediate CA certificates in the trust chain.
   *                                                    - rootCACertificate: The PEM-encoded root CA certificate in the trust chain.
   * @throws {Error} If the CertificateAuthority or its secret cannot be found, or if required data is missing.
   */
  async getCertificateAuthority(namespace, name) {
    await this._ensureValidTokenAndClient();

    if (!namespace || !name) {
      throw new Error("Missing required parameters for getCertificateAuthority: 'namespace' and 'name' must be provided.");
    }

    // 1. Get the CertificateAuthority KRM object
    let caKrm;
    try {
      const caKrmResponse = await this.customObjectsApi.getNamespacedCustomObject({
        group: CRD_GROUP,
        version: CRD_VERSION,
        namespace: namespace,
        plural: CA_CRD_PLURAL,
        name: name,
      });
      caKrm = caKrmResponse;
    } catch (err) {
      throw new Error(`Failed to get CertificateAuthority '${name}' in namespace '${namespace}': ${err.body ? err.body : err.message}`);
    }

    // 2. Get the PEM encoded CA certificate from the referenced secret in the status
    const secretName = caKrm?.spec?.secretConfig?.secretName;
    if (!secretName) {
      throw new Error(`CertificateAuthority '${name}' does not have a 'spec.secretConfig.secretName'.`);
    }
    const secretResponse = await this.coreV1Api.readNamespacedSecret({ name: secretName, namespace: namespace });
    const secretData = secretResponse.data;
    if (!secretData || !secretData['tls.crt'] || !secretData['ca.crt']) {
      throw new Error(`CA Secret '${secretName}' does not contain 'tls.crt' or 'ca.crt' data.`);
    }

    const caCertificate = Buffer.from(secretData['tls.crt'], 'base64').toString('utf8');
    const rootCACertificate = Buffer.from(secretData['ca.crt'], 'base64').toString('utf8');

    // 3. Return the combined information
    return {
      certificateAuthority: caKrm,
      caCertificate: caCertificate,
      rootCACertificate: rootCACertificate,
    };
  }

  /**
   * Gets a specific RevokeCertificateRequest.
   * @param {string} namespace The namespace.
   * @param {string} name The name.
   * @returns {Promise<any>} The RevokeCertificateRequest custom object.
   */
  async getRevokeCertificateRequest(namespace, name) {
    await this._ensureValidTokenAndClient();
    return this.customObjectsApi.getNamespacedCustomObject({
      group: CRD_GROUP,
      version: CRD_VERSION,
      namespace: namespace,
      plural: REVOKE_REQ_CRD_PLURAL,
      name: name,
    });
  }

  /**
   * Deletes a specific RevokeCertificateRequest.
   * @param {string} namespace The namespace.
   * @param {string} name The name to delete.
   * @returns {Promise<any>} The status of the deletion.
   */
  async deleteRevokeCertificateRequest(namespace, name) {
    await this._ensureValidTokenAndClient();
    return this.customObjectsApi.deleteNamespacedCustomObject({
      group: CRD_GROUP,
      version: CRD_VERSION,
      namespace: namespace,
      plural: REVOKE_REQ_CRD_PLURAL,
      name: name,
    });
  }

  /**
   * Lists all RevokeCertificateRequests in a given namespace.
   * @param {string} namespace The namespace.
   * @returns {Promise<any>} List of RevokeCertificateRequest custom objects.
   */
  async listRevokeCertificateRequests(namespace) {
    await this._ensureValidTokenAndClient();
    return this.customObjectsApi.listNamespacedCustomObject({
      group: CRD_GROUP,
      version: CRD_VERSION,
      namespace: namespace,
      plural: REVOKE_REQ_CRD_PLURAL,
    });
  }
}
