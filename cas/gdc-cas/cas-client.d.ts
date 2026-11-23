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

export interface ServiceAccount {
  type: string;
  format_version: string;
  project: string;
  private_key_id: string;
  private_key: string;
  name: string;
  token_uri: string;
}
/**
 * Configuration for the CASClient.
 */
export interface CASClientConfig {
  /** Optional. Path to the service account JSON file. */
  saFilePath?: string;
  /** Optional. The content of the service account JSON. */
  serviceAccount?: ServiceAccount;
  /** Optional. Path to the CA certificate file for STS and Kubernetes API server. If not provided the system truststore is used*/
  caFilePath?: string;
  /** The GDC zone (e.g., "us-west6-a"). */
  zone: string;
  /** Optional. If true, skips TLS verification for the Kubernetes API server. Defaults to false. Use for debug only. */
  skipKubeTLSVerify?: boolean;
  /** Optional. If set to false, disables the default Keep-Alive agent behavior. Defaults to true. */
  keepAlive?: boolean;
  /** Optional. The maximum number of sockets to allow per host for the Keep-Alive agent. Defaults to 1000. */
  maxSockets?: number;
  /** Optional. The maximum number of sockets to leave open in a free state for the Keep-Alive agent. Defaults to 256. */
  maxFreeSockets?: number;
  /** Optional. The http library to use for making requests. Must implement the HttpLibrary interface of @kubernetes/client-node. If not provided, IsomorphicFetchHttpLibrary will be used. */
  httpApi?: any;
  /** Optional. Middleware array to apply to requests. If not provided, no middleware will be applied. */
  middleware?: any[];
  /** Optional. If true, uses direct gRPC calls to the CAS proxy instead of creating KRM resources. Defaults to false. */
  useGrpc?: boolean;
  /** Optional. The URL of the CAS proxy. If useGrpc is true and this is not provided, it is automatically derived from the service account's token URI. */
  casProxyUrl?: string;
}

export enum RevocationReason {
  UNSPECIFIED = 0,
  KEY_COMPROMISE = 1,
  CA_COMPROMISE = 2,
  AFFILIATION_CHANGED = 3,
  SUPERSEDED = 4,
  CESSATION_OF_OPERATION = 5,
  CERTIFICATE_HOLD = 6,
  PRIVILEGE_WITHDRAWN = 7,
  AA_COMPROMISE = 8,
}

export interface CertificateRequestReference {
  /** Name of the CertificateRequest resource. */
  name: string;
  /** Namespace of the CertificateRequest resource. */
  namespace: string;
}

/**
 * Parameters for revoking a certificate.
 */
export interface CreateRevokeCertificateRequestParams {
  /** Required for gRPC mode. The PEM-encoded certificate to be revoked. */
  certificate?: string;
  /** The reason for revocation. */
  reason: RevocationReason | string;
  /** Required for KRM mode. Reference to the CertificateRequest to revoke. */
  certificateRequestRef?: CertificateRequestReference;
  /** Optional for KRM mode. Desired name for the RevokeCertificateRequest custom resource. */
  revokeReqName?: string;
}

/**
 * Result of a certificate revocation request.
 */
export interface CreateRevokeCertificateRequestResult {
  /** The reason for revocation. */
  reason: RevocationReason | string;
  /** KRM mode: Name of the created RevokeCertificateRequest custom resource. */
  revokeCertificateRequestName?: string;
  /** gRPC mode: The PEM-encoded certificate that was requested to be revoked. */
  certificate?: string;
}

/**
 * Optional settings for the createRevokeCertificateRequest operation.
 */
export interface CreateRevokeCertificateRequestOptions {
  /** Optional. Timeout in milliseconds to wait for the revocation request. Defaults to 60000ms. */
  timeoutMs?: number;
  /** Optional. Interval in milliseconds for polling the RevokeCertificateRequest status. Defaults to 200ms. */
  pollingIntervalMs?: number;
}

/**

 * Parameters for creating a CertificateRequest.
 */
export interface CreateCertificateRequestParams {
  /** Name of the CertificateAuthority resource to use for signing. */
  certificateAuthorityRef: string;
  /** The Certificate Signing Request (CSR). The CSR should be a base64 encoded string of the PEM-encoded CSR. */
  csr: string;
  /** Optional. Desired name for the CertificateRequest custom resource. If not provided, a name will be generated. */
  certReqName?: string;
  /** Optional. The 'not before' time for the certificate, as a Date object or an RFC3339 string (e.g., "2023-01-01T00:00:00Z"). If not set, the CA will use its default. */
  notBefore?: Date | string;
  /** Optional. The 'not after' time for the certificate, as a Date object or an RFC3339 string (e.g., "2024-01-01T00:00:00Z"). If not set, the CA will use its default, respecting its maximum validity period. */
  notAfter?: Date | string;
  /** Optional (Supported in the BigBear release). A template used to issue the certificate. */
  certificateTemplate?:
  | "endEntityClientAuthCertificate"
  | "endEntityServerAuthCertificate"
  | "blankSubCACertificate_PathLen0_CSRPassthrough"
  | "blankSubCACertificate_PathLen1_CSRPassthrough";
  /** Optional (Supported in the BigBear release). SubjectOverride is a base64 encoded string of a raw, ASN.1 DER-encoded X.509 subject. If set, this raw subject will be used instead of the raw subject in the CSR. */
  subjectOverride?: string;
}

/**
 * Optional settings for the createCertificateRequest operation.
 */
export interface CreateCertificateRequestOptions {
  /** Optional. Timeout in milliseconds to wait for the CertificateRequest to become Ready. Defaults to 10000ms. */
  timeoutMs?: number;
  /** Optional. Interval in milliseconds for polling the CertificateRequest status. Defaults to 200ms. */
  pollingIntervalMs?: number;
}

/**
 * Result of a successful certificate request creation.
 */
export interface CreateCertificateRequestResult {
  /** The name of the created CertificateRequest custom resource. */
  certificateRequestName: string;
  /** The PEM-encoded signed TLS certificate. */
  tlsCrt: string;
  /** The PEM-encoded CA certificate that signed the TLS certificate. */
  caCert: string;
}

/**
 * Contains information about a Certificate Authority.
 */
export interface CertificateAuthorityInfoResult {
  /** The full Kubernetes Resource Model (KRM) object for the Certificate Authority. */
  certificateAuthority: any;
  /**
   * The PEM-encoded public certificate of the Certificate Authority.
   * This may also contain all the intermedicate CA certificates in the certificate chain.
   */
  caCertificate: string;
  /** The PEM-encoded root CA certificate of the Certificate Authority. */
  rootCACertificate: string;
}

/**
 * Result of a CA health check.
 */
export interface CertificateAuthorityHealthResult {
  /** The overall health status of the CA. */
  status: string;
  /** Additional details about the health check. */
}

/**
 * Client for interacting with the GDC Certificate Authority Service (CAS)
 */
export declare class CASClient {
  /**
   * Creates an instance of CASClient.
   * @param config Configuration for the CAS client.
   */
  constructor(config: CASClientConfig);

  /**
   * Initializes the client. This typically involves setting up authentication
   * (e.g., fetching an STS token) and configuring the Kubernetes API client.
   * This method must be called before other operations.
   */
  init(): Promise<void>;

  /**
   * Creates a CertificateRequest custom resource, waits for it to become Ready,
   * then fetches the corresponding TLS secret and returns its certificate data.
   * @param namespace The Kubernetes namespace for the CertificateRequest.
   * @param params The specification for the CertificateRequest.
   * @param options Optional settings for the request, like timeouts.
   * @returns A promise that resolves to an object containing the certificate data.
   */
  createCertificateRequest(
    namespace: string,
    params: CreateCertificateRequestParams,
    options?: CreateCertificateRequestOptions
  ): Promise<CreateCertificateRequestResult>;

  /**
   * Creates a request to revoke a certificate.
   * Supports both KRM and gRPC modes.
   * @param namespace The namespace of the certificate.
   * @param params The specification for the revocation.
   * @param options Optional settings for KRM mode (e.g. timeouts).
   * @returns A promise that resolves to the revocation result.
   */
  createRevokeCertificateRequest(
    namespace: string,
    params: CreateRevokeCertificateRequestParams,
    options?: CreateRevokeCertificateRequestOptions
  ): Promise<CreateRevokeCertificateRequestResult>;

  /**
   * Retrieves a specific RevokeCertificateRequest custom resource.
   * @param namespace The Kubernetes namespace.
   * @param name The name of the RevokeCertificateRequest.
   * @returns A promise that resolves to the RevokeCertificateRequest custom object.
   */
  getRevokeCertificateRequest(
    namespace: string,
    name: string
  ): Promise<any>;

  /**
   * Deletes a specific RevokeCertificateRequest custom resource.
   * @param namespace The Kubernetes namespace.
   * @param name The name of the RevokeCertificateRequest to delete.
   * @returns A promise that resolves to the deletion status.
   */
  deleteRevokeCertificateRequest(
    namespace: string,
    name: string
  ): Promise<any>;

  /**
   * Lists all RevokeCertificateRequest custom resources in a given namespace.
   * @param namespace The Kubernetes namespace.
   * @returns A promise that resolves to a list of RevokeCertificateRequest custom objects.
   */
  listRevokeCertificateRequests(
    namespace: string
  ): Promise<any>;

  /**
   * Retrieves a specific CertificateRequest custom resource.
   * @param namespace The Kubernetes namespace of the CertificateRequest.
   * @param name The name of the CertificateRequest.
   * @returns A promise that resolves to the CertificateRequest custom object.
   */
  getCertificateRequest(
    namespace: string,
    name: string
  ): Promise<any>;

  /**
   * Lists all CertificateRequest custom resources in a given namespace.
   * @param namespace The Kubernetes namespace to list CertificateRequests from.
   * @returns A promise that resolves to a list of CertificateRequest custom objects.
   */
  listCertificateRequests(
    namespace: string
  ): Promise<any>;

  /**
   * Deletes a specific CertificateRequest custom resource.
   * @param namespace The Kubernetes namespace of the CertificateRequest.
   * @param name The name of the CertificateRequest to delete.
   * @returns A promise that resolves to the CertificateRequest custom object.
   */
  deleteCertificateRequest(
    namespace: string,
    name: string
  ): Promise<any>;

  /**
   * Retrieves a CertificateAuthority's KRM resource and CA certificate.
   * @param namespace The namespace of the CertificateAuthority.
   * @param name The name of the CertificateAuthority.
   * @returns A promise that resolves to an object containing the CA's KRM resource and certificates.
   */
  getCertificateAuthority(
    namespace: string,
    name: string
  ): Promise<CertificateAuthorityInfoResult>;
}
