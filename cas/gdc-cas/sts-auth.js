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

/**
 * sts-auth.js
 *
 * This module provides functions to generate a self-signed JWT using a service
 * account's private key and then exchange it for an STS (Security Token Service) token.
 */

import jwt from 'jsonwebtoken';
import axios from 'axios'; 
import https from 'https';

// Constants for OAuth 2.0 Token Exchange (RFC 8693)
const TOKEN_EXCHANGE_GRANT_TYPE = "urn:ietf:params:oauth:token-type:token-exchange";
const REQUESTED_TOKEN_TYPE_ACCESS_TOKEN = "urn:ietf:params:oauth:token-type:access_token";
const SUBJECT_TOKEN_TYPE_SERVICE_ACCOUNT_JWT = "urn:k8s:params:oauth:token-type:serviceaccount"; // Matches Go code's serviceAccoutTokenType

/**
 * @typedef {Object} ServiceAccountConfig
 * @property {string} name - Service account name (e.g., "my-sa").
 * @property {string} project - Project ID associated with the service account.
 * @property {string} tokenUri - The OAuth 2.0 Token URI. This is used as:
 *                              1. The audience ('aud' claim) for the self-signed JWT.
 *                              2. The HTTP endpoint for the STS token exchange.
 * @property {string} privateKeyId - The ID of the private key.
 * @property {string} privateKey - The private key in PEM format (string).
 */

/**
 * @typedef {Object} StsToken
 * @property {string} accessToken - The STS access token.
 * @property {Date} expiry - The expiry date and time of the STS token.
 * @property {string} tokenType - The type of the token (e.g., "Bearer").
 */

/**
 * Signs a JWT using the service account's private key.
 * The JWT is intended for exchange with an STS server.
 *
 * @param {ServiceAccountConfig} saConfig - Configuration for the service account.
 * @returns {Promise<string>} A promise that resolves to the signed JWT string.
 * @throws {Error} If service account configuration is invalid or JWT signing fails.
 */
async function signSelfSignedJwt(saConfig) {
    const { name, project, privateKeyId, privateKey, tokenUri } = saConfig;

    if (!name || !project || !privateKeyId || !privateKey || !tokenUri) {
        throw new Error("Invalid service account configuration: missing one or more required fields (name, project, privateKeyId, privateKey, tokenUri).");
    }

    // The issuer and subject for the JWT are typically in the format: system:serviceaccount:<project>:<name>
    const issSubValue = `system:serviceaccount:${project}:${name}`;
    const nowInSeconds = Math.floor(Date.now() / 1000);
    // The self-signed JWT typically has a shorter lifespan, e.g., 1 hour, as it's exchanged quickly.
    // The Go code uses 24 hours for the JWT, let's match that for consistency.
    const expirationInSeconds = nowInSeconds + (24 * 60 * 60);

    const payload = {
        iss: issSubValue,
        sub: issSubValue,
        aud: tokenUri, // Audience for the self-signed JWT is the STS token URI
        iat: nowInSeconds,
        exp: expirationInSeconds,
    };

    const header = {
        kid: privateKeyId,
        typ: "JWT", // Standard type header
        alg: "ES256" // Assuming ES256, as used in the Go example's Tink configuration
    };

    try {
        const signedJwt = jwt.sign(payload, privateKey, {
            algorithm: 'ES256', // Ensure this matches your key type and STS server expectation
            header: header
        });
        return signedJwt;
    } catch (error) {
        throw new Error(`Failed to sign JWT: ${error.message}`);
    }
}

/**
 * Exchanges a self-signed JWT for an STS token.
 *
 * @param {string} selfSignedJwt - The self-signed JWT.
 * @param {string} stsTokenExchangeUrl - The URL of the STS token exchange endpoint.
 * @param {string} targetStsAudience - The desired audience for the STS token.
 * @param {string} [caCertPem] - Optional: CA certificate in PEM format (string) for validating the STS server's certificate.
 * @returns {Promise<StsToken>} A promise that resolves to an object containing the STS access token and its expiry.
 * @throws {Error} If the token exchange fails or the response is invalid.
 */
async function exchangeJwtForStsToken(selfSignedJwt, stsTokenExchangeUrl, targetStsAudience, caCertPem) {
    const requestData = {
        grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
        audience: targetStsAudience, // Audience for the *requested* STS token
        requested_token_type: REQUESTED_TOKEN_TYPE_ACCESS_TOKEN,
        subject_token: selfSignedJwt,
        subject_token_type: SUBJECT_TOKEN_TYPE_SERVICE_ACCOUNT_JWT,
    };

    const axiosConfig = {
        headers: {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
        },
    };

    if (caCertPem) {
        const httpsAgent = new https.Agent({
            ca: caCertPem,
        });
        axiosConfig.httpsAgent = httpsAgent;
    }

    const maxRetries = 3;
    const initialRetryDelayMs = 1000; // Initial delay of 1 second

    for (let attempt = 1; attempt <= maxRetries; attempt++) {
        try {
            const response = await axios.post(stsTokenExchangeUrl, requestData, axiosConfig);

            // axios typically throws for non-2xx status codes, but an explicit check is good practice.
            if (response.status !== 200) {
                let errorDetails = `Status: ${response.status}`;
                if (response.data) {
                    errorDetails += `, Body: ${typeof response.data === 'string' ? response.data : JSON.stringify(response.data)}`;
                }
                throw new Error(`STS token exchange failed. ${errorDetails}`);
            }

            const tokenResponse = response.data;
            if (!tokenResponse.access_token || typeof tokenResponse.expires_in !== 'number') {
                throw new Error('Invalid STS token response format: access_token or expires_in missing or invalid.');
            }

            const expiryDate = new Date(Date.now() + tokenResponse.expires_in * 1000);

            return {
                accessToken: tokenResponse.access_token,
                tokenType: tokenResponse.token_type || "Bearer", // STS usually returns "Bearer"
                expiry: expiryDate,
            };
        } catch (error) {
            // console.warn(`Attempt ${attempt} of ${maxRetries} failed for STS token exchange: ${error.message}`);
            if (attempt < maxRetries) {
                const delayMs = initialRetryDelayMs * Math.pow(2, attempt - 1); // Exponential backoff
                // console.warn(`Retrying in ${delayMs / 1000} seconds...`);
                await new Promise(resolve => setTimeout(resolve, delayMs));
            } else {
                // Last attempt failed, rethrow a comprehensive error
                if (axios.isAxiosError(error)) {
                    let message = `STS token exchange HTTP error after ${maxRetries} attempts: ${error.message}.`;
                    if (error.response) {
                        message += ` Status: ${error.response.status}. Response: ${JSON.stringify(error.response.data)}.`;
                    }
                    throw new Error(message);
                }
                // For other errors (e.g., validation errors thrown above, or unexpected errors)
                throw new Error(`STS token exchange failed after ${maxRetries} attempts: ${error.message}`);
            }
        }
    }
    // This line should theoretically be unreachable if the loop logic is correct,
    // as the last attempt will throw an error.
    throw new Error(`STS token exchange failed definitively after ${maxRetries} attempts.`);
}

/**
 * Main function to orchestrate JWT signing and STS token exchange.
 *
 * @param {ServiceAccountConfig} saConfig - Configuration for the service account.
 * @param {string} targetStsAudience - The desired audience for the final STS token.
 * @param {string} [caCertPem] - Optional: CA certificate in PEM format for the STS server.
 * @returns {Promise<StsToken>} A promise that resolves to the STS token.
 */
async function getStsToken(saConfig, targetStsAudience, caCertPem) {
    if (!saConfig) {
        throw new Error("Service account configuration (saConfig) is required.");
    }
    if (!targetStsAudience) {
        throw new Error("Target STS audience (targetStsAudience) is required.");
    }

    // Step 1: Generate the self-signed JWT.
    // The saConfig.tokenUri is used as the audience for this JWT.
    const selfSignedJwt = await signSelfSignedJwt(saConfig);

    // Step 2: Exchange the self-signed JWT for an STS token.
    // The saConfig.tokenUri is also the endpoint for the STS exchange.
    // The targetStsAudience is the audience for the *final* STS token.
    return await exchangeJwtForStsToken(selfSignedJwt, saConfig.tokenUri, targetStsAudience, caCertPem);
}

export {
    getStsToken,
};
