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

/*eslint-disable block-scoped-var, id-length, no-control-regex, no-magic-numbers, no-mixed-operators, no-prototype-builtins, no-redeclare, no-shadow, no-var, sort-vars, default-case, jsdoc/require-param*/
import $protobuf from "protobufjs/light.js";

const $root = ($protobuf.roots["default"] || ($protobuf.roots["default"] = new $protobuf.Root()))
.addJSON({
  "goog": {
    "nested": {
      "gdc": {
        "nested": {
          "security": {
            "nested": {
              "pki": {
                "nested": {
                  "v1": {
                    "options": {
                      "go_package": "github.com/googlecloudplatform/google-distributed-cloud-apis/pkg/apis/public/security/pki/v1/proto;pki",
                      "java_outer_classname": "CasProto",
                      "java_multiple_files": true,
                      "java_package": "goog.gdc.security.pki.v1"
                    },
                    "nested": {
                      "CertificateAuthorityService": {
                        "methods": {
                          "CreateCertificateRequest": {
                            "requestType": "CreateCertificateRequestRequest",
                            "responseType": "CertificateRequest"
                          },
                          "CreateRevokeCertificateRequest": {
                            "requestType": "CreateRevokeCertificateRequestRequest",
                            "responseType": "RevokeCertificateRequest"
                          }
                        }
                      },
                      "CreateCertificateRequestRequest": {
                        "fields": {
                          "parent": {
                            "type": "string",
                            "id": 1
                          },
                          "certificate_request": {
                            "type": "CertificateRequest",
                            "id": 2
                          }
                        }
                      },
                      "CertificateRequest": {
                        "fields": {
                          "name": {
                            "type": "string",
                            "id": 1
                          },
                          "ca_ref": {
                            "type": "string",
                            "id": 2
                          },
                          "csr": {
                            "type": "bytes",
                            "id": 4
                          },
                          "not_before_time": {
                            "type": "google.protobuf.Timestamp",
                            "id": 5
                          },
                          "not_after_time": {
                            "type": "google.protobuf.Timestamp",
                            "id": 6
                          },
                          "certificate_template": {
                            "type": "string",
                            "id": 7
                          },
                          "subject_override": {
                            "type": "bytes",
                            "id": 8
                          },
                          "certificate": {
                            "type": "bytes",
                            "id": 20
                          },
                          "ca_certificate": {
                            "type": "bytes",
                            "id": 21
                          }
                        }
                      },
                      "CreateRevokeCertificateRequestRequest": {
                        "fields": {
                          "parent": {
                            "type": "string",
                            "id": 1
                          },
                          "revoke_certificate_request": {
                            "type": "RevokeCertificateRequest",
                            "id": 2
                          }
                        }
                      },
                      "RevokeCertificateRequest": {
                        "fields": {
                          "certificate": {
                            "type": "bytes",
                            "id": 1
                          },
                          "reason": {
                            "type": "RevocationReason",
                            "id": 2
                          }
                        }
                      },
                      "RevocationReason": {
                        "values": {
                          "UNSPECIFIED": 0,
                          "KEY_COMPROMISE": 1,
                          "CA_COMPROMISE": 2,
                          "AFFILIATION_CHANGED": 3,
                          "SUPERSEDED": 4,
                          "CESSATION_OF_OPERATION": 5,
                          "CERTIFICATE_HOLD": 6,
                          "PRIVILEGE_WITHDRAWN": 7,
                          "AA_COMPROMISE": 8
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  },
  "google": {
    "nested": {
      "protobuf": {
        "nested": {
          "Timestamp": {
            "fields": {
              "seconds": {
                "type": "int64",
                "id": 1
              },
              "nanos": {
                "type": "int32",
                "id": 2
              }
            }
          }
        }
      }
    }
  }
});
export const goog = $root.get("goog");
export const google = $root.get("google");

export {
  /**
   * Reflected root namespace.
   * @type {$protobuf.Root}
   */
  $root as default
};
