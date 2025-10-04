;; Identity Vault Contract - Decentralized Identity Management
;; Stores encrypted identity credentials with user-controlled access permissions

;; Constants
(define-constant CONTRACT-OWNER tx-sender)
(define-constant ERR-UNAUTHORIZED (err u100))
(define-constant ERR-INVALID-CREDENTIAL (err u101))
(define-constant ERR-CREDENTIAL-EXISTS (err u102))
(define-constant ERR-CREDENTIAL-NOT-FOUND (err u103))
(define-constant ERR-INVALID-PERMISSION (err u104))
(define-constant ERR-ACCESS-DENIED (err u105))
(define-constant ERR-INVALID-ISSUER (err u106))
(define-constant ERR-CREDENTIAL-REVOKED (err u107))
(define-constant ERR-INVALID-TIMESTAMP (err u108))

;; Data Variables
(define-data-var next-credential-id uint u1)
(define-data-var next-issuer-id uint u1)
(define-data-var vault-paused bool false)
(define-data-var total-credentials uint u0)
(define-data-var total-users uint u0)

;; Data Maps
;; User identity registry
(define-map user-identities principal {
    created-at: uint,
    updated-at: uint,
    is-verified: bool,
    credential-count: uint,
    public-key: (buff 33)
})

;; Credential storage with encryption metadata  
(define-map credentials uint {
    owner: principal,
    issuer: principal,
    credential-type: (string-ascii 64),
    encrypted-data-hash: (buff 32),
    metadata-hash: (buff 32),
    issued-at: uint,
    expires-at: uint,
    is-revoked: bool,
    revoked-at: (optional uint),
    attestation-count: uint
})

;; Access permissions for credential sharing
(define-map credential-permissions { credential-id: uint, verifier: principal } {
    granted-at: uint,
    expires-at: uint,
    permission-type: (string-ascii 32),
    access-count: uint,
    last-accessed: (optional uint)
})

;; Trusted issuer registry
(define-map trusted-issuers principal {
    issuer-id: uint,
    name: (string-ascii 128),
    registered-at: uint,
    is-active: bool,
    issued-credentials: uint,
    revoked-credentials: uint,
    public-key: (buff 33)
})

;; Credential attestations from multiple sources
(define-map attestations { credential-id: uint, attester: principal } {
    attestation-hash: (buff 32),
    attested-at: uint,
    confidence-score: uint,
    is-valid: bool
})

;; Authentication sessions
(define-map auth-sessions principal {
    session-id: (buff 16),
    created-at: uint,
    expires-at: uint,
    is-active: bool,
    authentication-method: (string-ascii 32)
})

;; Private Functions
(define-private (has-valid-identity (user principal))
    (is-some (map-get? user-identities user))
)

(define-private (is-authorized-issuer (issuer principal))
    (match (map-get? trusted-issuers issuer)
        issuer-data (get is-active issuer-data)
        false
    )
)

(define-private (get-next-credential-id)
    (let ((current-id (var-get next-credential-id)))
        (var-set next-credential-id (+ current-id u1))
        current-id
    )
)

(define-private (is-credential-owner (credential-id uint) (user principal))
    (match (map-get? credentials credential-id)
        credential (is-eq (get owner credential) user)
        false
    )
)

(define-private (has-access-permission (credential-id uint) (verifier principal))
    (match (map-get? credential-permissions { credential-id: credential-id, verifier: verifier })
        permission (and 
            (< stacks-block-height (get expires-at permission))
            (> (get expires-at permission) u0)
        )
        false
    )
)

;; Public Functions
(define-public (create-identity (public-key (buff 33)))
    (let ((user tx-sender))
        (asserts! (not (has-valid-identity user)) ERR-CREDENTIAL-EXISTS)
        (asserts! (is-eq (len public-key) u33) ERR-INVALID-CREDENTIAL)
        (asserts! (not (var-get vault-paused)) ERR-ACCESS-DENIED)
        (map-set user-identities user {
            created-at: stacks-block-height,
            updated-at: stacks-block-height,
            is-verified: false,
            credential-count: u0,
            public-key: public-key
        })
        (var-set total-users (+ (var-get total-users) u1))
        (ok true)
    )
)

(define-public (store-credential 
    (credential-type (string-ascii 64))
    (encrypted-data-hash (buff 32))
    (metadata-hash (buff 32))
    (expires-at uint)
    (issuer principal)
)
    (let (
        (user tx-sender)
        (credential-id (get-next-credential-id))
        (current-height stacks-block-height)
    )
        (asserts! (has-valid-identity user) ERR-UNAUTHORIZED)
        (asserts! (> (len credential-type) u0) ERR-INVALID-CREDENTIAL)
        (asserts! (is-eq (len encrypted-data-hash) u32) ERR-INVALID-CREDENTIAL)
        (asserts! (is-authorized-issuer issuer) ERR-INVALID-ISSUER)
        (asserts! (> expires-at current-height) ERR-INVALID-TIMESTAMP)
        (asserts! (not (var-get vault-paused)) ERR-ACCESS-DENIED)
        
        (map-set credentials credential-id {
            owner: user,
            issuer: issuer,
            credential-type: credential-type,
            encrypted-data-hash: encrypted-data-hash,
            metadata-hash: metadata-hash,
            issued-at: current-height,
            expires-at: expires-at,
            is-revoked: false,
            revoked-at: none,
            attestation-count: u0
        })
        
        (var-set total-credentials (+ (var-get total-credentials) u1))
        (ok credential-id)
    )
)

(define-public (grant-access 
    (credential-id uint)
    (verifier principal)
    (permission-type (string-ascii 32))
    (duration uint)
)
    (let ((user tx-sender))
        (asserts! (is-credential-owner credential-id user) ERR-UNAUTHORIZED)
        (asserts! (> duration u0) ERR-INVALID-PERMISSION)
        (asserts! (> (len permission-type) u0) ERR-INVALID-PERMISSION)
        (asserts! (not (var-get vault-paused)) ERR-ACCESS-DENIED)
        
        (map-set credential-permissions 
            { credential-id: credential-id, verifier: verifier }
            {
                granted-at: stacks-block-height,
                expires-at: (+ stacks-block-height duration),
                permission-type: permission-type,
                access-count: u0,
                last-accessed: none
            }
        )
        (ok true)
    )
)

(define-public (revoke-credential (credential-id uint))
    (let ((user tx-sender))
        (asserts! (is-credential-owner credential-id user) ERR-UNAUTHORIZED)
        (match (map-get? credentials credential-id)
            credential 
                (begin
                    (asserts! (not (get is-revoked credential)) ERR-CREDENTIAL-REVOKED)
                    (map-set credentials credential-id 
                        (merge credential {
                            is-revoked: true,
                            revoked-at: (some stacks-block-height)
                        })
                    )
                    (ok true)
                )
            ERR-CREDENTIAL-NOT-FOUND
        )
    )
)

(define-public (register-issuer 
    (issuer principal)
    (name (string-ascii 128))
    (public-key (buff 33))
)
    (begin
        (asserts! (is-eq tx-sender CONTRACT-OWNER) ERR-UNAUTHORIZED)
        (asserts! (is-none (map-get? trusted-issuers issuer)) ERR-CREDENTIAL-EXISTS)
        (asserts! (> (len name) u0) ERR-INVALID-CREDENTIAL)
        (asserts! (is-eq (len public-key) u33) ERR-INVALID-CREDENTIAL)
        
        (let ((issuer-id (var-get next-issuer-id)))
            (var-set next-issuer-id (+ issuer-id u1))
            (map-set trusted-issuers issuer {
                issuer-id: issuer-id,
                name: name,
                registered-at: stacks-block-height,
                is-active: true,
                issued-credentials: u0,
                revoked-credentials: u0,
                public-key: public-key
            })
            (ok true)
        )
    )
)

(define-public (add-attestation 
    (credential-id uint)
    (attestation-hash (buff 32))
    (confidence-score uint)
)
    (let ((attester tx-sender))
        (asserts! (is-authorized-issuer attester) ERR-INVALID-ISSUER)
        (asserts! (<= confidence-score u100) ERR-INVALID-CREDENTIAL)
        (asserts! (is-eq (len attestation-hash) u32) ERR-INVALID-CREDENTIAL)
        
        (match (map-get? credentials credential-id)
            credential 
                (begin
                    (asserts! (not (get is-revoked credential)) ERR-CREDENTIAL-REVOKED)
                    (map-set attestations 
                        { credential-id: credential-id, attester: attester }
                        {
                            attestation-hash: attestation-hash,
                            attested-at: stacks-block-height,
                            confidence-score: confidence-score,
                            is-valid: true
                        }
                    )
                    (ok true)
                )
            ERR-CREDENTIAL-NOT-FOUND
        )
    )
)

(define-public (create-auth-session 
    (session-id (buff 16))
    (duration uint)
    (auth-method (string-ascii 32))
)
    (let ((user tx-sender))
        (asserts! (has-valid-identity user) ERR-UNAUTHORIZED)
        (asserts! (> duration u0) ERR-INVALID-TIMESTAMP)
        (asserts! (is-eq (len session-id) u16) ERR-INVALID-CREDENTIAL)
        (asserts! (not (var-get vault-paused)) ERR-ACCESS-DENIED)
        
        (map-set auth-sessions user {
            session-id: session-id,
            created-at: stacks-block-height,
            expires-at: (+ stacks-block-height duration),
            is-active: true,
            authentication-method: auth-method
        })
        (ok true)
    )
)

(define-public (verify-identity (user principal))
    (begin
        (asserts! (is-eq tx-sender CONTRACT-OWNER) ERR-UNAUTHORIZED)
        (match (map-get? user-identities user)
            identity 
                (begin
                    (map-set user-identities user 
                        (merge identity {
                            is-verified: true,
                            updated-at: stacks-block-height
                        })
                    )
                    (ok true)
                )
            ERR-CREDENTIAL-NOT-FOUND
        )
    )
)

(define-public (revoke-access (credential-id uint) (verifier principal))
    (let ((user tx-sender))
        (asserts! (is-credential-owner credential-id user) ERR-UNAUTHORIZED)
        (map-delete credential-permissions { credential-id: credential-id, verifier: verifier })
        (ok true)
    )
)

(define-public (update-issuer-status (issuer principal) (is-active bool))
    (begin
        (asserts! (is-eq tx-sender CONTRACT-OWNER) ERR-UNAUTHORIZED)
        (match (map-get? trusted-issuers issuer)
            issuer-data 
                (begin
                    (map-set trusted-issuers issuer 
                        (merge issuer-data { is-active: is-active })
                    )
                    (ok true)
                )
            ERR-INVALID-ISSUER
        )
    )
)

(define-public (toggle-vault-pause)
    (begin
        (asserts! (is-eq tx-sender CONTRACT-OWNER) ERR-UNAUTHORIZED)
        (var-set vault-paused (not (var-get vault-paused)))
        (ok (var-get vault-paused))
    )
)

;; Read-only functions
(define-read-only (get-user-identity (user principal))
    (map-get? user-identities user)
)

(define-read-only (get-credential (credential-id uint))
    (let ((caller tx-sender))
        (match (map-get? credentials credential-id)
            credential 
                (if (or 
                    (is-eq caller (get owner credential))
                    (has-access-permission credential-id caller)
                )
                    (some credential)
                    none
                )
            none
        )
    )
)

(define-read-only (get-issuer-info (issuer principal))
    (map-get? trusted-issuers issuer)
)

(define-read-only (is-credential-valid (credential-id uint))
    (match (map-get? credentials credential-id)
        credential (and 
            (not (get is-revoked credential))
            (> (get expires-at credential) stacks-block-height)
        )
        false
    )
)

(define-read-only (get-attestation (credential-id uint) (attester principal))
    (map-get? attestations { credential-id: credential-id, attester: attester })
)

(define-read-only (check-access-permission (credential-id uint) (verifier principal))
    (map-get? credential-permissions { credential-id: credential-id, verifier: verifier })
)

(define-read-only (get-auth-session (user principal))
    (map-get? auth-sessions user)
)

(define-read-only (get-vault-status)
    (ok {
        paused: (var-get vault-paused),
        next-credential-id: (var-get next-credential-id),
        next-issuer-id: (var-get next-issuer-id),
        total-credentials: (var-get total-credentials),
        total-users: (var-get total-users)
    })
)
