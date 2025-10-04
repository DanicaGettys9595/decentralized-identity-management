;; Verification Network Contract - Decentralized Identity Management
;; Coordinates between credential issuers and verifiers in a trustless manner

;; Constants
(define-constant CONTRACT-OWNER tx-sender)
(define-constant ERR-UNAUTHORIZED (err u200))
(define-constant ERR-INVALID-PROOF (err u201))
(define-constant ERR-VERIFICATION-FAILED (err u202))
(define-constant ERR-AUTHORITY-NOT-FOUND (err u203))
(define-constant ERR-DISPUTE-EXISTS (err u204))
(define-constant ERR-INVALID-CLAIM (err u205))
(define-constant ERR-NETWORK-PAUSED (err u206))
(define-constant ERR-INSUFFICIENT-STAKE (err u207))
(define-constant ERR-INVALID-TIMESTAMP (err u208))
(define-constant ERR-PROOF-EXPIRED (err u209))
(define-constant ERR-INVALID-SIGNATURE (err u210))

;; Network configuration constants
(define-constant MIN-STAKE-AMOUNT u1000)
(define-constant VERIFICATION-TIMEOUT u144)
(define-constant DISPUTE-PERIOD u1008)
(define-constant MAX-PROOF-SIZE u512)
(define-constant MIN-CONFIDENCE-THRESHOLD u75)

;; Data Variables
(define-data-var next-verification-id uint u1)
(define-data-var next-authority-id uint u1)
(define-data-var next-dispute-id uint u1)
(define-data-var network-paused bool false)
(define-data-var total-verifications uint u0)
(define-data-var total-disputes uint u0)
(define-data-var total-authorities uint u0)

;; Data Maps
(define-map credential-authorities principal {
    authority-id: uint,
    name: (string-ascii 128),
    domain: (string-ascii 64),
    public-key: (buff 33),
    stake-amount: uint,
    reputation-score: uint,
    total-verifications: uint,
    successful-verifications: uint,
    registration-height: uint,
    is-active: bool,
    last-activity: uint
})

(define-map verification-requests uint {
    requester: principal,
    verifier: principal,
    authority: principal,
    claim-type: (string-ascii 64),
    proof-hash: (buff 32),
    proof-data: (buff 512),
    metadata-hash: (buff 32),
    requested-at: uint,
    expires-at: uint,
    status: (string-ascii 16),
    confidence-score: uint,
    validation-count: uint
})

(define-map verification-results { verification-id: uint, authority: principal } {
    result: bool,
    confidence-level: uint,
    proof-validity: bool,
    verification-method: (string-ascii 32),
    verified-at: uint,
    signature: (buff 64),
    additional-data: (optional (buff 256))
})

(define-map disputes uint {
    dispute-id: uint,
    verification-id: uint,
    challenger: principal,
    disputed-authority: principal,
    dispute-type: (string-ascii 32),
    evidence-hash: (buff 32),
    stake-amount: uint,
    created-at: uint,
    resolution-deadline: uint,
    status: (string-ascii 16),
    resolution-result: (optional bool),
    resolved-at: (optional uint)
})

(define-map consensus-votes { verification-id: uint, authority: principal } {
    vote: bool,
    confidence: uint,
    reasoning-hash: (buff 32),
    voted-at: uint,
    stake-weight: uint
})

;; Private Functions
(define-private (is-active-authority (authority principal))
    (match (map-get? credential-authorities authority)
        auth-data (and 
            (get is-active auth-data)
            (>= (get stake-amount auth-data) MIN-STAKE-AMOUNT)
        )
        false
    )
)

(define-private (is-proof-valid-time (expires-at uint))
    (> expires-at stacks-block-height)
)

(define-private (get-next-verification-id)
    (let ((current-id (var-get next-verification-id)))
        (var-set next-verification-id (+ current-id u1))
        current-id
    )
)

;; Public Functions
(define-public (register-authority 
    (name (string-ascii 128))
    (domain (string-ascii 64))
    (public-key (buff 33))
    (stake-amount uint)
)
    (let ((authority tx-sender) (authority-id (var-get next-authority-id)))
        (asserts! (>= stake-amount MIN-STAKE-AMOUNT) ERR-INSUFFICIENT-STAKE)
        (asserts! (is-none (map-get? credential-authorities authority)) ERR-DISPUTE-EXISTS)
        (asserts! (> (len name) u0) ERR-INVALID-CLAIM)
        (asserts! (> (len domain) u0) ERR-INVALID-CLAIM)
        (asserts! (is-eq (len public-key) u33) ERR-INVALID-PROOF)
        (asserts! (not (var-get network-paused)) ERR-NETWORK-PAUSED)
        
        (var-set next-authority-id (+ authority-id u1))
        (var-set total-authorities (+ (var-get total-authorities) u1))
        (map-set credential-authorities authority {
            authority-id: authority-id,
            name: name,
            domain: domain,
            public-key: public-key,
            stake-amount: stake-amount,
            reputation-score: u100,
            total-verifications: u0,
            successful-verifications: u0,
            registration-height: stacks-block-height,
            is-active: true,
            last-activity: stacks-block-height
        })
        (ok true)
    )
)

(define-public (submit-verification-request 
    (verifier principal)
    (authority principal)
    (claim-type (string-ascii 64))
    (proof-hash (buff 32))
    (proof-data (buff 512))
    (metadata-hash (buff 32))
    (duration uint)
)
    (let (
        (requester tx-sender)
        (verification-id (get-next-verification-id))
        (expires-at (+ stacks-block-height duration))
    )
        (asserts! (is-active-authority authority) ERR-AUTHORITY-NOT-FOUND)
        (asserts! (> (len proof-data) u0) ERR-INVALID-PROOF)
        (asserts! (<= (len proof-data) MAX-PROOF-SIZE) ERR-INVALID-PROOF)
        (asserts! (> duration u0) ERR-INVALID-TIMESTAMP)
        (asserts! (<= duration VERIFICATION-TIMEOUT) ERR-INVALID-TIMESTAMP)
        (asserts! (not (var-get network-paused)) ERR-NETWORK-PAUSED)
        
        (map-set verification-requests verification-id {
            requester: requester,
            verifier: verifier,
            authority: authority,
            claim-type: claim-type,
            proof-hash: proof-hash,
            proof-data: proof-data,
            metadata-hash: metadata-hash,
            requested-at: stacks-block-height,
            expires-at: expires-at,
            status: "pending",
            confidence-score: u0,
            validation-count: u0
        })
        
        (var-set total-verifications (+ (var-get total-verifications) u1))
        (ok verification-id)
    )
)

(define-public (process-verification 
    (verification-id uint)
    (result bool)
    (confidence-level uint)
    (verification-method (string-ascii 32))
    (signature (buff 64))
)
    (let ((authority tx-sender))
        (asserts! (is-active-authority authority) ERR-AUTHORITY-NOT-FOUND)
        (asserts! (<= confidence-level u100) ERR-INVALID-CLAIM)
        (asserts! (> (len verification-method) u0) ERR-INVALID-CLAIM)
        (asserts! (is-eq (len signature) u64) ERR-INVALID-SIGNATURE)
        
        (match (map-get? verification-requests verification-id)
            request 
                (begin
                    (asserts! (is-eq (get authority request) authority) ERR-UNAUTHORIZED)
                    (asserts! (is-proof-valid-time (get expires-at request)) ERR-PROOF-EXPIRED)
                    (asserts! (is-eq (get status request) "pending") ERR-VERIFICATION-FAILED)
                    
                    (map-set verification-results 
                        { verification-id: verification-id, authority: authority }
                        {
                            result: result,
                            confidence-level: confidence-level,
                            proof-validity: true,
                            verification-method: verification-method,
                            verified-at: stacks-block-height,
                            signature: signature,
                            additional-data: none
                        }
                    )
                    
                    (map-set verification-requests verification-id
                        (merge request {
                            status: (if result "verified" "rejected"),
                            confidence-score: confidence-level,
                            validation-count: (+ (get validation-count request) u1)
                        })
                    )
                    
                    (ok true)
                )
            ERR-VERIFICATION-FAILED
        )
    )
)

(define-public (submit-consensus-vote 
    (verification-id uint)
    (vote bool)
    (confidence uint)
    (reasoning-hash (buff 32))
)
    (let ((authority tx-sender))
        (asserts! (is-active-authority authority) ERR-AUTHORITY-NOT-FOUND)
        (asserts! (<= confidence u100) ERR-INVALID-CLAIM)
        (asserts! (is-eq (len reasoning-hash) u32) ERR-INVALID-PROOF)
        
        (match (map-get? credential-authorities authority)
            auth-data 
                (begin
                    (map-set consensus-votes 
                        { verification-id: verification-id, authority: authority }
                        {
                            vote: vote,
                            confidence: confidence,
                            reasoning-hash: reasoning-hash,
                            voted-at: stacks-block-height,
                            stake-weight: (get stake-amount auth-data)
                        }
                    )
                    (ok true)
                )
            ERR-AUTHORITY-NOT-FOUND
        )
    )
)

(define-public (challenge-verification 
    (verification-id uint)
    (dispute-type (string-ascii 32))
    (evidence-hash (buff 32))
    (stake-amount uint)
)
    (let (
        (challenger tx-sender)
        (dispute-id (var-get next-dispute-id))
    )
        (asserts! (>= stake-amount MIN-STAKE-AMOUNT) ERR-INSUFFICIENT-STAKE)
        (asserts! (> (len dispute-type) u0) ERR-INVALID-CLAIM)
        (asserts! (is-eq (len evidence-hash) u32) ERR-INVALID-PROOF)
        
        (match (map-get? verification-requests verification-id)
            request 
                (begin
                    (asserts! (not (is-eq (get status request) "pending")) ERR-VERIFICATION-FAILED)
                    
                    (var-set next-dispute-id (+ dispute-id u1))
                    (var-set total-disputes (+ (var-get total-disputes) u1))
                    (map-set disputes dispute-id {
                        dispute-id: dispute-id,
                        verification-id: verification-id,
                        challenger: challenger,
                        disputed-authority: (get authority request),
                        dispute-type: dispute-type,
                        evidence-hash: evidence-hash,
                        stake-amount: stake-amount,
                        created-at: stacks-block-height,
                        resolution-deadline: (+ stacks-block-height DISPUTE-PERIOD),
                        status: "open",
                        resolution-result: none,
                        resolved-at: none
                    })
                    
                    (ok dispute-id)
                )
            ERR-VERIFICATION-FAILED
        )
    )
)

(define-public (resolve-dispute 
    (dispute-id uint)
    (resolution bool)
    (resolution-evidence (buff 32))
)
    (begin
        (asserts! (is-eq tx-sender CONTRACT-OWNER) ERR-UNAUTHORIZED)
        
        (match (map-get? disputes dispute-id)
            dispute 
                (begin
                    (asserts! (is-eq (get status dispute) "open") ERR-DISPUTE-EXISTS)
                    (asserts! (< stacks-block-height (get resolution-deadline dispute)) ERR-INVALID-TIMESTAMP)
                    
                    (map-set disputes dispute-id
                        (merge dispute {
                            status: "resolved",
                            resolution-result: (some resolution),
                            resolved-at: (some stacks-block-height)
                        })
                    )
                    
                    (ok true)
                )
            ERR-DISPUTE-EXISTS
        )
    )
)

(define-public (update-stake (new-stake-amount uint))
    (let ((authority tx-sender))
        (asserts! (>= new-stake-amount MIN-STAKE-AMOUNT) ERR-INSUFFICIENT-STAKE)
        (asserts! (is-active-authority authority) ERR-AUTHORITY-NOT-FOUND)
        
        (match (map-get? credential-authorities authority)
            auth-data 
                (begin
                    (map-set credential-authorities authority
                        (merge auth-data {
                            stake-amount: new-stake-amount,
                            last-activity: stacks-block-height
                        })
                    )
                    (ok true)
                )
            ERR-AUTHORITY-NOT-FOUND
        )
    )
)

(define-public (update-authority-status (authority principal) (is-active bool))
    (begin
        (asserts! (is-eq tx-sender CONTRACT-OWNER) ERR-UNAUTHORIZED)
        (match (map-get? credential-authorities authority)
            auth-data 
                (begin
                    (map-set credential-authorities authority
                        (merge auth-data { is-active: is-active })
                    )
                    (ok true)
                )
            ERR-AUTHORITY-NOT-FOUND
        )
    )
)

(define-public (increase-authority-reputation (authority principal))
    (begin
        (asserts! (is-eq tx-sender CONTRACT-OWNER) ERR-UNAUTHORIZED)
        (match (map-get? credential-authorities authority)
            auth-data 
                (let ((new-reputation (+ (get reputation-score auth-data) u5)))
                    (map-set credential-authorities authority
                        (merge auth-data { 
                            reputation-score: (if (> new-reputation u100) u100 new-reputation)
                        })
                    )
                    (ok true)
                )
            ERR-AUTHORITY-NOT-FOUND
        )
    )
)

(define-public (cancel-verification-request (verification-id uint))
    (let ((requester tx-sender))
        (match (map-get? verification-requests verification-id)
            request 
                (begin
                    (asserts! (is-eq (get requester request) requester) ERR-UNAUTHORIZED)
                    (asserts! (is-eq (get status request) "pending") ERR-VERIFICATION-FAILED)
                    
                    (map-set verification-requests verification-id
                        (merge request { status: "cancelled" })
                    )
                    (ok true)
                )
            ERR-VERIFICATION-FAILED
        )
    )
)

(define-public (toggle-network-pause)
    (begin
        (asserts! (is-eq tx-sender CONTRACT-OWNER) ERR-UNAUTHORIZED)
        (var-set network-paused (not (var-get network-paused)))
        (ok (var-get network-paused))
    )
)

;; Read-only functions
(define-read-only (get-authority-info (authority principal))
    (map-get? credential-authorities authority)
)

(define-read-only (get-verification-request (verification-id uint))
    (map-get? verification-requests verification-id)
)

(define-read-only (get-verification-result (verification-id uint) (authority principal))
    (map-get? verification-results { verification-id: verification-id, authority: authority })
)

(define-read-only (get-dispute-info (dispute-id uint))
    (map-get? disputes dispute-id)
)

(define-read-only (is-verification-valid (verification-id uint))
    (match (map-get? verification-requests verification-id)
        request (and 
            (is-eq (get status request) "verified")
            (is-proof-valid-time (get expires-at request))
            (>= (get confidence-score request) MIN-CONFIDENCE-THRESHOLD)
        )
        false
    )
)

(define-read-only (get-consensus-vote (verification-id uint) (authority principal))
    (map-get? consensus-votes { verification-id: verification-id, authority: authority })
)

(define-read-only (get-network-stats)
    (ok {
        total-verifications: (var-get total-verifications),
        total-disputes: (var-get total-disputes),
        total-authorities: (var-get total-authorities),
        network-paused: (var-get network-paused),
        min-stake-amount: MIN-STAKE-AMOUNT,
        verification-timeout: VERIFICATION-TIMEOUT,
        next-verification-id: (var-get next-verification-id),
        next-authority-id: (var-get next-authority-id),
        next-dispute-id: (var-get next-dispute-id)
    })
)

(define-read-only (check-authority-requirements (authority principal))
    (match (map-get? credential-authorities authority)
        auth-data (ok {
            meets-stake-requirement: (>= (get stake-amount auth-data) MIN-STAKE-AMOUNT),
            is-active: (get is-active auth-data),
            reputation: (get reputation-score auth-data),
            total-verifications: (get total-verifications auth-data)
        })
        ERR-AUTHORITY-NOT-FOUND
    )
)
