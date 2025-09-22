;; Privacy Compliance Validator Contract
;; Ensures biometric data handling meets regulatory requirements
;; Monitors consent management, data retention policies, and triggers compliance-related insurance payouts

;; Constants
(define-constant contract-owner tx-sender)
(define-constant err-owner-only (err u300))
(define-constant err-not-found (err u301))
(define-constant err-invalid-compliance (err u302))
(define-constant err-insufficient-balance (err u303))
(define-constant err-claim-already-processed (err u304))
(define-constant err-invalid-score (err u305))
(define-constant err-invalid-policy (err u306))
(define-constant err-policy-expired (err u307))
(define-constant err-violation-not-confirmed (err u308))
(define-constant err-consent-required (err u309))

;; Compliance thresholds (percentage scores)
(define-constant min-gdpr-score u95)
(define-constant min-ccpa-score u92)
(define-constant min-hipaa-score u98)
(define-constant min-overall-compliance u95)
(define-constant max-compliance-claim u300000000000)

;; Data retention periods (in blocks)
(define-constant max-retention-period u525600)
(define-constant consent-validity-period u262800)

;; Data Variables
(define-data-var total-compliance-policies uint u0)
(define-data-var total-violations-detected uint u0)
(define-data-var total-compliance-claims-paid uint u0)
(define-data-var validator-enabled bool true)
(define-data-var contract-balance uint u0)

;; Data Maps
(define-map compliance-violations
    { violation-id: uint }
    {
        timestamp: uint,
        system-id: (string-ascii 64),
        violation-type: (string-ascii 32),
        regulation: (string-ascii 16),
        severity-score: uint,
        affected-subjects: uint,
        remediation-required: bool,
        confirmed: bool,
        policy-holder: principal
    }
)

(define-map compliance-policies
    { policy-id: uint }
    {
        policy-holder: principal,
        coverage-amount: uint,
        premium-paid: uint,
        start-block: uint,
        end-block: uint,
        system-id: (string-ascii 64),
        min-compliance-score: uint,
        data-retention-limit: uint,
        active: bool
    }
)

(define-map consent-records
    { system-id: (string-ascii 64), subject-id: (string-ascii 64) }
    {
        consent-given: bool,
        consent-timestamp: uint,
        consent-type: (string-ascii 32),
        expiry-block: uint,
        withdrawal-timestamp: (optional uint)
    }
)

(define-map compliance-policy-counter { id: uint } { count: uint })
(define-map violation-counter { id: uint } { count: uint })

;; Initialize counters
(map-set compliance-policy-counter { id: u0 } { count: u0 })
(map-set violation-counter { id: u0 } { count: u0 })

;; Private Functions
(define-private (get-next-compliance-policy-id)
    (let ((current (default-to u0 (get count (map-get? compliance-policy-counter { id: u0 })))))
        (let ((next-id (+ current u1)))
            (map-set compliance-policy-counter { id: u0 } { count: next-id })
            next-id
        )
    )
)

(define-private (get-next-violation-id)
    (let ((current (default-to u0 (get count (map-get? violation-counter { id: u0 })))))
        (let ((next-id (+ current u1)))
            (map-set violation-counter { id: u0 } { count: next-id })
            next-id
        )
    )
)

(define-private (is-compliance-policy-active (policy-id uint))
    (match (map-get? compliance-policies { policy-id: policy-id })
        policy-data
        (and
            (get active policy-data)
            (>= stacks-block-height (get start-block policy-data))
            (<= stacks-block-height (get end-block policy-data))
        )
        false
    )
)

(define-private (is-consent-valid (system-id (string-ascii 64)) (subject-id (string-ascii 64)))
    (match (map-get? consent-records { system-id: system-id, subject-id: subject-id })
        consent-data
        (and
            (get consent-given consent-data)
            (is-none (get withdrawal-timestamp consent-data))
            (< stacks-block-height (get expiry-block consent-data))
        )
        false
    )
)

;; Public Functions

;; Create privacy compliance insurance policy
(define-public (create-compliance-policy (coverage-amount uint) (premium uint) (duration-blocks uint) (system-id (string-ascii 64))
                                        (min-score uint) (retention-limit uint))
    (let ((policy-id (get-next-compliance-policy-id)))
        (begin
            (asserts! (<= coverage-amount max-compliance-claim) err-invalid-policy)
            (asserts! (> premium u0) err-invalid-policy)
            (asserts! (and (>= min-score u80) (<= min-score u100)) err-invalid-score)
            (asserts! (<= retention-limit max-retention-period) err-invalid-policy)
            
            (try! (stx-transfer? premium tx-sender (as-contract tx-sender)))
            
            (map-set compliance-policies
                { policy-id: policy-id }
                {
                    policy-holder: tx-sender,
                    coverage-amount: coverage-amount,
                    premium-paid: premium,
                    start-block: stacks-block-height,
                    end-block: (+ stacks-block-height duration-blocks),
                    system-id: system-id,
                    min-compliance-score: min-score,
                    data-retention-limit: retention-limit,
                    active: true
                }
            )
            
            (var-set total-compliance-policies (+ (var-get total-compliance-policies) u1))
            (var-set contract-balance (+ (var-get contract-balance) premium))
            (ok policy-id)
        )
    )
)

;; Record consent from data subject
(define-public (record-consent (system-id (string-ascii 64)) (subject-id (string-ascii 64)) (consent-type (string-ascii 32))
                              (validity-blocks uint))
    (begin
        (asserts! (var-get validator-enabled) err-owner-only)
        (asserts! (<= validity-blocks consent-validity-period) err-invalid-policy)
        
        (map-set consent-records
            { system-id: system-id, subject-id: subject-id }
            {
                consent-given: true,
                consent-timestamp: stacks-block-height,
                consent-type: consent-type,
                expiry-block: (+ stacks-block-height validity-blocks),
                withdrawal-timestamp: none
            }
        )
        (ok true)
    )
)

;; Report compliance violation
(define-public (report-violation (policy-id uint) (violation-type (string-ascii 32)) (regulation (string-ascii 16))
                                (severity-score uint) (affected-subjects uint) (system-id (string-ascii 64)))
    (let ((violation-id (get-next-violation-id)))
        (begin
            (asserts! (var-get validator-enabled) err-owner-only)
            (asserts! (is-compliance-policy-active policy-id) err-policy-expired)
            (asserts! (and (>= severity-score u1) (<= severity-score u100)) err-invalid-score)
            (asserts! (> affected-subjects u0) err-invalid-compliance)
            
            (match (map-get? compliance-policies { policy-id: policy-id })
                policy-data
                (begin
                    (asserts! (is-eq (get policy-holder policy-data) tx-sender) err-owner-only)
                    (asserts! (is-eq (get system-id policy-data) system-id) err-invalid-policy)
                    
                    (map-set compliance-violations
                        { violation-id: violation-id }
                        {
                            timestamp: stacks-block-height,
                            system-id: system-id,
                            violation-type: violation-type,
                            regulation: regulation,
                            severity-score: severity-score,
                            affected-subjects: affected-subjects,
                            remediation-required: (>= severity-score u70),
                            confirmed: false,
                            policy-holder: tx-sender
                        }
                    )
                    
                    (var-set total-violations-detected (+ (var-get total-violations-detected) u1))
                    (ok violation-id)
                )
                err-not-found
            )
        )
    )
)

;; Admin function to toggle validator
(define-public (toggle-validator)
    (begin
        (asserts! (is-eq tx-sender contract-owner) err-owner-only)
        (var-set validator-enabled (not (var-get validator-enabled)))
        (ok (var-get validator-enabled))
    )
)

;; Read-only functions
(define-read-only (get-compliance-policy (policy-id uint))
    (map-get? compliance-policies { policy-id: policy-id })
)

(define-read-only (get-violation (violation-id uint))
    (map-get? compliance-violations { violation-id: violation-id })
)

(define-read-only (get-consent-record (system-id (string-ascii 64)) (subject-id (string-ascii 64)))
    (map-get? consent-records { system-id: system-id, subject-id: subject-id })
)

(define-read-only (is-consent-valid-check (system-id (string-ascii 64)) (subject-id (string-ascii 64)))
    (is-consent-valid system-id subject-id)
)

(define-read-only (get-validator-stats)
    {
        total-policies: (var-get total-compliance-policies),
        total-violations: (var-get total-violations-detected),
        total-claims-paid: (var-get total-compliance-claims-paid),
        validator-enabled: (var-get validator-enabled),
        contract-balance: (var-get contract-balance)
    }
)