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
(define-constant max-compliance-claim u300000000000) ;; 300,000 STX in microSTX

;; Data retention periods (in blocks)
(define-constant max-retention-period u525600) ;; ~1 year in 10-minute blocks
(define-constant consent-validity-period u262800) ;; ~6 months

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
        policy-holder: principal,
        compliance-officer: (optional principal)
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
        covered-regulations: (list 5 (string-ascii 16)),
        min-compliance-score: uint,
        data-retention-limit: uint,
        active: bool
    }
)

(define-map compliance-claims
    { claim-id: uint }
    {
        policy-id: uint,
        violation-id: uint,
        claim-amount: uint,
        processed: bool,
        timestamp: uint,
        regulation: (string-ascii 16)
    }
)

(define-map consent-records
    { system-id: (string-ascii 64), subject-id: (string-ascii 64) }
    {
        consent-given: bool,
        consent-timestamp: uint,
        consent-type: (string-ascii 32),
        expiry-block: uint,
        withdrawal-timestamp: (optional uint),
        purpose-limitation: (list 5 (string-ascii 32))
    }
)

(define-map data-retention-records
    { system-id: (string-ascii 64), data-type: (string-ascii 32) }
    {
        creation-timestamp: uint,
        retention-period: uint,
        deletion-scheduled: uint,
        anonymized: bool,
        legal-basis: (string-ascii 32)
    }
)

(define-map compliance-scores
    { system-id: (string-ascii 64), audit-period: uint }
    {
        gdpr-score: uint,
        ccpa-score: uint,
        hipaa-score: uint,
        overall-score: uint,
        audit-timestamp: uint,
        auditor: principal,
        next-audit-due: uint
    }
)

(define-map system-compliance-stats
    { system-id: (string-ascii 64) }
    {
        total-violations: uint,
        total-audits: uint,
        avg-compliance-score: uint,
        last-violation-block: uint,
        consent-coverage: uint,
        data-minimization-score: uint
    }
)

(define-map compliance-policy-counter { id: uint } { count: uint })
(define-map violation-counter { id: uint } { count: uint })
(define-map compliance-claim-counter { id: uint } { count: uint })

;; Initialize counters
(map-set compliance-policy-counter { id: u0 } { count: u0 })
(map-set violation-counter { id: u0 } { count: u0 })
(map-set compliance-claim-counter { id: u0 } { count: u0 })

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

(define-private (get-next-compliance-claim-id)
    (let ((current (default-to u0 (get count (map-get? compliance-claim-counter { id: u0 })))))
        (let ((next-id (+ current u1)))
            (map-set compliance-claim-counter { id: u0 } { count: next-id })
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

(define-private (calculate-compliance-claim-amount (severity uint) (affected-subjects uint) (coverage uint) (compliance-score uint))
    (let (
        (base-amount (/ (* coverage severity) u100))
        (subject-divisor (/ affected-subjects u100))
        (subject-multiplier (if (< subject-divisor u5) subject-divisor u5))
        (compliance-penalty (/ (- u100 compliance-score) u10))
        (calculated-amount (+ base-amount (* subject-multiplier compliance-penalty)))
    )
        (if (< calculated-amount coverage)
            calculated-amount
            coverage)
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

(define-private (calculate-overall-compliance-score (gdpr uint) (ccpa uint) (hipaa uint))
    (/ (+ gdpr ccpa hipaa) u3)
)

(define-private (update-compliance-stats (system-id (string-ascii 64)) (violation-severity uint) (compliance-score uint))
    (let ((current-stats (default-to
            {
                total-violations: u0,
                total-audits: u0,
                avg-compliance-score: u100,
                last-violation-block: u0,
                consent-coverage: u0,
                data-minimization-score: u100
            }
            (map-get? system-compliance-stats { system-id: system-id })
        )))
        (let (
            (total-violations (+ (get total-violations current-stats) u1))
            (total-audits (+ (get total-audits current-stats) u1))
            (new-avg-score (/ (+ (* (get avg-compliance-score current-stats) (get total-audits current-stats)) compliance-score) total-audits))
        )
            (map-set system-compliance-stats
                { system-id: system-id }
                {
                    total-violations: total-violations,
                    total-audits: total-audits,
                    avg-compliance-score: new-avg-score,
                    last-violation-block: stacks-block-height,
                    consent-coverage: (get consent-coverage current-stats),
                    data-minimization-score: (get data-minimization-score current-stats)
                }
            )
        )
    )
)

;; Public Functions

;; Create privacy compliance insurance policy
(define-public (create-compliance-policy (coverage-amount uint) (premium uint) (duration-blocks uint) (system-id (string-ascii 64))
                                        (regulations (list 5 (string-ascii 16))) (min-score uint) (retention-limit uint))
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
                    covered-regulations: regulations,
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
                              (purposes (list 5 (string-ascii 32))) (validity-blocks uint))
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
                withdrawal-timestamp: none,
                purpose-limitation: purposes
            }
        )
        (ok true)
    )
)

;; Withdraw consent
(define-public (withdraw-consent (system-id (string-ascii 64)) (subject-id (string-ascii 64)))
    (begin
        (asserts! (var-get validator-enabled) err-owner-only)
        
        (match (map-get? consent-records { system-id: system-id, subject-id: subject-id })
            consent-data
            (begin
                (map-set consent-records
                    { system-id: system-id, subject-id: subject-id }
                    (merge consent-data {
                        consent-given: false,
                        withdrawal-timestamp: (some stacks-block-height)
                    })
                )
                (ok true)
            )
            err-not-found
        )
    )
)

;; Submit compliance audit results
(define-public (submit-audit (system-id (string-ascii 64)) (gdpr-score uint) (ccpa-score uint) (hipaa-score uint))
    (let ((audit-period (/ stacks-block-height u144))) ;; Daily audit periods
        (begin
            (asserts! (var-get validator-enabled) err-owner-only)
            (asserts! (and (<= gdpr-score u100) (<= ccpa-score u100) (<= hipaa-score u100)) err-invalid-score)
            
            (let ((overall-score (calculate-overall-compliance-score gdpr-score ccpa-score hipaa-score)))
                (map-set compliance-scores
                    { system-id: system-id, audit-period: audit-period }
                    {
                        gdpr-score: gdpr-score,
                        ccpa-score: ccpa-score,
                        hipaa-score: hipaa-score,
                        overall-score: overall-score,
                        audit-timestamp: stacks-block-height,
                        auditor: tx-sender,
                        next-audit-due: (+ stacks-block-height u144) ;; Next day
                    }
                )
                (ok overall-score)
            )
        )
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
                            policy-holder: tx-sender,
                            compliance-officer: none
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

;; Confirm compliance violation
(define-public (confirm-violation (violation-id uint) (compliance-officer principal))
    (begin
        (asserts! (var-get validator-enabled) err-owner-only)
        
        (match (map-get? compliance-violations { violation-id: violation-id })
            violation-data
            (begin
                (asserts! (is-eq (get policy-holder violation-data) tx-sender) err-owner-only)
                
                (map-set compliance-violations
                    { violation-id: violation-id }
                    (merge violation-data {
                        confirmed: true,
                        compliance-officer: (some compliance-officer)
                    })
                )
                
                (update-compliance-stats
                    (get system-id violation-data)
                    (get severity-score violation-data)
                    u0 ;; Will be updated by audit
                )
                (ok true)
            )
            err-not-found
        )
    )
)

;; Process compliance claim
(define-public (process-compliance-claim (policy-id uint) (violation-id uint) (regulation (string-ascii 16)))
    (let ((claim-id (get-next-compliance-claim-id)))
        (begin
            (asserts! (is-compliance-policy-active policy-id) err-policy-expired)
            
            (match (map-get? compliance-policies { policy-id: policy-id })
                policy-data
                (match (map-get? compliance-violations { violation-id: violation-id })
                    violation-data
                    (begin
                        (asserts! (get confirmed violation-data) err-violation-not-confirmed)
                        (asserts! (is-eq (get policy-holder policy-data) (get policy-holder violation-data)) err-invalid-policy)
                        
                        (let (
                            (claim-amount (calculate-compliance-claim-amount
                                (get severity-score violation-data)
                                (get affected-subjects violation-data)
                                (get coverage-amount policy-data)
                                (get min-compliance-score policy-data)
                            ))
                        )
                            (asserts! (> claim-amount u0) err-invalid-compliance)
                            (asserts! (<= claim-amount (var-get contract-balance)) err-insufficient-balance)
                            
                            (map-set compliance-claims
                                { claim-id: claim-id }
                                {
                                    policy-id: policy-id,
                                    violation-id: violation-id,
                                    claim-amount: claim-amount,
                                    processed: true,
                                    timestamp: stacks-block-height,
                                    regulation: regulation
                                }
                            )
                            
                            (try! (as-contract (stx-transfer? claim-amount tx-sender (get policy-holder policy-data))))
                            (var-set total-compliance-claims-paid (+ (var-get total-compliance-claims-paid) claim-amount))
                            (var-set contract-balance (- (var-get contract-balance) claim-amount))
                            
                            (ok claim-id)
                        )
                    )
                    err-not-found
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

(define-read-only (get-compliance-claim (claim-id uint))
    (map-get? compliance-claims { claim-id: claim-id })
)

(define-read-only (get-consent-record (system-id (string-ascii 64)) (subject-id (string-ascii 64)))
    (map-get? consent-records { system-id: system-id, subject-id: subject-id })
)

(define-read-only (get-compliance-score (system-id (string-ascii 64)) (audit-period uint))
    (map-get? compliance-scores { system-id: system-id, audit-period: audit-period })
)

(define-read-only (get-compliance-stats (system-id (string-ascii 64)))
    (map-get? system-compliance-stats { system-id: system-id })
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
