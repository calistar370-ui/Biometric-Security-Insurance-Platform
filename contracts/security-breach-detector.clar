;; Security Breach Detector Contract
;; Automated detection of biometric database breaches and unauthorized access attempts
;; Monitors biometric database integrity and processes breach-related insurance claims

;; Constants
(define-constant contract-owner tx-sender)
(define-constant err-owner-only (err u200))
(define-constant err-not-found (err u201))
(define-constant err-invalid-breach (err u202))
(define-constant err-insufficient-balance (err u203))
(define-constant err-claim-already-processed (err u204))
(define-constant err-invalid-severity (err u205))
(define-constant err-invalid-policy (err u206))
(define-constant err-policy-expired (err u207))
(define-constant err-breach-not-confirmed (err u208))

;; Breach severity levels
(define-constant severity-low u1)
(define-constant severity-medium u2)
(define-constant severity-high u3)
(define-constant severity-critical u4)

;; Maximum response times in blocks (10 minutes per block)
(define-constant max-detection-time u6) ;; 1 hour
(define-constant max-response-time u144) ;; 24 hours
(define-constant max-claim-amount u500000000000) ;; 500,000 STX in microSTX

;; Data Variables
(define-data-var total-breach-policies uint u0)
(define-data-var total-breaches-detected uint u0)
(define-data-var total-breach-claims-paid uint u0)
(define-data-var detector-enabled bool true)
(define-data-var contract-balance uint u0)

;; Data Maps
(define-map breach-incidents
    { incident-id: uint }
    {
        timestamp: uint,
        system-id: (string-ascii 64),
        breach-type: (string-ascii 32),
        severity-level: uint,
        affected-records: uint,
        detection-time: uint,
        response-time: uint,
        confirmed: bool,
        policy-holder: principal,
        remediation-status: (string-ascii 16)
    }
)

(define-map breach-policies
    { policy-id: uint }
    {
        policy-holder: principal,
        coverage-amount: uint,
        premium-paid: uint,
        start-block: uint,
        end-block: uint,
        system-id: (string-ascii 64),
        max-detection-time: uint,
        max-response-time: uint,
        coverage-types: (list 5 (string-ascii 32)),
        active: bool
    }
)

(define-map breach-claims
    { claim-id: uint }
    {
        policy-id: uint,
        incident-id: uint,
        claim-amount: uint,
        processed: bool,
        timestamp: uint,
        claim-type: (string-ascii 32)
    }
)

(define-map access-patterns
    { system-id: (string-ascii 64), block-range: uint }
    {
        normal-access-count: uint,
        suspicious-access-count: uint,
        failed-attempts: uint,
        anomaly-score: uint,
        last-updated: uint
    }
)

(define-map system-security-metrics
    { system-id: (string-ascii 64) }
    {
        total-incidents: uint,
        avg-detection-time: uint,
        avg-response-time: uint,
        security-score: uint,
        last-incident-block: uint,
        high-severity-count: uint
    }
)

(define-map breach-policy-counter { id: uint } { count: uint })
(define-map incident-counter { id: uint } { count: uint })
(define-map breach-claim-counter { id: uint } { count: uint })

;; Initialize counters
(map-set breach-policy-counter { id: u0 } { count: u0 })
(map-set incident-counter { id: u0 } { count: u0 })
(map-set breach-claim-counter { id: u0 } { count: u0 })

;; Private Functions
(define-private (get-next-breach-policy-id)
    (let ((current (default-to u0 (get count (map-get? breach-policy-counter { id: u0 })))))
        (let ((next-id (+ current u1)))
            (map-set breach-policy-counter { id: u0 } { count: next-id })
            next-id
        )
    )
)

(define-private (get-next-incident-id)
    (let ((current (default-to u0 (get count (map-get? incident-counter { id: u0 })))))
        (let ((next-id (+ current u1)))
            (map-set incident-counter { id: u0 } { count: next-id })
            next-id
        )
    )
)

(define-private (get-next-breach-claim-id)
    (let ((current (default-to u0 (get count (map-get? breach-claim-counter { id: u0 })))))
        (let ((next-id (+ current u1)))
            (map-set breach-claim-counter { id: u0 } { count: next-id })
            next-id
        )
    )
)

(define-private (is-breach-policy-active (policy-id uint))
    (match (map-get? breach-policies { policy-id: policy-id })
        policy-data
        (and
            (get active policy-data)
            (>= stacks-block-height (get start-block policy-data))
            (<= stacks-block-height (get end-block policy-data))
        )
        false
    )
)

(define-private (calculate-breach-claim-amount (severity uint) (affected-records uint) (coverage uint) (detection-time uint) (response-time uint))
    (let (
        (base-amount (/ (* coverage severity) u10))
        (record-divisor (/ affected-records u1000))
        (record-multiplier (if (< record-divisor u10) record-divisor u10))
        (time-penalty (if (> detection-time max-detection-time) u2 u1))
        (response-penalty (if (> response-time max-response-time) u2 u1))
        (calculated-amount (/ (* base-amount record-multiplier) (* time-penalty response-penalty)))
    )
        (if (< calculated-amount coverage)
            calculated-amount
            coverage)
    )
)

(define-private (calculate-anomaly-score (normal-access uint) (suspicious-access uint) (failed-attempts uint))
    (let (
        (total-access (+ normal-access suspicious-access))
        (suspicious-ratio (if (> total-access u0) (/ (* suspicious-access u100) total-access) u0))
        (failure-ratio (if (> total-access u0) (/ (* failed-attempts u100) total-access) u0))
    )
        (+ suspicious-ratio failure-ratio)
    )
)

(define-private (update-security-metrics (system-id (string-ascii 64)) (detection-time uint) (response-time uint) (severity uint))
    (let ((current-metrics (default-to
            {
                total-incidents: u0,
                avg-detection-time: u0,
                avg-response-time: u0,
                security-score: u100,
                last-incident-block: u0,
                high-severity-count: u0
            }
            (map-get? system-security-metrics { system-id: system-id })
        )))
        (let (
            (total-incidents (+ (get total-incidents current-metrics) u1))
            (new-avg-detection (/ (+ (* (get avg-detection-time current-metrics) (get total-incidents current-metrics)) detection-time) total-incidents))
            (new-avg-response (/ (+ (* (get avg-response-time current-metrics) (get total-incidents current-metrics)) response-time) total-incidents))
            (high-severity-count (+ (get high-severity-count current-metrics) (if (>= severity severity-high) u1 u0)))
            (penalty-score (/ (* high-severity-count u10) total-incidents))
            (security-score (if (> penalty-score u100) u0 (- u100 penalty-score)))
        )
            (map-set system-security-metrics
                { system-id: system-id }
                {
                    total-incidents: total-incidents,
                    avg-detection-time: new-avg-detection,
                    avg-response-time: new-avg-response,
                    security-score: security-score,
                    last-incident-block: stacks-block-height,
                    high-severity-count: high-severity-count
                }
            )
        )
    )
)

;; Public Functions

;; Create breach detection insurance policy
(define-public (create-breach-policy (coverage-amount uint) (premium uint) (duration-blocks uint) (system-id (string-ascii 64))
                                    (max-detect-time uint) (max-resp-time uint) (coverage-types (list 5 (string-ascii 32))))
    (let ((policy-id (get-next-breach-policy-id)))
        (begin
            (asserts! (<= coverage-amount max-claim-amount) err-invalid-policy)
            (asserts! (> premium u0) err-invalid-policy)
            (asserts! (<= max-detect-time u144) err-invalid-policy) ;; Max 24 hours detection
            (asserts! (<= max-resp-time u720) err-invalid-policy) ;; Max 5 days response
            
            (try! (stx-transfer? premium tx-sender (as-contract tx-sender)))
            
            (map-set breach-policies
                { policy-id: policy-id }
                {
                    policy-holder: tx-sender,
                    coverage-amount: coverage-amount,
                    premium-paid: premium,
                    start-block: stacks-block-height,
                    end-block: (+ stacks-block-height duration-blocks),
                    system-id: system-id,
                    max-detection-time: max-detect-time,
                    max-response-time: max-resp-time,
                    coverage-types: coverage-types,
                    active: true
                }
            )
            
            (var-set total-breach-policies (+ (var-get total-breach-policies) u1))
            (var-set contract-balance (+ (var-get contract-balance) premium))
            (ok policy-id)
        )
    )
)

;; Report security breach incident
(define-public (report-breach (policy-id uint) (breach-type (string-ascii 32)) (severity-level uint) 
                             (affected-records uint) (system-id (string-ascii 64)))
    (let ((incident-id (get-next-incident-id)))
        (begin
            (asserts! (var-get detector-enabled) err-owner-only)
            (asserts! (is-breach-policy-active policy-id) err-policy-expired)
            (asserts! (and (>= severity-level severity-low) (<= severity-level severity-critical)) err-invalid-severity)
            (asserts! (> affected-records u0) err-invalid-breach)
            
            (match (map-get? breach-policies { policy-id: policy-id })
                policy-data
                (begin
                    (asserts! (is-eq (get policy-holder policy-data) tx-sender) err-owner-only)
                    (asserts! (is-eq (get system-id policy-data) system-id) err-invalid-policy)
                    
                    (map-set breach-incidents
                        { incident-id: incident-id }
                        {
                            timestamp: stacks-block-height,
                            system-id: system-id,
                            breach-type: breach-type,
                            severity-level: severity-level,
                            affected-records: affected-records,
                            detection-time: u1, ;; Immediate detection assumed
                            response-time: u0, ;; To be updated when resolved
                            confirmed: false,
                            policy-holder: tx-sender,
                            remediation-status: "reported"
                        }
                    )
                    
                    (var-set total-breaches-detected (+ (var-get total-breaches-detected) u1))
                    (ok incident-id)
                )
                err-not-found
            )
        )
    )
)

;; Update access patterns for anomaly detection
(define-public (update-access-patterns (system-id (string-ascii 64)) (normal-access uint) (suspicious-access uint) (failed-attempts uint))
    (let ((block-range (/ stacks-block-height u144))) ;; 24-hour windows
        (begin
            (asserts! (var-get detector-enabled) err-owner-only)
            
            (let ((anomaly-score (calculate-anomaly-score normal-access suspicious-access failed-attempts)))
                (map-set access-patterns
                    { system-id: system-id, block-range: block-range }
                    {
                        normal-access-count: normal-access,
                        suspicious-access-count: suspicious-access,
                        failed-attempts: failed-attempts,
                        anomaly-score: anomaly-score,
                        last-updated: stacks-block-height
                    }
                )
                (ok anomaly-score)
            )
        )
    )
)

;; Confirm breach incident and update response time
(define-public (confirm-breach (incident-id uint) (response-time uint))
    (begin
        (asserts! (var-get detector-enabled) err-owner-only)
        
        (match (map-get? breach-incidents { incident-id: incident-id })
            incident-data
            (begin
                (asserts! (is-eq (get policy-holder incident-data) tx-sender) err-owner-only)
                
                (map-set breach-incidents
                    { incident-id: incident-id }
                    (merge incident-data {
                        response-time: response-time,
                        confirmed: true,
                        remediation-status: "confirmed"
                    })
                )
                
                (update-security-metrics 
                    (get system-id incident-data)
                    (get detection-time incident-data)
                    response-time
                    (get severity-level incident-data)
                )
                (ok true)
            )
            err-not-found
        )
    )
)

;; Process breach insurance claim
(define-public (process-breach-claim (policy-id uint) (incident-id uint) (claim-type (string-ascii 32)))
    (let ((claim-id (get-next-breach-claim-id)))
        (begin
            (asserts! (is-breach-policy-active policy-id) err-policy-expired)
            
            (match (map-get? breach-policies { policy-id: policy-id })
                policy-data
                (match (map-get? breach-incidents { incident-id: incident-id })
                    incident-data
                    (begin
                        (asserts! (get confirmed incident-data) err-breach-not-confirmed)
                        (asserts! (is-eq (get policy-holder policy-data) (get policy-holder incident-data)) err-invalid-policy)
                        
                        (let (
                            (claim-amount (calculate-breach-claim-amount
                                (get severity-level incident-data)
                                (get affected-records incident-data)
                                (get coverage-amount policy-data)
                                (get detection-time incident-data)
                                (get response-time incident-data)
                            ))
                        )
                            (asserts! (> claim-amount u0) err-invalid-breach)
                            (asserts! (<= claim-amount (var-get contract-balance)) err-insufficient-balance)
                            
                            (map-set breach-claims
                                { claim-id: claim-id }
                                {
                                    policy-id: policy-id,
                                    incident-id: incident-id,
                                    claim-amount: claim-amount,
                                    processed: true,
                                    timestamp: stacks-block-height,
                                    claim-type: claim-type
                                }
                            )
                            
                            (try! (as-contract (stx-transfer? claim-amount tx-sender (get policy-holder policy-data))))
                            (var-set total-breach-claims-paid (+ (var-get total-breach-claims-paid) claim-amount))
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

;; Admin function to toggle detector
(define-public (toggle-detector)
    (begin
        (asserts! (is-eq tx-sender contract-owner) err-owner-only)
        (var-set detector-enabled (not (var-get detector-enabled)))
        (ok (var-get detector-enabled))
    )
)

;; Read-only functions
(define-read-only (get-breach-policy (policy-id uint))
    (map-get? breach-policies { policy-id: policy-id })
)

(define-read-only (get-breach-incident (incident-id uint))
    (map-get? breach-incidents { incident-id: incident-id })
)

(define-read-only (get-breach-claim (claim-id uint))
    (map-get? breach-claims { claim-id: claim-id })
)

(define-read-only (get-access-patterns (system-id (string-ascii 64)) (block-range uint))
    (map-get? access-patterns { system-id: system-id, block-range: block-range })
)

(define-read-only (get-security-metrics (system-id (string-ascii 64)))
    (map-get? system-security-metrics { system-id: system-id })
)

(define-read-only (get-detector-stats)
    {
        total-policies: (var-get total-breach-policies),
        total-breaches: (var-get total-breaches-detected),
        total-claims-paid: (var-get total-breach-claims-paid),
        detector-enabled: (var-get detector-enabled),
        contract-balance: (var-get contract-balance)
    }
)
