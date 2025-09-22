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
(define-constant max-detection-time u6)
(define-constant max-response-time u144)
(define-constant max-claim-amount u500000000000)

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
        policy-holder: principal
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
        active: bool
    }
)

(define-map breach-policy-counter { id: uint } { count: uint })
(define-map incident-counter { id: uint } { count: uint })

;; Initialize counters
(map-set breach-policy-counter { id: u0 } { count: u0 })
(map-set incident-counter { id: u0 } { count: u0 })

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

;; Public Functions

;; Create breach detection insurance policy
(define-public (create-breach-policy (coverage-amount uint) (premium uint) (duration-blocks uint) (system-id (string-ascii 64))
                                    (max-detect-time uint) (max-resp-time uint))
    (let ((policy-id (get-next-breach-policy-id)))
        (begin
            (asserts! (<= coverage-amount max-claim-amount) err-invalid-policy)
            (asserts! (> premium u0) err-invalid-policy)
            (asserts! (<= max-detect-time u144) err-invalid-policy)
            (asserts! (<= max-resp-time u720) err-invalid-policy)
            
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
                            detection-time: u1,
                            response-time: u0,
                            confirmed: false,
                            policy-holder: tx-sender
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

(define-read-only (get-detector-stats)
    {
        total-policies: (var-get total-breach-policies),
        total-breaches: (var-get total-breaches-detected),
        total-claims-paid: (var-get total-breach-claims-paid),
        detector-enabled: (var-get detector-enabled),
        contract-balance: (var-get contract-balance)
    }
)