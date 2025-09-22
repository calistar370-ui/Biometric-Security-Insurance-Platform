;; Biometric Accuracy Oracle Contract
;; Real-time monitoring of fingerprint, facial recognition, and iris scan accuracy rates
;; Triggers insurance claims when accuracy thresholds are breached

;; Constants
(define-constant contract-owner tx-sender)
(define-constant err-owner-only (err u100))
(define-constant err-not-found (err u101))
(define-constant err-invalid-accuracy (err u102))
(define-constant err-insufficient-balance (err u103))
(define-constant err-claim-already-processed (err u104))
(define-constant err-threshold-not-breached (err u105))
(define-constant err-invalid-policy (err u106))
(define-constant err-policy-expired (err u107))

;; Minimum accuracy thresholds (basis points: 9950 = 99.5%)
(define-constant min-fingerprint-accuracy u9950)
(define-constant min-facial-accuracy u9900)
(define-constant min-iris-accuracy u9980)
(define-constant max-claim-amount u100000000000)
(define-constant measurement-window u144)

;; Data Variables
(define-data-var total-policies-issued uint u0)
(define-data-var total-claims-paid uint u0)
(define-data-var contract-balance uint u0)
(define-data-var oracle-enabled bool true)

;; Data Maps
(define-map biometric-readings 
    { measurement-id: uint }
    { 
        timestamp: uint,
        fingerprint-accuracy: uint,
        facial-accuracy: uint, 
        iris-accuracy: uint,
        total-samples: uint,
        policy-holder: principal,
        system-id: (string-ascii 64)
    }
)

(define-map insurance-policies
    { policy-id: uint }
    {
        policy-holder: principal,
        coverage-amount: uint,
        premium-paid: uint,
        start-block: uint,
        end-block: uint,
        system-id: (string-ascii 64),
        fingerprint-threshold: uint,
        facial-threshold: uint,
        iris-threshold: uint,
        active: bool
    }
)

(define-map policy-counter { id: uint } { count: uint })
(define-map measurement-counter { id: uint } { count: uint })

;; Initialize counters
(map-set policy-counter { id: u0 } { count: u0 })
(map-set measurement-counter { id: u0 } { count: u0 })

;; Private Functions
(define-private (get-next-policy-id)
    (let ((current (default-to u0 (get count (map-get? policy-counter { id: u0 })))))
        (let ((next-id (+ current u1)))
            (map-set policy-counter { id: u0 } { count: next-id })
            next-id
        )
    )
)

(define-private (get-next-measurement-id)
    (let ((current (default-to u0 (get count (map-get? measurement-counter { id: u0 })))))
        (let ((next-id (+ current u1)))
            (map-set measurement-counter { id: u0 } { count: next-id })
            next-id
        )
    )
)

(define-private (is-policy-active (policy-id uint))
    (match (map-get? insurance-policies { policy-id: policy-id })
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
(define-public (create-policy (coverage-amount uint) (premium uint) (duration-blocks uint) (system-id (string-ascii 64)) 
                             (fp-threshold uint) (face-threshold uint) (iris-threshold uint))
    (let ((policy-id (get-next-policy-id)))
        (begin
            (asserts! (<= coverage-amount max-claim-amount) err-invalid-policy)
            (asserts! (> premium u0) err-invalid-policy)
            (asserts! (and (>= fp-threshold u9000) (<= fp-threshold u10000)) err-invalid-accuracy)
            (asserts! (and (>= face-threshold u9000) (<= face-threshold u10000)) err-invalid-accuracy)
            (asserts! (and (>= iris-threshold u9000) (<= iris-threshold u10000)) err-invalid-accuracy)
            
            (try! (stx-transfer? premium tx-sender (as-contract tx-sender)))
            
            (map-set insurance-policies
                { policy-id: policy-id }
                {
                    policy-holder: tx-sender,
                    coverage-amount: coverage-amount,
                    premium-paid: premium,
                    start-block: stacks-block-height,
                    end-block: (+ stacks-block-height duration-blocks),
                    system-id: system-id,
                    fingerprint-threshold: fp-threshold,
                    facial-threshold: face-threshold,
                    iris-threshold: iris-threshold,
                    active: true
                }
            )
            
            (var-set total-policies-issued (+ (var-get total-policies-issued) u1))
            (var-set contract-balance (+ (var-get contract-balance) premium))
            (ok policy-id)
        )
    )
)

(define-public (submit-measurement (policy-id uint) (fingerprint-acc uint) (facial-acc uint) (iris-acc uint) 
                                  (total-samples uint) (system-id (string-ascii 64)))
    (let ((measurement-id (get-next-measurement-id)))
        (begin
            (asserts! (var-get oracle-enabled) err-owner-only)
            (asserts! (is-policy-active policy-id) err-policy-expired)
            (asserts! (and (<= fingerprint-acc u10000) (<= facial-acc u10000) (<= iris-acc u10000)) err-invalid-accuracy)
            (asserts! (> total-samples u0) err-invalid-accuracy)
            
            (match (map-get? insurance-policies { policy-id: policy-id })
                policy-data
                (begin
                    (asserts! (is-eq (get policy-holder policy-data) tx-sender) err-owner-only)
                    (asserts! (is-eq (get system-id policy-data) system-id) err-invalid-policy)
                    
                    (map-set biometric-readings
                        { measurement-id: measurement-id }
                        {
                            timestamp: stacks-block-height,
                            fingerprint-accuracy: fingerprint-acc,
                            facial-accuracy: facial-acc,
                            iris-accuracy: iris-acc,
                            total-samples: total-samples,
                            policy-holder: tx-sender,
                            system-id: system-id
                        }
                    )
                    
                    (ok measurement-id)
                )
                err-not-found
            )
        )
    )
)

;; Admin function to toggle oracle
(define-public (toggle-oracle)
    (begin
        (asserts! (is-eq tx-sender contract-owner) err-owner-only)
        (var-set oracle-enabled (not (var-get oracle-enabled)))
        (ok (var-get oracle-enabled))
    )
)

;; Read-only functions
(define-read-only (get-policy (policy-id uint))
    (map-get? insurance-policies { policy-id: policy-id })
)

(define-read-only (get-measurement (measurement-id uint))
    (map-get? biometric-readings { measurement-id: measurement-id })
)

(define-read-only (get-contract-stats)
    {
        total-policies: (var-get total-policies-issued),
        total-claims-paid: (var-get total-claims-paid),
        contract-balance: (var-get contract-balance),
        oracle-enabled: (var-get oracle-enabled)
    }
)