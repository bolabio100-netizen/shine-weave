;; ShineWeave - Decentralized Communication Mesh Protocol

;; ===========================
;; Constants
;; ===========================

(define-constant CONTRACT-OWNER tx-sender)

(define-constant ERR-NOT-AUTHORIZED       (err u100))
(define-constant ERR-NODE-NOT-FOUND       (err u101))
(define-constant ERR-NODE-ALREADY-EXISTS  (err u102))
(define-constant ERR-TUNNEL-NOT-FOUND     (err u103))
(define-constant ERR-TUNNEL-ALREADY-EXISTS (err u104))
(define-constant ERR-RATE-LIMITED         (err u105))
(define-constant ERR-INSUFFICIENT-STAKE   (err u106))
(define-constant ERR-INVALID-PAYLOAD      (err u107))
(define-constant ERR-SUBSCRIPTION-ACTIVE  (err u108))
(define-constant ERR-NO-ACTIVE-SUBSCRIPTION (err u109))
(define-constant ERR-NODE-INACTIVE        (err u110))

;; Minimum STX stake required to register a Weave Node (in micro-STX)
(define-constant MIN-NODE-STAKE u1000000)

;; Maximum messages a node can send per block (rate limiting)
(define-constant MAX-MESSAGES-PER-BLOCK u10)

;; Base subscription cost per block (in micro-STX)
(define-constant SUBSCRIPTION-COST-PER-BLOCK u100)

;; Maximum payload length in bytes (ASCII characters)
(define-constant MAX-PAYLOAD-LEN u1024)

;; ===========================
;; Data Maps and Variables
;; ===========================

;; Global message counter (monotonically increasing message ID)
(define-data-var message-nonce uint u0)

;; Global tunnel counter
(define-data-var tunnel-nonce uint u0)

;; Total protocol fees collected
(define-data-var protocol-treasury uint u0)

;; Weave Node registry
;; Each node is identified by its principal (operator address)
(define-map weave-nodes
  principal
  {
    active:           bool,
    reputation:       uint,   ;; 0-1000 reputation score
    stake:            uint,   ;; micro-STX staked
    registered-at:    uint,   ;; block height of registration
    messages-relayed: uint,   ;; lifetime messages relayed
    tunnels-count:    uint    ;; number of tunnels this node participates in
  }
)

;; Communication tunnels between two endpoints (dApps / contracts)
;; tunnel-id => tunnel data
(define-map tunnels
  uint
  {
    endpoint-a:    principal,
    endpoint-b:    principal,
    relay-node:    principal,
    created-at:    uint,
    active:        bool,
    message-count: uint,
    last-activity: uint   ;; block height of last message
  }
)

;; Lookup map: (endpoint-a, endpoint-b) => tunnel-id
;; Endpoints are stored with the lexicographically smaller principal as 'a'
;; to ensure a canonical key regardless of call order.
;; Since Clarity does not support tuple keys with two principals directly,
;; we key on (sender, recipient) from the perspective of the caller.
(define-map tunnel-index
  { endpoint-a: principal, endpoint-b: principal }
  uint
)

;; Messages stored on-chain (lightweight reference log)
(define-map messages
  uint  ;; message-id
  {
    tunnel-id:   uint,
    sender:      principal,
    recipient:   principal,
    payload:     (string-ascii 1024),
    block-sent:  uint,
    delivered:   bool
  }
)

;; Rate limiting: tracks how many messages a principal has sent in the current block
(define-map block-message-counts
  { sender: principal, block-height: uint }
  uint
)

;; Subscriptions: a subscriber pays a node to receive data streams
(define-map subscriptions
  { subscriber: principal, provider: principal }
  {
    active:       bool,
    started-at:   uint,   ;; block height subscription began
    expires-at:   uint,   ;; block height subscription expires
    cost-per-block: uint
  }
)

;; ===========================
;; Private Helpers
;; ===========================

;; Check whether a Weave Node exists and is active
(define-private (is-active-node (node principal))
  (match (map-get? weave-nodes node)
    node-data (get active node-data)
    false
  )
)

;; Get current block-message count for a sender, defaulting to 0
(define-private (get-block-count (sender principal))
  (default-to u0
    (map-get? block-message-counts { sender: sender, block-height: block-height })
  )
)

;; Increment the block-message count for a sender
(define-private (increment-block-count (sender principal))
  (let ((current (get-block-count sender)))
    (map-set block-message-counts
      { sender: sender, block-height: block-height }
      (+ current u1)
    )
  )
)

;; Adjust node reputation by a signed delta (clamped to 0-1000)
(define-private (adjust-reputation (node principal) (delta int))
  (match (map-get? weave-nodes node)
    node-data
      (let (
        (current   (to-int (get reputation node-data)))
        (new-score (+ current delta))
        (clamped   (if (< new-score 0) 0
                     (if (> new-score 1000) 1000 new-score)))
      )
        (map-set weave-nodes node
          (merge node-data { reputation: (to-uint clamped) })
        )
        true
      )
    false
  )
)

;; ===========================
;; Node Management
;; ===========================

;; Register a new Weave Node by staking the minimum required STX
(define-public (register-node)
  (let ((caller tx-sender))
    (asserts! (is-none (map-get? weave-nodes caller)) ERR-NODE-ALREADY-EXISTS)
    (try! (stx-transfer? MIN-NODE-STAKE caller (as-contract tx-sender)))
    (map-set weave-nodes caller
      {
        active:           true,
        reputation:       u500,
        stake:            MIN-NODE-STAKE,
        registered-at:    block-height,
        messages-relayed: u0,
        tunnels-count:    u0
      }
    )
    (ok true)
  )
)

;; Deactivate a node and reclaim staked STX
(define-public (deregister-node)
  (let (
    (caller    tx-sender)
    (node-data (unwrap! (map-get? weave-nodes caller) ERR-NODE-NOT-FOUND))
    (stake     (get stake node-data))
  )
    (asserts! (get active node-data) ERR-NODE-INACTIVE)
    (map-set weave-nodes caller (merge node-data { active: false }))
    (try! (as-contract (stx-transfer? stake tx-sender caller)))
    (ok true)
  )
)

;; Read-only: get node info
(define-read-only (get-node-info (node principal))
  (map-get? weave-nodes node)
)

;; ===========================
;; Tunnel Management
;; ===========================

;; Open a new communication tunnel between two endpoints via a relay node
(define-public (open-tunnel (endpoint-b principal) (relay-node principal))
  (let (
    (caller    tx-sender)
    (tunnel-id (var-get tunnel-nonce))
  )
    ;; Caller is endpoint-a; endpoint-b must differ
    (asserts! (not (is-eq caller endpoint-b)) ERR-INVALID-PAYLOAD)
    ;; Relay node must be active
    (asserts! (is-active-node relay-node) ERR-NODE-INACTIVE)
    ;; No duplicate tunnel in either direction
    (asserts! (is-none (map-get? tunnel-index { endpoint-a: caller, endpoint-b: endpoint-b })) ERR-TUNNEL-ALREADY-EXISTS)
    (asserts! (is-none (map-get? tunnel-index { endpoint-a: endpoint-b, endpoint-b: caller })) ERR-TUNNEL-ALREADY-EXISTS)
    ;; Store the tunnel
    (map-set tunnels tunnel-id
      {
        endpoint-a:    caller,
        endpoint-b:    endpoint-b,
        relay-node:    relay-node,
        created-at:    block-height,
        active:        true,
        message-count: u0,
        last-activity: block-height
      }
    )
    (map-set tunnel-index { endpoint-a: caller, endpoint-b: endpoint-b } tunnel-id)
    ;; Increment relay node tunnel count
    (match (map-get? weave-nodes relay-node)
      node-data
        (map-set weave-nodes relay-node
          (merge node-data { tunnels-count: (+ (get tunnels-count node-data) u1) })
        )
      false
    )
    (var-set tunnel-nonce (+ tunnel-id u1))
    (ok tunnel-id)
  )
)

;; Close a tunnel (only endpoints can close)
(define-public (close-tunnel (tunnel-id uint))
  (let (
    (caller      tx-sender)
    (tunnel-data (unwrap! (map-get? tunnels tunnel-id) ERR-TUNNEL-NOT-FOUND))
  )
    (asserts! (or (is-eq caller (get endpoint-a tunnel-data))
                  (is-eq caller (get endpoint-b tunnel-data)))
              ERR-NOT-AUTHORIZED)
    (asserts! (get active tunnel-data) ERR-TUNNEL-NOT-FOUND)
    (map-set tunnels tunnel-id (merge tunnel-data { active: false }))
    (ok true)
  )
)

;; Read-only: get tunnel info by ID
(define-read-only (get-tunnel-info (tunnel-id uint))
  (map-get? tunnels tunnel-id)
)

;; Read-only: look up a tunnel ID by endpoint pair
(define-read-only (get-tunnel-id (endpoint-a principal) (endpoint-b principal))
  (map-get? tunnel-index { endpoint-a: endpoint-a, endpoint-b: endpoint-b })
)

;; ===========================
;; Messaging
;; ===========================

;; Send a message through a tunnel.
;; The caller must be one of the tunnel endpoints.
;; Rate limiting: max MAX-MESSAGES-PER-BLOCK messages per block per sender.
(define-public (send-message
  (tunnel-id uint)
  (payload   (string-ascii 1024))
)
  (let (
    (caller      tx-sender)
    (tunnel-data (unwrap! (map-get? tunnels tunnel-id) ERR-TUNNEL-NOT-FOUND))
    (msg-id      (var-get message-nonce))
    (block-count (get-block-count caller))
  )
    ;; Tunnel must be active
    (asserts! (get active tunnel-data) ERR-TUNNEL-NOT-FOUND)
    ;; Caller must be an endpoint
    (asserts! (or (is-eq caller (get endpoint-a tunnel-data))
                  (is-eq caller (get endpoint-b tunnel-data)))
              ERR-NOT-AUTHORIZED)
    ;; Rate limit check
    (asserts! (< block-count MAX-MESSAGES-PER-BLOCK) ERR-RATE-LIMITED)
    ;; Payload must not be empty
    (asserts! (> (len payload) u0) ERR-INVALID-PAYLOAD)
    ;; Determine recipient (the other endpoint)
    (let (
      (recipient (if (is-eq caller (get endpoint-a tunnel-data))
                   (get endpoint-b tunnel-data)
                   (get endpoint-a tunnel-data)))
      (relay     (get relay-node tunnel-data))
    )
      ;; Store message
      (map-set messages msg-id
        {
          tunnel-id:   tunnel-id,
          sender:      caller,
          recipient:   recipient,
          payload:     payload,
          block-sent:  block-height,
          delivered:   false
        }
      )
      ;; Update tunnel stats
      (map-set tunnels tunnel-id
        (merge tunnel-data {
          message-count: (+ (get message-count tunnel-data) u1),
          last-activity: block-height
        })
      )
      ;; Update relay node stats and reputation
      (match (map-get? weave-nodes relay)
        node-data
          (map-set weave-nodes relay
            (merge node-data { messages-relayed: (+ (get messages-relayed node-data) u1) })
          )
        false
      )
      (adjust-reputation relay 1)
      ;; Rate limit bookkeeping
      (increment-block-count caller)
      (var-set message-nonce (+ msg-id u1))
      (ok msg-id)
    )
  )
)

;; Mark a message as delivered (called by recipient to confirm receipt)
(define-public (acknowledge-message (msg-id uint))
  (let (
    (caller   tx-sender)
    (msg-data (unwrap! (map-get? messages msg-id) ERR-TUNNEL-NOT-FOUND))
  )
    (asserts! (is-eq caller (get recipient msg-data)) ERR-NOT-AUTHORIZED)
    (asserts! (not (get delivered msg-data)) ERR-TUNNEL-NOT-FOUND)
    (map-set messages msg-id (merge msg-data { delivered: true }))
    (ok true)
  )
)

;; Read-only: get message details
(define-read-only (get-message (msg-id uint))
  (map-get? messages msg-id)
)

;; ===========================
;; Subscription Model
;; ===========================

;; Subscribe to a data provider node for a given number of blocks.
;; Transfers the total cost (cost-per-block * duration) to the provider.
(define-public (subscribe (provider principal) (duration-blocks uint))
  (let (
    (caller   tx-sender)
    (key      { subscriber: caller, provider: provider })
    (existing (map-get? subscriptions key))
    (total-cost (* SUBSCRIPTION-COST-PER-BLOCK duration-blocks))
  )
    ;; Provider must be an active node
    (asserts! (is-active-node provider) ERR-NODE-INACTIVE)
    ;; No duplicate active subscription
    (asserts! (match existing sub (not (get active sub)) true) ERR-SUBSCRIPTION-ACTIVE)
    ;; Transfer payment to provider
    (try! (stx-transfer? total-cost caller provider))
    (map-set subscriptions key
      {
        active:         true,
        started-at:     block-height,
        expires-at:     (+ block-height duration-blocks),
        cost-per-block: SUBSCRIPTION-COST-PER-BLOCK
      }
    )
    (ok true)
  )
)

;; Cancel a subscription (subscriber only; no refund)
(define-public (cancel-subscription (provider principal))
  (let (
    (caller  tx-sender)
    (key     { subscriber: caller, provider: provider })
    (sub-data (unwrap! (map-get? subscriptions key) ERR-NO-ACTIVE-SUBSCRIPTION))
  )
    (asserts! (get active sub-data) ERR-NO-ACTIVE-SUBSCRIPTION)
    (map-set subscriptions key (merge sub-data { active: false }))
    (ok true)
  )
)

;; Read-only: check whether a subscription is currently active and unexpired
(define-read-only (is-subscription-active (subscriber principal) (provider principal))
  (match (map-get? subscriptions { subscriber: subscriber, provider: provider })
    sub-data
      (and (get active sub-data)
           (<= block-height (get expires-at sub-data)))
    false
  )
)

;; Read-only: get subscription details
(define-read-only (get-subscription (subscriber principal) (provider principal))
  (map-get? subscriptions { subscriber: subscriber, provider: provider })
)

;; ===========================
;; Admin / Protocol Functions
;; ===========================

;; Owner can slash a malicious node's reputation
(define-public (slash-node (node principal) (penalty uint))
  (begin
    (asserts! (is-eq tx-sender CONTRACT-OWNER) ERR-NOT-AUTHORIZED)
    (asserts! (is-some (map-get? weave-nodes node)) ERR-NODE-NOT-FOUND)
    (adjust-reputation node (- 0 (to-int penalty)))
    (ok true)
  )
)

;; Read-only: get protocol treasury balance
(define-read-only (get-treasury-balance)
  (var-get protocol-treasury)
)

;; Read-only: get current message nonce (total messages ever sent)
(define-read-only (get-message-nonce)
  (var-get message-nonce)
)

;; Read-only: get current tunnel nonce (total tunnels ever created)
(define-read-only (get-tunnel-nonce)
  (var-get tunnel-nonce)
)
