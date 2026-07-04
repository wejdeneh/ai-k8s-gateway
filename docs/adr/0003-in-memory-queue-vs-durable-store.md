# ADR 0003: In-Memory Queue vs. Durable Store for Human Approval Queue

## Status
Accepted

## Context
High-risk actions permitted by OPA are suspended in a human-approval queue. If multiple replicas of the gateway run behind a load balancer, they must share state so that:
- Any replica can display the full list of pending actions to operators (`GET /pending`).
- Any replica can process a human resolution request (`POST /approve/{id}`).
- Pending requests do not disappear if a gateway pod restarts or crashes.

## Decision
For Phase 1 (MVP/Demo), we implement an **in-memory thread-safe dictionary** protected by a `threading.Lock`. However, we structure the `app/approval/queue.py` interface explicitly to isolate the storage details. 

For Phase 2 (Roadmap), we establish that a shared **durable key-value store (Redis)** is the required design for production environments.

## Trade-off Analysis

### Option A: In-Memory Queue (Current)
- **Pros**: Zero deployment dependencies (no database setup required), extremely fast, zero infrastructure overhead for local testing.
- **Cons**: Single point of failure (restarts clear the queue), cannot scale horizontally (each pod has its own separate queue).

### Option B: Redis Durable Key-Value Store (Production Standard)
- **Pros**: Survives restarts, supports distributed synchronization, multiple gateway replicas can query a single Redis cluster, supports native TTL eviction for stale approval requests.
- **Cons**: Requires managing a Redis cluster, configuring TLS and credentials, and writing Redis client logic.

## consequences

### Design for Swappability
By encapsulating queue actions inside the `ApprovalQueue` class with distinct methods:
- `enqueue(request)`
- `list_pending()`
- `resolve(request_id)`

The FastAPI routes are completely decoupled from the storage layer. Swapping the storage backend to Redis in production requires modifying only the `ApprovalQueue` implementation, leaving `app/main.py` untouched.
