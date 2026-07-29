# Filestream shared `input-logfile.store` cache

## Problem

OTel / multi-receiver setups can create one `input_logfile.InputManager` per filestream receiver (or multiple managers bound to the same `statestore.States`). Each manager calls `openStore` (`manager.go:98` → `store.go:156`), which:

1. Opens `*statestore.Store` via `statestore.StoreFor("")`.
2. Runs `readStates`, loading registry keys matching `<Type>::` into a new in-memory `states.table`.

Memory scales with **(number of ephemeral stores) × (loaded registry entries)**. The on-disk / extension-backed registry is already deduplicated at `libbeat/statestore` (`sharedStore` ref-counting in `store.go:43–85`), but each `openStore` builds another full in-memory copy.

Today each `InputManager.Init` also starts its own registry **cleaner** goroutine against that store (`manager.go:114–148`). With a shared store, N cleaners on one table are redundant and wasteful.

## Goal

- One `*store` (ephemeral + single held `*statestore.Store` handle) per unique **persistent store backend**.
- Reference counting so `store.close` / `persistentStore.Close` run only after **all** users are done.
- **One cleaner per cached store**, started on cache miss and stopped when the last manager releases the entry.
- A draining entry remains cached until the underlying `*store` actually closes. Acquisitions arriving while it drains wait for closure before creating a replacement.
- No behavior change for single-manager Filebeat.

## Non-goals

- Lazy / partial registry load (full `readStates` once per cache entry remains).
- Sharing a single `InputManager` across receivers (wrong isolation layer).
- `input-cursor` package (uses `StoreFor(prefix)` + `SetID`; separate issue).
- Passing `unison.Group` into `openStore` (cleaner cancel is store-owned, not Beat-group-owned).

## Why cache key is only the persistent store (not `prefix`)

**Checked in tree:**

| Layer | What selects storage | Filestream behavior |
|-------|----------------------|---------------------|
| OTel / Filebeat registry | `filebeat/beater/store.go` `openStateStore` | Backend from path + backend name. `otelstorage.NewFileStorage` receives the ID returned by `otelReceiverIDFromBeat`, which is currently derived from `info.Beat` (normally `filebeat`), not the OTel component/receiver instance ID. Receivers using the same Filebeat state store therefore reach the same registry namespace. |
| `statestore.States.StoreFor` | `filebeatStore.StoreFor(typ)` (`store.go:162–166`) | Chooses file vs Elasticsearch registry for the beat; **`typ` is not the filestream registry key prefix**. Filestream passes **`""`**. |
| `input-logfile.openStore` | `store.go:159` | Always `StoreFor("")`. |
| `readStates` `prefix` | `store.go:941–942` | **`InputManager.Type`** (e.g. `filestream`)—filters which keys are loaded into **ephemeral** memory only; does **not** open a different persistent store. |

Registry key namespaces (`filestream::<input-id>::…`) live **inside** the same persistent store. Receivers using the same Filebeat registry path/backend and beat store share that namespace; different registry paths/backends get separate `globalStores` entries. Therefore the package cache is keyed only by the shared persistent backend identity, not by `readStates` prefix.

**Invariants:** `input-logfile` always calls `StoreFor("")`, and production filestream managers always use `Type == "filestream"`. The cache relies on both invariants. On cache miss, `readStates` still receives the caller’s prefix, but the prefix is not part of the cache key because it is hardcoded to `filestream` for this package in production. Add assertions/tests around these invariants so a future caller cannot silently violate them. Unit tests that intentionally exercise alternate prefixes continue to call `openStore` directly and bypass the cache.

Contrast: `input-cursor` calls `StoreFor(prefix)` and `SetID` (`input-cursor/store.go:134–139`)—out of scope.

## Cache key

`openStore` / `acquireStore` always call `statestore.StoreFor("")`. Within a given `States`, that always selects the same underlying backend store (Filebeat: `registry.Get(storeName)` — see `beater/store.go:162–166`). No need to key on the `StoreFor` argument or on `readStates` prefix.

**Cache key = States `storeKey`** — the identifier of the underlying shared registry backend.

In Filebeat this is already `filebeatStore.storeKey`:

```go
// beater/store.go
func storeKey(resolvedPath, backendName string) string {
    // e.g. "memlog:///path/to/data/registry"
    //      "otel_file_storage:///path/..."
    return backendName + "://" + resolvedPath
}
```

`globalStores` is already keyed by this string. Two `filebeatStore` wrappers with the same `storeKey` share `sharedRegistries` → same persistent backend → must share one filestream `*store`.

**Required API** on `statestore.States` (not on `*Store`):

```go
// StoreKey returns a process-wide identifier for the underlying registry
// backend used by StoreFor. Equal keys mean the same persistent store.
func StoreKey() string
```

- `filebeatStore.StoreKey()` → `s.storeKey`
- Test doubles → any stable unique string per backend instance
- A `statestore.States` implementation that cannot derive a more specific key may return a documented process-wide constant. That intentionally places every instance using that constant in one cache domain.

**Not used as cache key:**

- `StoreFor("")` argument (always `""` for filestream)
- `*statestore.Store` wrapper pointer / `sharedStore.name` alone
- `InputManager.Type` / `readStates` prefix

Lookup flow: `key := states.StoreKey()` → hit/miss on `entries[key]` → on miss `StoreFor("")` + `readStates`.

## Data structures

New file `beats/filebeat/input/filestream/internal/input-logfile/store_cache.go`:

```text
var globalStoreCache storeCache

type storeCacheEntry struct {
    state       initializing | active | draining
    ready       chan struct{}       // closed when initialization succeeds/fails
    closed      chan struct{}       // closed after the underlying *store closes
    initErr     error
    store       *store
    users       int                 // active manager acquisitions
    cancel      context.CancelFunc  // stops the cleaner
    cleanerDone sync.WaitGroup
    interval    time.Duration       // first initializer's interval wins
}

type storeCache struct {
    mu      sync.Mutex
    entries map[string]*storeCacheEntry // States.StoreKey() -> entry
}
```

Store the `storeKey` and a final-close callback on `*store` for O(1) removal and notification when its refcount reaches the free state.

Use a package logger created independently of any receiver, for example `logp.NewLogger("filestream.store")`, for `openStore`, `readStates`, store-close errors, and the cleaner. Do not derive the shared logger from whichever manager happens to initialize the entry.

Test hook: `resetStoreCacheForTest()` + `t.Cleanup`. It must handle entry state explicitly: fail/wake initializing entries, cancel and join active cleaners before releasing their cache-owned references, and wait for already-draining entries without releasing their cache reference a second time. Tests using this hook must not run in parallel with other cache tests.

### Debug lifecycle logging

Add debug logs using `sharedStoreLogger`; no metrics are needed. Log state transitions and waits, not every short-lived `store.Retain`/`Release`.

Recommended events:

- cache lookup miss and insertion of an `initializing` placeholder;
- acquisition waiting for an existing initializer;
- initialization success, including key, cleanup interval, and initial manager-user count;
- initialization failure and placeholder removal;
- cache hit and resulting manager-user count;
- manager release and resulting manager-user count;
- transition from `active` to `draining`;
- acquisition waiting for a draining entry to close;
- cleaner start, cancellation requested, and cleaner stopped;
- release of the cache-owned reference;
- final store close and removal of the draining entry;
- completion of a draining wait, including elapsed wait time.

The cache key may be logged at debug level. Do not attach receiver/component fields to these messages because one entry can be shared by several receivers.

## Acquire / release API

```go
func acquireStore(states statestore.States, prefix string) (*store, error)
func releaseAcquiredStore(s *store)
```

`prefix` is for **`readStates` on cache miss only**; not part of the cache key.

### Cache entry ownership

`concert.RefCount` has an implicit initial owner: its zero value reaches the free state on its first `Release`. Ownership is assigned as follows:

| Ref | Who |
|-----|-----|
| Initial/implicit ref | Cache entry, from successful `openStore` until final draining |
| Manager ref | One `Retain` per successful `acquireStore`; released by `releaseAcquiredStore` |
| Short-lived ref | Existing `getRetainedStore` calls; unchanged |

The cleaner does **not** retain the store. The cache entry's initial reference keeps the store alive until the cleaner has been canceled and joined. This avoids leaking the implicit initial owner.

### Miss / initializing path

1. `key := states.StoreKey()`.
2. Under the cache mutex, insert an `initializing` placeholder with `ready` and `closed` channels before doing any I/O.
3. Release the mutex and have only the initializer call `openStore(sharedStoreLogger, states, prefix)` (`StoreFor("")` + `readStates`).
4. Other acquisitions finding `initializing` capture the entry and `ready`, release the mutex, and wait. After wakeup, they return that entry's `initErr` if initialization failed; otherwise they retry the lookup and acquire the now-active entry. They do not call `openStore`.
5. On initialization failure, record `initErr`, remove the placeholder, close `ready` and `closed`, and return the same error to current waiters. A later acquisition may retry with a new placeholder.
6. On success:
   - The cache entry takes ownership of `openStore`'s implicit initial reference.
   - Compute the cleanup interval from the initializing `States`; default to 5m. This first interval wins for the lifetime of the entry.
   - Create the cleaner context and account for its goroutine in `cleanerDone` before publishing the entry.
   - Install a store-close callback that removes this exact entry and closes `entry.closed` after `closeStore` finishes.
   - `Retain()` once for the initializing manager and set `users = 1`.
   - Publish `active`, close `ready`, and start the one cleaner using `sharedStoreLogger`.

### Hit path

1. For an `active` entry, increment `users` and `Retain()` for the new manager while holding the cache mutex.
2. Do **not** call `readStates`; do **not** start another cleaner.

### Draining acquisition path

An acquisition that finds a `draining` entry must not create or reuse another ephemeral store. It captures `entry.closed`, releases the cache mutex, waits for the old store to close, and retries from the beginning. This guarantees that at most one ephemeral table for a cache key is live, including during receiver reload and shutdown overlap.

### Release path (`releaseAcquiredStore`)

For a non-final manager release, decrement `users` under the cache mutex, unlock, and release that manager's store reference.

On the last manager release (`users` → 0):

1. Under the cache mutex, change the entry from `active` to `draining`, but **leave it in `entries`** so new acquisitions wait on `closed`.
2. Unlock and call `entry.cancel()`.
3. Wait for `cleanerDone`; the cache-owned initial reference guarantees that the store cannot close while the cleaner runs.
4. Release the last manager reference.
5. Release the cache-owned implicit initial reference.
6. Any in-flight `getRetainedStore` references keep the store alive. Their final `Release` eventually reaches the free state and runs `closeStore`.
7. After `closeStore` completes, the installed callback removes the entry only if the map still points to that exact entry, then closes `entry.closed`. Waiting acquisitions wake and may initialize a replacement.

Do not remove the entry at `users == 0`, and do not close `persistentStore` directly from the cache layer.

### Ref-count layering

| Layer | Mechanism | Purpose |
|-------|-----------|---------|
| Manager acquire | cache `users` + `store.Retain` / `releaseAcquiredStore` | N managers; last one cancels cleaner + starts draining |
| Cache entry | `openStore`'s implicit initial reference | Keeps the store and cleaner alive until draining |
| Cleaner | cache-owned reference + `cleanerDone` | No separate retain; cancel and join it before releasing the cache reference |
| Short-lived use | `getRetainedStore` / `defer Release` | Unchanged |
| Resource / ACK | `resource.pending` | Unchanged |

### `openStore` vs `acquireStore`

No split/`openStoreWithPersistent`. `openStore` stays as today’s uncached open (`StoreFor("")` + `readStates`).

- **Production** (`InputManager.init`): call `acquireStore` (cache + cleaner).
- **Cache miss:** `acquireStore` calls `openStore`.
- **Unit tests** (`store_test.go`, `testOpenStore`, integration): may keep calling `openStore` directly to bypass cache/cleaner.

`StoreKey()` lives on `States`, so cache lookup does not need an already-open `*statestore.Store`. Do **not** pass `unison.Group` into `openStore`.

`StoreFor("")` and the `filestream` read prefix are explicit package invariants. They are not added to the cache key.

## `InputManager` wiring (Option A)

**Option A:** change the helper to `init(group unison.Group)`. Its existing `sync.Once` guards the complete manager initialization: acquire the cached store, create the ACK channel/writer, initialize the ID map, and install the shutdown waiter. The cleaner is **not** started from `Init` via `group.Go`; it remains cache-owned.

| Location | Change |
|----------|--------|
| `Init(group)` | Call `init(group)`; all setup and waiter installation happen inside its existing `sync.Once`. |
| `init(group)` | Require a non-nil group on the first call; `acquireStore(...)`, initialize manager state, and install the thin shutdown waiter. |
| `Create()` | Call `init(nil)` as an initialization check. After successful `Init` this is an idempotent no-op. If `Create` is the first call, return an `Init required` error before acquiring resources. |
| `shutdown()` | `ackUpdater.Close()` + `releaseAcquiredStore(cim.store)`. |
| Remove | Cleaner start + `cleaner.run` from `Init`’s `group.Go` body. |

`getRetainedStore` and inputs are unchanged.

**First-call contract:** `Init(group)` must be the first call that reaches `init`. If `Create` calls `init(nil)` first, the `sync.Once` records an initialization error and the manager remains failed; it does not acquire a store or start an ACK writer/cleaner. This makes `Init`-before-`Create` explicit and prevents direct callers/tests from creating an owner with no shutdown path.

**Why still use `Group`:** per-manager lifecycle — when that Beat’s task group cancels, close this manager’s `ackUpdater` and drop its acquire. Cleaner lifetime is **independent** of any single manager’s group (cancel only on last `releaseAcquiredStore`).

### ACK writer setup and ownership

The ACK writer is existing behavior, not a new responsibility introduced by the cache:

1. `InputManager.init()` currently creates `cim.ackCH = newUpdateChan()` and `cim.ackUpdater = newUpdateWriter(store, cim.ackCH)` immediately after `openStore`.
2. `newUpdateWriter` starts its own background `unison.TaskGroup` routine. It waits for scheduled, acknowledged cursor updates on `ackCH`.
3. Each `managedInput` created by that manager receives the manager's `ackCH`.
4. Each harvester connects to the publishing pipeline with `newInputACKHandler(ackCH)` as its event listener.
5. When publishing an event with a cursor update, filestream updates the in-memory resource and puts an `*updateOp` in `event.Private`; it does **not** persist the cursor yet.
6. After the output pipeline acknowledges the event, `newInputACKHandler` extracts the acknowledged `updateOp` values and sends a coalesced `scheduledUpdate` to `ackCH`.
7. The ACK writer consumes the update and calls `updateOp.Execute(store, n)`, which writes the acknowledged cursor to `persistentStore` and releases the update's pending resource ownership.

This preserves the delivery guarantee: persisting a cursor before its event is acknowledged could make a restart skip an event that was never delivered. Deferring the persistent write until ACK may replay an event after a crash, but does not advance the registry beyond confirmed delivery.

The writer is asynchronous because registry I/O can block. The custom `updateChan` also coalesces multiple acknowledged updates for the same resource, keeping ACK callbacks lightweight and limiting redundant persistent writes.

The writer remains **per manager**, even though the underlying `*store` is shared:

- Its ACK callbacks belong to the pipeline clients created by that manager's inputs.
- Existing ACK ordering/coalescing assumptions are scoped to those callbacks.
- Sharing the writer in the store cache would require proving ordering across independent receiver pipelines and would move ACK lifecycle/flush behavior into the cache. That is unnecessary for the memory fix.

The manager's retained store reference keeps the store alive while its ACK writer runs. During shutdown, `ackUpdater.Close()` stops the writer and synchronously executes updates already queued in `ackCH`; only then does `releaseAcquiredStore` drop the manager reference. Moving waiter installation into `init(group)` ensures creation of the ACK writer and creation of its shutdown owner happen in the same `sync.Once` execution.

### Thin Init goroutine (replaces today’s cleaner+shutdown goroutine)

**Today** (`manager.go:114–148`): `Init` does `getRetainedStore()`, then `group.Go` runs `cleaner.run` and on exit `defer store.Release()` + `defer cim.shutdown()`. One goroutine owns both GC and manager teardown. The extra `Retain` exists because that goroutine is a store owner (the cleaner).

**After this change:** GC moves to the cache (the cache entry's implicit reference owns the store while the cleaner runs). `init(group)` creates the waiter that tears down **this manager** when the Beat group cancels:

```go
func (cim *InputManager) Init(group unison.Group) error {
    return cim.init(group)
}

func (cim *InputManager) init(group unison.Group) error {
    cim.initOnce.Do(func() {
        if group == nil {
            cim.initErr = errors.New("input manager Init must be called before Create")
            return
        }

        // acquireStore + ackCH/ackUpdater/ids initialization
        // ...

        // beats#45034: ensure the goroutine is running so shutdown is armed,
        // otherwise the manager’s acquireStore Retain is never released.
        waitRunning := make(chan struct{})
        err := group.Go(func(canceler context.Context) error {
            waitRunning <- struct{}{}
            <-canceler.Done()
            cim.shutdown() // ackUpdater.Close + releaseAcquiredStore
            return nil
        })
        if err != nil {
            cim.shutdown()
            cim.initErr = fmt.Errorf("can not start input manager shutdown waiter: %w", err)
            return
        }
        <-waitRunning
    })
    return cim.initErr
}
```

**No `getRetainedStore` / no store `Retain` in this goroutine.** It does not touch the store. Manager ownership is solely the `Retain` from `acquireStore` inside `init()`, released by `shutdown` → `releaseAcquiredStore`.

**Why keep `waitRunning` (beats#45034):**
If `group.Go` accepts the task but the function never runs (Beat shutting down immediately), and `init` returned successfully, nothing would call `shutdown()` → manager’s acquire `Retain` leaks → store never reaches free → Filebeat shutdown can hang. Waiting until the waiter has started arms `shutdown` on cancel (or `init` fails and calls `shutdown` itself if `group.Go` errors).

**What moved where:**

| Responsibility | Today | After |
|----------------|-------|-------|
| Start cleaner | `Init` `group.Go` | cache miss in `acquireStore` |
| Cleaner store lifetime | `getRetainedStore` in `Init` | cache entry's implicit initial reference |
| Stop cleaner | Beat `group` cancel | last `releaseAcquiredStore` → draining + `cancel()` + join |
| Manager `shutdown` | same `group.Go` as cleaner | thin `group.Go` waiter only |
| Manager store acquire | implicit / shutdown `Release` | `acquireStore` `Retain` |

## Concurrency

- Do not hold `globalStoreCache.mu` across `readStates` / disk I/O.
- An `initializing` placeholder serializes `openStore` per key without holding the global mutex during I/O.
- An `active` entry can be retained only while holding the cache mutex, before it can transition to `draining`.
- A `draining` entry remains in the map. New acquisitions wait on `closed`; they never revive it or open a competing store.
- The store-close callback removes by key **and entry identity**, preventing an old callback from deleting a later entry.
- Do not call `store.Release` while holding `globalStoreCache.mu`, because a final release invokes the close callback, which also takes that mutex.

## Correctness notes

### Shared ephemeral state

One `ephemeralStore.table` per persistent backend. Per-input isolation: `SourceIdentifier` (`filestream::<id>::`).

### One cleaner

`gcStore` locks `ephemeralStore.mu`. Single cleaner per backend is enough.

If equal cache keys are acquired through `States` values with different cleanup intervals, the first initializer's positive interval (or the 5m default) wins until that cache entry closes. Cleanup intervals are not independently configured in the supported multi-receiver setup, so no interval arbitration is needed for this change.

The store and cleaner use the package-level `sharedStoreLogger`, which contains no receiver-specific fields.

### Multiple `ackUpdater`s

One per manager; existing per-resource mutexes apply.

### `persistentStore.Close`

After the cleaner has stopped and all manager, cache-owned, and short-lived `store.refCount` references have been released. The close callback removes the draining entry and wakes blocked acquisitions only after `closeStore` returns.

### Shutdown ordering (beats#45034)

Preserve `waitRunning` on the thin Init waiter so the manager’s `acquireStore` retain cannot leak if the task never starts. Cleaner no longer rides that goroutine and does not use the Beat `group` canceler.

### Input shutdown precedes manager draining

In the supported Filebeat lifecycle, the cache should not normally spend meaningful time in `draining`:

1. `v2InputLoader.Init(&inputTaskGroup)` installs the manager shutdown waiter in `inputTaskGroup`.
2. During Filebeat shutdown, `inputs.Stop()`, `modules.Stop()`, and `crawler.Stop()` run explicitly before `Filebeat.Run` returns.
3. Each v2 runner's `Stop()` cancels the input and waits for `managedInput.Run` to return.
4. `managedInput.Run` releases its `groupStore` and `prospectorStore` references on return.
5. Only after the `Run` body returns does the deferred `inputTaskGroup.Stop()` cancel the manager shutdown waiter.
6. The manager closes its ACK writer and calls `releaseAcquiredStore` after all normal input-owned store references have therefore been released.

Consequently, the last manager normally transitions to `draining` and closes immediately after the cleaner stops. Waiting on `entry.closed` remains a defensive correctness mechanism for unusual/direct lifecycle use and races, not an expected part of normal shutdown.

Filestream also bounds harvester-group waiting with `harvesterGroupStopTimeout` (one minute plus the configured `read_until_eof` allowance), and Filebeat bounds publisher draining with `shutdown_timeout` or its default. A blocked backend registry operation in the ACK writer, cleaner, or `persistentStore.Close` can still block shutdown, but that behavior already exists without this cache and is not a new filestream-input hang introduced by the plan.

## Tests

1. **Cache hit:** two `acquireStore` with `States` sharing the same `StoreKey()` → same `*store`; one cleaner.
2. **Refcount / draining:** acquire ×2, one `releaseAcquiredStore` → store+cleaner active; second release → entry becomes draining, cleaner stops, and the cache-owned reference is released.
3. **Wait for short-lived refs:** hold a `getRetainedStore` reference while releasing the last manager; a concurrent acquire must block, the cache must still contain the draining entry, and no second `readStates` may run. Releasing the short-lived ref closes the old store and allows the acquire to create a replacement.
4. **Implicit cache ownership:** after the last manager/cache/short-lived releases, `closeStore` runs exactly once. This test must detect the leak that would result from retaining manager+cleaner without releasing the implicit owner.
5. **Concurrent initialization:** simultaneous misses for one key run `StoreFor`/`readStates` exactly once; all callers receive the same `*store`.
6. **Initialization failure:** all current waiters receive the failure, the placeholder is removed, and a later acquire can retry.
7. **Backend isolation:** different `StoreKey()` values (for example different registry paths) → two entries, two cleaners.
8. **filebeatStore.StoreKey:** matches `storeKey(path, backend)`; two `openStateStore` with same path/backend → equal keys.
9. **Manager Init shutdown:** `Init` + cancel group → that manager’s `shutdown` runs; shared store remains if another manager still holds it.
10. **Manager initialization once:** repeated/concurrent `Init` calls acquire one manager reference and install one shutdown waiter.
11. **Create before Init:** returns the explicit lifecycle error, does not call `StoreFor`, does not add a cache user, and does not start an ACK writer or cleaner.
12. **Concurrent acquire/release:** exercise initialization, active retention, transition to draining, close notification, and retry under `-race`.
13. **Regression:** `store_test.go` / `manager_test.go`; update direct-`Create` tests to initialize and stop a task group, update `States` test doubles with `StoreKey()`, and use `resetStoreCacheForTest` only in non-parallel cache tests.

## Implementation steps

1. Add `StoreKey() string` to `statestore.States`; implement on `filebeatStore` (`s.storeKey`) + all test doubles.
2. Leave `openStore` as-is (uncached open). Add `acquireStore` / `releaseAcquiredStore` that call `openStore` on cache miss.
3. `store_cache.go`: initializing/active/draining entries keyed by `states.StoreKey()`, package-level neutral logger, debug lifecycle logs, cleaner start/cancel/join, close notification, and `resetStoreCacheForTest`.
4. Add a final-close callback to `store.Release`: after the existing `closeStore(s)` hook finishes, notify the cache entry. Keep notification outside `closeStore` so tests that replace the close hook cannot strand a draining entry.
5. `manager.go` Option A: change to `init(group)`, put acquisition/setup/thin shutdown waiter inside its existing `sync.Once`, reject `Create` before `Init`, and remove the per-manager cleaner.
6. `store_cache_test.go` (+ manager Init/share test if practical).
7. `go test -race ./filebeat/input/filestream/internal/input-logfile/...` (and compile-fix all `States` impls).
8. Changelog fragment: **`bug-fix`** (memory growth / duplicate stores with many filestream receivers).
9. Remove planning comment block `manager.go:433–453` after implementation.

## Risks

| Risk | Mitigation |
|------|------------|
| Close while cleaner runs | Cache owns the implicit initial ref; cancel + join cleaner before releasing it |
| Old and new ephemeral stores overlap | Keep a draining entry in the map; new acquisitions wait for `closed` |
| Stale cache entry | Final-close callback removes by key and entry identity, then wakes waiters |
| Miss-path duplicate load/cleaner | Insert an initializing placeholder; one initializer performs `openStore` |
| Initial `concert.RefCount` owner leaked | Treat it as cache ownership and release it exactly once after cleaner shutdown |
| Tests + global cache | `resetStoreCacheForTest`; do not use it from parallel cache tests |
| Wrong / colliding cache keys | Use Filebeat `storeKey` (`backend://path`); tests with two paths |
| Different cleanup intervals | First initializer wins; document/test the invariant |
| Receiver-specific logger retained by shared entry | Create a package-level logger with no receiver fields |

## Accepted decisions

1. **`States.StoreKey()` compatibility:** the interface change is accepted. Implementations that cannot provide a backend-specific identity may return and document a constant key.
2. **Repository boundary:** implementing the change upstream in Beats and bringing it into Elastic Agent through the normal submodule update workflow is accepted.

## Remaining risks / decisions

No unresolved cache-design risk is currently considered blocking. The draining wait is retained defensively and made observable with debug logs, but normal Filebeat shutdown ordering releases input references before manager draining begins.

## Look at later

1. **`statestore.Store` concurrency contract:** all supported backends are expected to be thread-safe, and existing filestream already accesses the handle concurrently. No additional serialization is planned for this change. A later cleanup can audit the contract/comments and align them with actual backend guarantees.
2. **Timed-out harvester goroutines:** `task.Group.Stop` can return after its configured timeout even if a harvester goroutine has not exited. This is existing behavior and prevents the input runner from waiting forever, but a separate follow-up can audit detached-harvester cleanup and ownership after timeout.
