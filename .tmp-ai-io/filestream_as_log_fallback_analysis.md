# Filestream as Log fallback - feasibility check

## Scope

Task analyzed from `ai-tasks/filestream_as_log_fallback.md`.

Primary questions:
1. If Filebeatreceiver is running and the feature flag changes, is the process always restarted?
2. Is the fallback workflow feasible for Filebeatreceiver (flag propagation + stop/start guarantees)?

## Findings

### 1) Is Filebeatreceiver always restarted on feature flag changes?

Short answer: **No, not always**.

- In receiver mode, Filebeat reads feature flags from receiver config only at startup via `features.UpdateFromConfig(b.RawConfig)` in `beats/x-pack/libbeat/cmd/instance/beat.go`.
- Filebeatreceiver mode installs `otelmanager.NewOtelManager` as the manager factory in `beats/x-pack/libbeat/cmd/instance/beat.go`.
- That manager is effectively a stub (`Start()` no-op, `Enabled()` false) in `beats/x-pack/otel/otelmanager/manager.go`, so it does not push dynamic feature updates into a running receiver.
- Restart behavior is controlled by OTel manager config hashing in `internal/pkg/otel/manager/manager.go`.
  - If merged OTel config hash changes, collector subprocess is stopped and started in `applyMergedConfig`.
  - If hash does not change, update is skipped.
- For this specific flag (`features.log_input_run_as_filestream.enabled`), current component translation path does not inject it into generated receiver config (`internal/pkg/otel/translate/otelconfig.go`), so a policy feature change alone will not necessarily alter merged OTel config, therefore no guaranteed restart.

Net: restart is guaranteed only when configuration diff reaches merged collector config.

### 2) Is the workflow feasible for Filebeatreceiver?

Short answer: **Feasible with caveats**.

- Feasible today in explicit OTel receiver configs (manual `receivers.filebeatreceiver...`) where the flag is set directly in receiver config:
  - Example template includes `features.log_input_run_as_filestream.enabled` in `testing/integration/ess/testdata/filebeat_receiver_log_as_filestream.yml`.
  - Integration test `testing/integration/ess/otel_log_as_filestream_test.go` validates stop -> reconfigure -> start workflow from Log to Filestream and no duplication.
- Not fully feasible in the policy-to-component auto-translation path (the usual hybrid/Fleet path) without extra plumbing:
  - Translator building receiver config (`internal/pkg/otel/translate/otelconfig.go`) does not add this feature flag.
  - Agent-side feature model in `pkg/features/features.go` does not model this flag.
  - Proto features forwarded with components are not consumed by OTel translation for receiver config.

Net: the required workflow is feasible for standalone Filebeat and for manually defined receiver configs, but **not end-to-end for auto-generated Filebeatreceiver configs until flag propagation is added**.

## Recommended implementation direction

1. Add explicit propagation of `log_input_run_as_filestream` into generated Filebeatreceiver config in `internal/pkg/otel/translate/otelconfig.go`.
2. Ensure policy updates that toggle this flag produce a merged collector config diff so OTel manager restarts collector (`internal/pkg/otel/manager/manager.go` already handles restart-on-config-change).
3. Implement registry backup/restore in Filebeat startup store path (`beats/filebeat/beater/store.go`, `openStateStore`) keyed by `features.LogInputRunFilestream()`.

This matches the required startup-time fallback semantics.

## Unresolved questions

- Should the flag source be `agent.features...` in policy, or a dedicated input/runtime setting propagated to receiver config?
- Should backup path be shared between standalone Filebeat and receiver mode, or receiver-specific (`path.data`) namespaced only?
