# Hybrid mode: where `filebeatreceiver` reads config

## Single file that reads receiver config

- `beats/x-pack/libbeat/cmd/instance/beat.go`
  - Function: `NewBeatForReceiver(...)`
  - This is where receiver config is converted to Beat config and feature flags are parsed:
    - `b.RawConfig = cfg`
    - `cfg.Unpack(&b.Config)`
    - `features.UpdateFromConfig(b.RawConfig)`

## Receiver-side handoff into that file

- `beats/x-pack/filebeat/fbreceiver/config.go`
  - `Config` uses `mapstructure:",remain"`:
    - `Beatconfig map[string]interface{}`
  - OTel receiver config is stored as a raw map here.

- `beats/x-pack/filebeat/fbreceiver/factory.go`
  - Function: `createReceiver(...)`
  - Passes `cfg.Beatconfig` to:
    - `xpInstance.NewBeatForReceiver(...)`

## Agent/Hybrid path that produces receiver config

1. `internal/pkg/agent/application/coordinator/coordinator.go`
   - `updateManagersWithConfig(...)` calls:
   - `c.otelMgr.Update(c.otelCfg, ..., otelModel.Components)`

2. `internal/pkg/otel/manager/manager.go`
   - `buildMergedConfig(...)` calls:
   - `translate.GetOtelConfig(...)`

3. `internal/pkg/otel/translate/otelconfig.go`
   - `getReceiversConfigForComponent(...)` builds `filebeatreceiver` config.
   - For filebeat receiver, this is where:
     - `features.log_input_run_as_filestream.enabled`
     is injected into the receiver config map.

4. `internal/pkg/otel/manager/execution_subprocess.go`
   - `startCollector(...)` marshals merged conf to YAML and writes it to collector `stdin`.

5. `internal/edot/otelcol/components.go`
   - Registers `fbreceiver.NewFactory()` in OTel receiver factories.

## Where component features come from

- `pkg/component/component.go`
  - Component construction sets:
    - `Features: featureFlags.AsProto()`

- `pkg/features/features.go`
  - `AsProto()` sets `Source: f.source`.
  - `source` is populated by `setSource(...)` from parsed `agent.features.*`.

## Practical debug checkpoints

1. Confirm `component.Features.Source` contains:
   - `agent.features.log_input_run_as_filestream.enabled`
2. Confirm translated receiver config contains:
   - `features.log_input_run_as_filestream.enabled`
3. Confirm collector merged config hash changes (OTel manager) when flag flips.
4. Confirm `NewBeatForReceiver(...)` receives that key in `receiverConfig` and `features.UpdateFromConfig(...)` applies it.
