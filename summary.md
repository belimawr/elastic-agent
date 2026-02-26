# Changes needed

## Fleet/Fleet UI
When 'Advanced internal YAML settings' in Fleet UI is used to define:

```yaml
agent:
  features:
    log_input_run_as_filestream:
      enabled: true
```

It is not propagated to Elastic Agent, even when downloading the
policy to run an standalone Elastic Agent, `agent.features` is empty.

## Elastic Agent

`log_input_run_as_filestream` needs to be added to
`pkg/features/features.go`, `cfg` struct

## Filebeat

Changes to read the feature flag
 - In `x-pack/libbeat/management/features.go` NewConfigFromProto:
   parse the source field and add it to the final config
 - In `x-pack/libbeat/management/managerV2.go` logic go restart if
   feature flag changes
