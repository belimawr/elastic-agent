# Fallback mechanism for Filestream running as Log input

The Filestream input can be ran instead of the Log input using
@beats/filebeat/input/logv2. See @beats/filebeat/input/logv2/README.md
for details.

Our job is to explore possibilities of a fallback mechanism, this fall
back consists on making a backup of the Store that is opened
@beats/filebeat/beater/store.go, see openStateStore function.

Constraints:
 - The solution needs to work for all ways to run Log/Filestream inputs:
   - Standalone Filebeat (entrypoint @beats/filebeat)
 - There is no specific signal from the Elastic Agent that Filestream
   should run instead of the Log input, nor there is any signal that
   this is being rolled back
 - The only signal we can rely on is the feature flag
   `features.log_input_run_as_filestream.enabled`.

The goal is to have a workflow like the one described below:

1.1: Filebeat starts and looks for the feature flag.
1.2: If it is false: Filebeat looks for the backup (there can be only one, a hard-coded path), if it exists, the backup is restored, the "current" registry is fully overridden.
1.3: Filebeat continues with its initialisation, with the backup as its current store

To enable the feature flag:
2.1: Filebeat is stopped
2.2: The configuration is changed (filebeat.yml edited, Elastic Agent has a new policy, etc)
2.3: Filebeat starts and looks for the feature flag
2.4: The flag is true: Filebeat makes a backup of the registry, then continues with its initialisation
2.5: Inputs start, if it is a Log input, Filestream is started
instead. The migration happens (take_over: true) (no change in the current migration logic).
2.6: Business as usual after the migration

To roll back
3.1: Filebeat is stopped
3.2: The configuration is changed (filebeat.yml edited, Elastic Agent has a new policy, etc)
3.3: GOTO 1.2


The questions I need you to answer right now:
1. When Filebeatreceiver is running and there is a feature flag
   change, is it (the process) always restarted?
2. Is this workflow feasible? If the Log/Filestream input are running
   as Filebeatreceiver, can we correctly pass the feature flag and
   ensure Filebeat is stopped/started?

