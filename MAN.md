SYSDIAG-ANALYZER(1)           General Commands Manual          SYSDIAG-ANALYZER(1)

**NAME**

       sysdiag-analyzer - Systemd & System Health Diagnostic Tool

**SYNOPSIS**

       **sysdiag-analyzer** \[*GLOBAL OPTIONS*] *COMMAND* \[*COMMAND OPTIONS*] \[*ARGUMENTS*...]

**DESCRIPTION**

       **sysdiag-analyzer** analyzes various aspects of a Linux system running
       systemd to provide a comprehensive health assessment. It examines boot
       performance, service unit health, system and per-unit resource
       utilization (via cgroups v2), system logs for patterns, unit
       dependencies, historical trends, and optionally uses eBPF for process
       tracing, Machine Learning for anomaly detection, and Large Language
       Models (LLMs) for report synthesis.

       The tool is designed to be run periodically (e.g., daily via cron or
       systemd timers) to build a history for trend analysis and ML model
       training, but can also be used for ad-hoc analysis. Root privileges are
       generally required for complete data collection.

**GLOBAL OPTIONS**

       These options apply to most commands.

       **-c, --config** *PATH*
              Path to a custom TOML configuration file. If specified, this file
              is loaded instead of checking the default locations
              (`/etc/sysdiag-analyzer/config.toml`,
              `~/.config/sysdiag-analyzer/config.toml`).

       **--output** *{rich|json}*
              Specify the output format. Defaults to **rich** (formatted text and
              tables for terminals). **json** outputs the raw analysis report as
              a JSON object. (Default: rich)

**COMMANDS**

       **run** \[*OPTIONS*]
              Perform a full system analysis, including boot, health, resources,
              logs, and basic dependency checks. Optionally enables advanced
              analyses like eBPF, ML, LLM, and full dependency graph checks.
              Saves the report to the configured history directory by default.

              **OPTIONS for run:**

              **--since** *TEXT*
                     Analyze logs since this time (e.g., '1 hour ago',
                     'yesterday'). *Currently Not Implemented.*

              **--enable-ebpf**
                     Enable eBPF-based process execution and exit tracing using
                     the `bcc` library. Requires root privileges and the `bcc`
                     library and matching kernel headers to be installed
                     (`sysdiag-analyzer[ebpf]` extra). Tracing occurs only
                     during the `sysdiag-analyzer run` execution.

              **--analyze-full-graph**
                     Perform full systemd dependency graph analysis to detect
                     circular dependencies. Requires the `networkx` library to
                     be installed (`sysdiag-analyzer[full-graph]` extra). Note:
                     Relies on parsing `systemctl list-dependencies` output,
                     which might be inaccurate on some systemd versions.

              **--analyze-ml**
                     Perform Machine Learning-based anomaly detection on unit
                     metrics compared to historical data. Requires pre-trained
                     models (see `retrain-ml` command) and the ML dependencies
                     to be installed (`sysdiag-analyzer[ml]` extra).

              **--analyze-llm**
                     Perform Large Language Model-based synthesis of the
                     analysis report. Requires LLM dependencies (`ollama`
                     client, `sysdiag-analyzer[llm]` extra) and a configured,
                     running Ollama instance with a downloaded model. See
                     CONFIGURATION FILE and OLLAMA SETUP sections.

              **--llm-model** *TEXT*
                     Override the LLM model specified in the configuration file
                     when using `--analyze-llm`. Useful for quick experiments
                     without modifying the config file.

              **--no-save**
                     Prevent the generated analysis report from being saved to
                     the history directory. Retention policies will also not be
                     applied.

       **config show** \[*OPTIONS*]
              Display the currently loaded (merged) configuration, showing the
              result of merging default values with any found configuration
              files (or the specified `--config` file). Useful for verifying
              which settings are active.

       **retrain-ml** \[*OPTIONS*]
              Load historical data from the configured history directory and
              retrain the Machine Learning anomaly detection models (Isolation
              Forest per unit). Saves the trained models and scalers to the
              configured models directory. Requires root privileges if writing
              to the default location (`/var/lib/sysdiag-analyzer/models`) and
              ML dependencies (`sysdiag-analyzer[ml]` extra).

              **OPTIONS for retrain-ml:**

              **-n, --num-reports** *INTEGER*
                     Number of recent history reports to load and use for
                     training. (Default: 50)

       **show-history** \[*OPTIONS*]
              List metadata (filename, size, timestamp) for recently saved
              analysis reports found in the configured history directory.

              **OPTIONS for show-history:**

              **-n, --limit** *INTEGER*
                     Number of recent reports to show metadata for. (Default: 5)

       **analyze-boot**
              Run only the boot performance analysis module.

       **analyze-health**
              Run only the service health analysis module (failed/flapping
              units, problematic sockets/timers).

       **analyze-resources**
              Run only the resource utilization analysis module (system-wide,
              per-unit cgroup stats, child process groups).

       **analyze-logs** \[*OPTIONS*]
              Run only the log analysis module, scanning for OOM events and common
              error/warning patterns.

              **OPTIONS for analyze-logs:**

              **-b, --boot** *INTEGER*
                     Specify the boot offset relative to the current boot (0 =
                     current, -1 = previous, etc.). (Default: 0)

              **-p, --priority** *INTEGER*
                     Minimum syslog priority level to analyze (0=emerg ...
                     4=warning ... 7=debug). Filters messages less severe than
                     this level. (Default: 4)

       **analyze-unit** *UNIT_NAME*
              Perform a focused analysis on a specific systemd unit.
              *Currently Not Implemented.*

**CONFIGURATION FILE**

       **sysdiag-analyzer** can be configured using a TOML file. Configuration
       is optional; defaults are used if no file is found or if specific keys
       are missing.

       **Locations:**
       Files are loaded and merged in the following order, with later files
       overriding earlier ones:
       1.  Defaults (built-in)
       2.  System-wide: `/etc/sysdiag-analyzer/config.toml`
       3.  User-specific: `~/.config/sysdiag-analyzer/config.toml`
       4.  Override: Path specified via the global `-c, --config` option (if
           used, disables loading from default locations).

       Use `sysdiag-analyzer config show` to see the final merged configuration.

       **Format:** TOML (Tom's Obvious, Minimal Language). See
       `config.toml.example` included with the source code.

       **Sections and Keys:**

       **[llm]**
              Settings for Large Language Model integration (used when
              `--analyze-llm` is passed).

              **provider** = *STRING*
                     Specifies the LLM provider backend. Currently, only
                     **"ollama"** is supported. (Required if using LLM features).
                     Default: *None*

              **model** = *STRING*
                     The name of the model to use within the specified provider.
                     For Ollama, this should be a model name available in your
                     local Ollama instance (e.g., "llama3:latest", "mistral",
                     "codellama:13b"). Can be overridden by the `--llm-model` CLI
                     option. (Required if `provider` is set).
                     Default: *None*

              **host** = *STRING* (Ollama specific)
                     The base URL of the Ollama API endpoint. Only needed if
                     Ollama is running on a different host or port than the
                     default (`http://localhost:11434`).
                     Default: *None* (uses Ollama client default)

              **temperature** = *FLOAT*
                     Controls the randomness of the LLM's output. Lower values
                     (e.g., 0.1, 0.2) make the output more focused and
                     deterministic. Higher values (> 1.0) increase randomness.
                     Default: `0.2`

              **max_tokens** = *INTEGER*
                     The maximum number of tokens (roughly, words or parts of
                     words) the LLM is allowed to generate in its response.
                     Default: `1024`

              **context_window** = *INTEGER*
                     Informational setting representing the model's context
                     window size (maximum input+output tokens). This value might
                     be used by some providers or internally for prompt sizing.
                     Default: `4096`

       **[history]**
              Settings for storing historical analysis reports.

              **directory** = *STRING* (Path)
                     The absolute path to the directory where analysis reports
                     (JSONL.gz format) should be saved. The application needs
                     write permissions to this directory. It will be created if
                     it doesn't exist (with mode 0700).
                     Default: `"/var/lib/sysdiag-analyzer/history"`

              **max_files** = *INTEGER*
                     The maximum number of report files to keep in the history
                     directory. When a new report is saved, if the total number
                     of reports exceeds this limit, the oldest reports (by
                     modification time) will be deleted until the limit is met.
                     Set to `0` or negative to disable retention.
                     Default: `50`

       **[models]**
              Settings related to Machine Learning models used for anomaly
              detection.

              **directory** = *STRING* (Path)
                     The absolute path to the directory where trained ML models
                     (Isolation Forest models and data scalers) are stored. The
                     `retrain-ml` command needs write permissions here. The `run
                     --analyze-ml` command needs read permissions.
                     Default: `"/var/lib/sysdiag-analyzer/models"`

              **anomaly_contamination** = *FLOAT* | *"auto"*
                     The expected proportion of outliers (anomalies) in the
                     dataset, used by the Isolation Forest algorithm during
                     training (`retrain-ml`). Can be set to `"auto"` (recommended)
                     to let the algorithm estimate it, or a float between 0.0
                     and 0.5.
                     Default: `"auto"`

              **min_samples_train** = *INTEGER*
                     The minimum number of historical data points (reports where
                     the unit had relevant metrics) required for a specific unit
                     before an anomaly detection model will be trained for it
                     during `retrain-ml`. Units with fewer samples will be
                     skipped.
                     Default: `10`

**FILES**

       `/etc/sysdiag-analyzer/config.toml`
              System-wide configuration file.

       `~/.config/sysdiag-analyzer/config.toml`
              User-specific configuration file (overrides system-wide).

       `/var/lib/sysdiag-analyzer/history/`
              Default directory for storing historical analysis reports (JSONL.gz
              format). Requires appropriate permissions for the user running
              `sysdiag-analyzer run` (typically root if using default path).

       `/var/lib/sysdiag-analyzer/models/`
              Default directory for storing trained ML models. Requires write
              permissions for `sysdiag-analyzer retrain-ml` (typically root) and
              read permissions for `sysdiag-analyzer run --analyze-ml`.

**USAGE EXAMPLES**

       **Run a standard analysis and save the report:**
              `sudo sysdiag-analyzer run`

       **Run analysis with eBPF tracing and ML detection:**
              `sudo sysdiag-analyzer run --enable-ebpf --analyze-ml`

       **Run analysis and generate LLM summary (requires config):**
              `sudo sysdiag-analyzer run --analyze-llm --llm-model mistral`

       **Run analysis but don't save the report:**
              `sudo sysdiag-analyzer run --no-save`

       **Retrain ML models using last 100 reports:**
              `sudo sysdiag-analyzer retrain-ml --num-reports 100`

       **Show the 10 most recent history report metadata:**
              `sudo sysdiag-analyzer show-history -n 10`

       **Show the currently active configuration:**
              `sysdiag-analyzer config show`

       **Analyze only logs from the previous boot, showing ERR and higher:**
              `sudo sysdiag-analyzer analyze-logs -b -1 -p 3`

       **Analyze resources and output as JSON:**
              `sudo sysdiag-analyzer analyze-resources -o json`

       **Automated Daily Run (Example Crontab Entry):**
              `0 3 * * * /path/to/venv/bin/sysdiag-analyzer run --config /etc/sysdiag-analyzer/config.toml`
              *(Adjust path and ensure necessary permissions)*

       **Automated Daily Run (Example systemd Timer/Service):**
              *(Create `sysdiag-analyzer.service` and `sysdiag-analyzer.timer` unit
              files in `/etc/systemd/system/`. See systemd documentation for
              details.)*

**INTERPRETING OUTPUT**

       **ML Anomaly Detection (`--analyze-ml`)**
              *   **Anomaly Score:** Provided by the Isolation Forest model.
                  Scores are relative; lower scores (typically negative, e.g.,
                  below -0.1 or -0.15) indicate a higher likelihood that the
                  unit's current metrics are anomalous compared to its own
                  history. Scores near 0 or positive are generally considered
                  normal. Thresholds may need tuning based on system behavior.
              *   **Zero Variance Units:** During `retrain-ml`, units whose
                  metrics showed no change across the training history will be
                  skipped. This is often normal for stable units like targets,
                  mounts, scopes, or services that were idle during the entire
                  training period. The `run --analyze-ml` output may list these
                  skipped units if configured.

       **eBPF Process Tracing (`--enable-ebpf`)**
              *   Provides a snapshot of process `exec` (execution) and `exit`
                  events captured *during the analysis run*.
              *   Look for unexpected processes being executed (check `Comm` and
                  `Filename`).
              *   Identify frequently starting/stopping (short-lived) processes,
                  which might indicate configuration issues or instability.
              *   Correlate non-zero `Exit Code` values with service failures or
                  other reported problems.
              *   *Future Work:* Correlate `Cgroup ID` back to specific systemd
                  units for more precise analysis.

       **Child Process Group Monitoring (Resource Analysis)**
              *   Aggregates CPU and Memory usage for processes that are children
                  (or grandchildren, etc.) of systemd service main PIDs but are
                  not directly managed cgroups themselves (common for container
                  runtimes like Docker/Podman, or complex applications).
              *   Identifies groups of processes with the same normalized
                  `Command Name` running under the same `Parent Unit`.
              *   Helps attribute resource consumption of these workloads back to
                  the originating systemd service.
              *   High `Aggr. CPU %` or `Aggr. Memory` for a group indicates
                  significant resource usage by that specific application/container
                  type running under the parent service.

**SECURITY CONSIDERATIONS**

       **Privileges:**
              Many analysis functions require access to system resources that are
              typically restricted to the **root** user. This includes:
              *   Reading cgroup files (`/sys/fs/cgroup`).
              *   Accessing systemd's DBus interface for unit details and control
                  group paths.
              *   Reading the system journal (`journalctl` or native bindings).
              *   Enabling eBPF tracing (`--enable-ebpf`).
              *   Writing to default history and model directories
                  (`/var/lib/sysdiag-analyzer/...`).
              Running `sysdiag-analyzer run` without root privileges (e.g., via
              `sudo`) will likely result in incomplete or inaccurate analysis.

       **SELinux / AppArmor:**
              No specific SELinux or AppArmor policies are included. If running
              in a confined environment, a custom policy allowing access to
              `/sys/fs/cgroup`, `/proc`, systemd DBus sockets, journal files,
              and potentially kernel tracing facilities (for eBPF) would be
              required.

       **Data Storage:**
              Analysis reports and trained ML models are stored locally in the
              directories specified in the configuration (defaults under
              `/var/lib/sysdiag-analyzer/`). Ensure appropriate permissions are
              set on these directories if they contain sensitive system
              information. Reports contain unit names, resource metrics, log
              snippets, process names, etc.

**DIAGNOSTICS / TROUBLESHOOTING**

       *   **Permission Errors:** Usually indicate the need to run the command
           with `sudo` or as root, especially for `run`, `retrain-ml`, or when
           accessing default history/model paths.
       *   **Missing Optional Dependencies:** Errors like "ImportError: No module
           named 'networkx'" or "'bcc' library not installed" indicate a missing
           optional feature set. Install the required extra, e.g., `pip install
           sysdiag-analyzer[full-graph]`, `sysdiag-analyzer[ebpf]`.
       *   **Configuration Issues:** Use `sysdiag-analyzer config show` to verify
           the loaded configuration. Check TOML syntax and file paths.
       *   **eBPF Failures:** Often related to missing `bcc` or incompatible/missing
           kernel headers. Ensure headers match the running kernel (`uname -r`)
           and `bcc` is installed correctly for your distribution. Requires root.
       *   **DBus Errors:** May indicate issues with the systemd DBus service or
           permissions. Check `systemctl status dbus.service`.
       *   **ML Model Errors:** "No pre-trained models found" usually means
           `retrain-ml` needs to be run first after gathering sufficient
           history.
       *   **Ollama Errors:** Ensure the Ollama service is running and the
           specified model is downloaded (`ollama list`). Check the `host` setting
           in the config if Ollama runs non-locally.

**BUGS**

       Report bugs at the project's issue tracker (see `pyproject.toml` URLs).

**AUTHOR**

       Systemd Smartfilter Architect Supreme <sysdiag@example.com>

**SEE ALSO**

       **systemd**(1), **systemctl**(1), **journalctl**(1), **systemd-analyze**(1),
       **cgtop**(1), **ps**(1), **top**(1), **bcc**(8), **ollama**(1), **toml**(5)

sysdiag-analyzer 0.6.0          May 2025                 SYSDIAG-ANALYZER(1)
