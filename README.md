# IoC Sync Tool: Azure Defender -> Check Point IoC Management

## Instructions for use
1. Edit config.yaml with correct values
2. Execute ./configure.sh
3. Execute the script:

| Command                                                   | What it does                                                 |
| --------------------------------------------------------- | ------------------------------------------------------------ |
| `python defender_ioc_export.py`                           | Normal run: export files + inject new IPv4 IOCs (no cleanup) |
| `python defender_ioc_export.py --test`                    | Dry run — no changes, writes preview files                   |
| `python defender_ioc_export.py --cleanup`                 | Inject new + delete stale IOCs                               |
| `python defender_ioc_export.py --test --cleanup`          | Dry run of full inject + cleanup                             |
| `python defender_ioc_export.py --no-cleanup`              | Force cleanup off                                            |
| `python defender_ioc_export.py --skip-checkpoint`         | Export files only                                            |
| `python defender_ioc_export.py --config /path/other.yaml` | Use alternate config                                         |
