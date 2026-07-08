# IoC Sync Tool: Azure Defender -> Check Point IoC Management

## Instructions for use
1. Edit config.yaml with correct values
2. Execute ./configure.sh
3. Execute the script:

| Command                                            | Behavior                      |
| -------------------------------------------------- | ----------------------------- |
| `python defender_ioc_export.py`                    | Export + upsert new IPv4 IOCs |
| `python defender_ioc_export.py --test`             | Dry run, writes preview files |
| `python defender_ioc_export.py --cleanup`          | Upsert + delete stale IOCs    |
| `python defender_ioc_export.py --test --cleanup`   | Dry run of full sync          |
| `python defender_ioc_export.py --no-cleanup`       | Force cleanup off             |
| `python defender_ioc_export.py --skip-checkpoint`  | Export only                   |
| `python defender_ioc_export.py -i input.json`      | Load from JSON file           |
| `python defender_ioc_export.py -i input.csv`       | Load from CSV file            |
| `python defender_ioc_export.py -i test.csv --test` | Full offline dry run          |
