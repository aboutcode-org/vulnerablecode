# How to export VCIO and import in Purl-Sync

## How to export
1. VCIO run exporter command and save the data in a git repo like https://github.com/nexB/vulnerablecode-data

## How to import/sync:
1. Service Actor ( Activitypub admin ) Create a new git Repository instance
2. Service Actor Send a Sync-Activity
3. the Activitypub server pull all git repo data and run import command