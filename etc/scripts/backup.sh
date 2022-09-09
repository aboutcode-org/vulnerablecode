
# backup current Db

DBDUMP=vcio-db-dump-$(date +"%Y-%m-%d_%H%M").dump
echo "Backup vulnerablecode current DB to: $DBDUMP"
sudo -u postgres pg_dump --format=c vulnerablecode > $DBDUMP
