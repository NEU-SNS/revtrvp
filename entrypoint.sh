#!/bin/sh

echo "Setting up revtrvp."

/revtrvp $@

echo "Starting traffic listener."

# Setup a cron schedule
echo "* * * * * bash /traffic_monitoring/traffic_listener_cron.sh >> /var/log/cron.log 2>&1
# Don't remove the empty line at the end of this file. It is required to run the cron job" > /traffic_monitoring/traffic_crontab

crontab /traffic_monitoring/traffic_crontab
cron -f