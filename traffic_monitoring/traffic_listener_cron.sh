#!/bin/sh

# This is supposed to be run as a cronjob.
# If it is run every X minutes, then this script
# emails the network traffic for the past 30 minutes

pcapfilename="/traffic_monitoring/traffic.pcap"
command="tcpdump -i net1 icmp -w ${pcapfilename}"
working=$(ps ax | grep "${command}" | wc -l)

# Kill tcpdump and collect packet capture.
echo "Ending packet cature."
while [ $working -gt 1 ];
do
	pid=$(ps ax | grep "${command}" | awk '{print $1}')
	kill $pid
	sleep 1
	working=$(ps ax | grep "${command}" | wc -l)
done


if [ -f "${pcapfilename}" ]; then
	echo "Adding the packet capture script."
    # Send packet capture.
    current_time=$(date "+%Y%m%d_%H%M%S")
    cp ${pcapfilename} "/var/spool/revtr/traffic/traffic_capture_${current_time}"
	#python3 /traffic_monitoring/send_email.py ${pcapfilename}
fi


# Now restart
echo "Restarting packet capture."
while [ $working -le 1 ];
do
	# Reboot if needed
	tcpdump -i net1 icmp -w ${pcapfilename} &
	sleep 1
	working=$(ps ax | grep "${command}" | wc -l)
done


