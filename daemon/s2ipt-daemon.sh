#!/bin/bash

# checking if executed as superuser
if [ "$EUID" -ne 0 ]
then
	echo "You need to have root privileges to run this script."
	echo "Please try again, this time using 'sudo'. Exiting."	
  exit
fi


DAEMON_CONFIG=/opt/s2ipt/daemon/daemon.config
UPDATE_CONFIG=/opt/s2ipt/daemon/s2ipt-update.config

# getting today's date as number of day in year
DATE=$(date +%j)
# getting current year
YEAR=$(date +%Y)

# reading config files
IFS="="
# reading the interval of update, expressed in days
while read -r name value
do
	if [ $name = 'update_interval_time_days' ]
	then
		INTERVAL=$value
	fi
done < $UPDATE_CONFIG

# reading the day of last update, expressed in number of days in year
while read -r name value
do
	if [ $name = 'last_update' ]
	then
		LAST_UPDATE=$value
	elif [ $name = 'update_year' ]
	then
		LAST_UPDATE_YEAR=$value
	fi
	fi

done < $DAEMON_CONFIG

# checking if INTERVAL is a number
re='^[0-9]+$'
if ! [[ $INTERVAL =~ $re ]] ; then
   echo "Error in 's2ipt-update.config' file: interval must be a number between 1 and 365" >&2; exit 1
fi

# checking if INTERVAL is between 1 and 365
if [ $INTERVAL -lt 1 ] || [ $INTERVAL -gt 365 ]
then
	echo "Error in 's2ipt-update.config' file: interval must be a number between 1 and 365"
	exit 1
fi

# checking if UPDATE = LAST_UPDATE + INTERVAL exceeds the current year
let UPDATE=($LAST_UPDATE+$INTERVAL)
if [ $UPDATE -ge 366 ]
then
	let UPDATE=($UPDATE)-365
fi

# every reboot and every midnight the daemon will check if current day is the elected day to update rules (or successive)
# if not, don't do anything; the daemon will be executed next reboot or midnight
if [ $DATE -ge $UPDATE ] || [ $YEAR -gt $LAST_UPDATE_YEAR ]
then

	/opt/s2ipt/install.sh -d > /dev/null 2>&1
	sudo echo '# s2ipt-daemon configuration file
# please do NOT modify this auto-generated file
last_update='$DATE > $DAEMON_CONFIG

fi
