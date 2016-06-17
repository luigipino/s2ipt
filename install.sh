#!/bin/bash

# checking if executed as superuser
if [ "$EUID" -ne 0 ]
then
	echo "You need to have root privileges to run this script."
	echo "Please try again, this time using 'sudo'. Exiting."	
  exit
fi

# download function, called both in normal usage and when '-d' option is specified
function download {

# checking connectivity to snort repository 
PING="ping -q -c1"
HOST=www.snort.com
WAIT_TIME=3
MAX_TRIES=5
I=1
AVAILABLE=1
FILENAME=/opt/s2ipt/daemon/daemon.config

echo "checking connectivity to snort repository..."

while [ $AVAILABLE -eq 1 ] && [ $I -le $MAX_TRIES ]; do
        ${PING} ${HOST} &> /dev/null
        if [ $? -ne 0 ]; then
                echo "Try" $I "failed..."
		I=$[$I+1]
	else
		let AVAILABLE=0
        fi
        sleep $WAIT_TIME 
done

if [ $AVAILABLE -eq 0 ]
then
	echo "connectivity check successful"
else
	echo "snort repository unreachable... Try again later running this script with '-d' argument."
	exit 1
fi

# community rules download from repository
echo "downloading snort community rules..."
echo "If this try will fail, please try again later running this script with '-d' argument."

wget --tries=3 --timeout=30 -P /opt/s2ipt/ https://www.snort.org/downloads/community/community-rules.tar.gz
status=$?
if [ $status -ne 0 ]
then
	echo "unable to download latest community-rules repository. Try again later running this script with '-d' argument."
	exit 1
else
	echo "latest community-rules repository downloaded successfully"
fi

DATE=$(date +%j)
YEAR=$(date +%Y)

sudo echo '# s2ipt-daemon configuration file
# please do NOT modify this auto-generated file
last_update='$DATE > $FILENAME
sudo echo 'update_year='$YEAR >> $FILENAME

# extracting files from archive
echo "extracting community rules from archive..."
tar -zxvf /opt/s2ipt/community-rules.tar.gz -C /opt/s2ipt/
echo "extraction successful"
sudo rm /opt/s2ipt/community-rules.tar.gz

exit 0
}


while getopts ":d" opt; do
  case $opt in
    d)
      	echo "checking s2ipt installation..." >&2
	if [ ! -f /usr/local/bin/s2ipt ]; then
    		echo "s2ipt installation not found, please run this script with NO option"
		exit 1
	else
		download
	fi
      	;;
    \?)
      	echo "Invalid option: -$OPTARG" >&2
	echo "exiting..."
	exit 1
      	;;
  esac
done

# checkin python version >= 2.7.3, iptables version >= 1.4.12 and linux kernel version >= 2.6.12 mandatory for some options in iptables rules

echo "checking python version..."

python_version=$(python --version |& awk '{print $2}')
array=(${python_version//./ })

if [ ${array[0]} -ge 2 ]
then
	echo "python version check successful"
elif [ ${array[0]} -eq 2 ] && [ ${array[1]} -ge 7 ]
then
	echo "python version check successful"
elif [ ${array[1]} -eq 7 ] && [ ${array[2]} -ge 3 ]
then
	echo "python version check successful"
else
	echo "python version must be at least 2.7.3"
	exit 1
fi

echo "checking iptables version..."

iptables_version=$(iptables --version |& awk '{print $2}')
iptables_version=${iptables_version:1}

array=(${iptables_version//./ })

if [ ${array[0]} -ge 1 ]
then
	echo "iptables version check successful"
elif [ ${array[0]} -eq 1 ] && [ ${array[1]} -ge 4 ]
then
	echo "iptables version check successful"
elif [ ${array[1]} -eq 4 ] && [ ${array[2]} -ge 12 ]
then
	echo "iptables version check successful"
else
	echo "iptables version must be at least 1.4.12"
	exit 1
fi

echo "checking linux-kernel version..."

linux_kernel_version=$(uname -r)

while [[ $linux_kernel_version == *"-"* ]]
do
	linux_kernel_version=${linux_kernel_version%-*}
done

array=(${linux_kernel_version//./ })

if [ ${array[0]} -ge 2 ]
then
	echo "linux-kernel version check successful"
elif [ ${array[0]} -eq 2 ] && [ ${array[1]} -ge 6 ]
then
	echo "linux-kernel version check successful"
elif [ ${array[1]} -eq 6 ] && [ ${array[2]} -ge 14 ]
then
	echo "linux-kernel version check successful"
else
	echo "linux-kernel version must be at least 2.6.14"
	exit 1
fi


# creating directory hierarchy
if [ -d "/opt/s2ipt" ]; then
	echo "s2ipt directories already exist. Installation may have already been executed."
	echo "If you want to download snort community rules, please run again this script with '-d' option."
	exit 1
fi

echo "creating directories..."
mkdir /opt/s2ipt
echo "created '/opt/s2ipt'"
mkdir /opt/s2ipt/backups
echo "created '/opt/s2ipt/backups'"
mkdir /opt/s2ipt/logs
echo "created '/opt/s2ipt/logs'"
echo "copying all files into directories..."
cp -f -r ./* /opt/s2ipt/
echo "file copy successful"
sudo chmod +x /opt/s2ipt/src/engine/s2ipt.py
sudo chmod +x /opt/s2ipt/daemon/s2ipt-daemon.sh

# creating symbolic link in /usr/local/bin
echo "creating symbolic link in '/usr/local/bin/'..."

sudo ln -s /opt/s2ipt/src/engine/s2ipt.py /usr/local/bin/s2ipt
if [ $? -eq 0 ]; then
	echo "symbolic link created"
fi

# backup of iptables rules
echo "executing backup of current iptables rules..."
touch /opt/s2ipt/backups/iptables_backup
sudo iptables-save > /opt/s2ipt/backups/iptables-pre-s2ipt-backup
if [ $? -eq 0 ]; then
	echo "backup successful"
fi
# creating a second backup file, which will be replaced after the execution of 's2ipt'
# this is made to execute the 3rd cron job successfully
sudo iptables-save > /opt/s2ipt/backups/iptables-s2ipt-backup


# write out current crontab
sudo crontab -l > mycron &> /dev/null
# echo new cron into cron file
sudo echo "00 00 * * * /opt/s2ipt/daemon/s2ipt-daemon.sh" >> mycron
sudo echo "@reboot /opt/s2ipt/daemon/s2ipt-daemon.sh" >> mycron
sudo echo "@reboot /sbin/iptables-restore < /opt/s2ipt/backups/iptables-s2ipt-backup" >> mycron
# install new cron file
sudo crontab mycron
sudo rm mycron

download



