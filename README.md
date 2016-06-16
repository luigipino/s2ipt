This is s2ipt tool README file. <br/><br/>
s2ipt is a lightweight python-engine whose aim is to translate Snort community rules into iptables ones. <br/>
First of all, you have to run './install.sh' script to set up the environment for s2ipt, as superuser. <br/><br/>
	# ./install.sh <br/><br/>
If your system doesn't recognize the script as executable, run 'chmod +x install.sh' and then retry. <br/><br/>
	# chmod +x install.sh <br/><br/>
This command will also download the latest Snort community-rules files. <br/>
If the download fails for some reasons, you have to run this script again with '-d' option. <br/><br/>
	# ./install.sh -d <br/><br/>
Now, you can run this tool just invoking 's2ipt' as superuser, with '--log', '--drop', '--reject' or '--revert' option, also specifying the interface to apply the iptables rules. <br/> <br/>
Example of usage: <br/><br/>
	# s2ipt --iface eth0 --log <br/><br/>
When using '--log', '--drop' or '--reject', is mandatory to provide a network interface. <br/>
In order to restore the iptables backup created before 's2ipt' execution, use '--revert'. <br/><br/>
	# s2ipt --revert <br/><br/>
You can also run 's2ipt' only specifying the interface, assuming '--log' as default. <br/><br/>
For more information run 's2ipt --help'. <br/><br/>
	# s2ipt --help <br/><br/>
The 's2ipt-daemon.sh' is an utility that checks for most recent Snort community-rules according to the interval set in './daemon/s2ipt-update.config' file.

