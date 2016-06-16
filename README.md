This is s2ipt tool README file.
First of all, you have to run './install.sh' script to set up the environment for s2ipt, as superuser.
If your system doesn't recognize the script as executable, run 'sudo chmod +x install.sh' and then retry.
This command will also download the latest Snort community-rules files.
If the download fails for some reasons, you have to run this script again with '-d' option (sudo ./install.sh -d).
In the end, you can run this tool just invoking 's2ipt' as superuser, with '--log', '--drop', '--reject' or '--revert' option.
You can also run 's2ipt' with no option specified, assuming '--log' as default.
For more information run 's2ipt --help'.
The 's2ipt-daemon.sh' will check for most recent community-rules according to the interval set in ./daemon/s2ipt-update.config file.

