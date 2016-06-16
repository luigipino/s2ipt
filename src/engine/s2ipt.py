#!/usr/bin/env python
#!/usr/local/bin/python2.7
# encoding: utf-8
'''
s2ipt -- s2ipt is a lightweight python-engine whose aim is to translate SNORT community rules into iptables ones.

s2ipt is lightweight a python-engine whose aim is to translate SNORT community rules into iptables ones and applies them to the local firewall.
SNORT rules are translated in best effort approach, discriminating 3 cases:
-    rules that can be translated as is into iptables;
-    rules that can be translated in "best-effort" (such as, not every rule option will be translated);
-    rules that can't be translated.


@author:     Esposito A. - Ocone L. - Pino L.

@copyright:  2016 s2ipt_security_team. All rights reserved.

@license:    s2ipt - a lightweight python-engine that translates SNORT community rules into iptables ones
Copyright (C) 2016  Esposito A. - Ocone L. - Pino L.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

@contact:    alessandro.espo91@gmail.com - oconeluciano84@gmail.com - pinoluigi@hotmail.com
@deffield    updated: 16-06-2016
'''

from argparse import ArgumentParser
from argparse import RawDescriptionHelpFormatter
import subprocess
import os
import sys
import time
import ConfigParser

if(os.getuid() is not 0):
    exit("You need to have root privileges to run this script.\nPlease try again, this time using 'sudo'. Exiting.")


dir_str = "/opt/s2ipt/src"
dir_domain_classes = dir_str+"/domain_classes"
dir_utils = dir_str+"/utils"
sys.path.append(dir_str)
sys.path.append(dir_domain_classes)
sys.path.append(dir_utils)


import RulesTranslator
from utils import Constants


__all__ = []
__version__ = 1.0
__date__ = '03-02-2016'
__updated__ = '16-06-2016'

DEBUG = 1
TESTRUN = 0
PROFILE = 0

class CLIError(Exception):
    '''Generic exception to raise and log different fatal errors.'''
    def __init__(self, msg):
        super(CLIError).__init__(type(self))
        self.msg = "E: %s" % msg
    def __str__(self):
        return self.msg
    def __unicode__(self):
        return self.msg

def revert_function():
    subprocess.call("sudo iptables-restore < "+Constants.BASE_DIR+"/backups/iptables-pre-s2ipt-backup",shell=True)
    
    #remove jump to custom chain if it doesn't exist, try for both IDS and IPS
    #removing jump to IDS...
    out = subprocess.call("sudo iptables -C INPUT -j IDS 2> /dev/null", shell=True)
    if(int(out)==0):
        subprocess.call("sudo iptables -D INPUT -j IDS 2> /dev/null", shell=True)
      
    out = subprocess.call("sudo iptables -C OUTPUT -j IDS 2> /dev/null", shell=True)
    if(int(out)==0):
        subprocess.call("sudo iptables -D OUTPUT -j IDS 2> /dev/null", shell=True)
        
    out = subprocess.call("sudo iptables -C FORWARD -j IDS 2> /dev/null", shell=True)
    if(int(out)==0):
        subprocess.call("sudo iptables -D FORWARD -j IDS 2> /dev/null", shell=True)
    
    #removing jump to IPS...    
    out = subprocess.call("sudo iptables -C INPUT -j IPS 2> /dev/null", shell=True)
    if(int(out)==0):
        subprocess.call("sudo iptables -D INPUT -j IPS 2> /dev/null", shell=True)
      
    out = subprocess.call("sudo iptables -C OUTPUT -j IPS 2> /dev/null", shell=True)
    if(int(out)==0):
        subprocess.call("sudo iptables -D OUTPUT -j IPS 2> /dev/null", shell=True)
        
    out = subprocess.call("sudo iptables -C FORWARD -j IPS 2> /dev/null", shell=True)
    if(int(out)==0):
        subprocess.call("sudo iptables -D FORWARD -j IPS 2> /dev/null", shell=True)
        
    #restoring config file, setting 0 read rules
    conf_file = Constants.BASE_DIR+"/"+Constants.CONF_DIR+"/"+Constants.PROP_FILE
    f_output = open(conf_file, 'a')
    f_output.write(Constants.CONFIG_SECTION_NAME+"\n")
    f_output.write(Constants.CONFIG_PROPERTY_NAME+" = 0")
    f_output.close()        
    return

def get_available_interfaces():
    #ip link show
    avail = []
    out = subprocess.check_output(["ip", "link", "show"])        
    lines = out.split('\n')
    lines.pop(len(lines)-1)
    i = 1
    for l in lines:
        if((i%2)==0):
            i = i+1
        else:
            substrings = l.split(':')
            avail.append(substrings[1].strip())
            i = i+1 
    return avail


def main(argv=None): # IGNORE:C0111
    '''Command line options.'''

    if argv is None:
        argv = sys.argv
    else:
        sys.argv.extend(argv)

    program_name = os.path.basename(sys.argv[0])
    program_version = "v%s" % __version__
    program_build_date = str(__updated__)
    program_version_message = '%%(prog)s %s (%s)' % (program_version, program_build_date)
    program_shortdesc = __import__('__main__').__doc__.split("\n")[1]
    program_license = '''%s

    s2ipt - a lightweight python-engine that translates SNORT community rules into iptables ones
    Copyright (C) 2016  Esposito A. - Ocone L. - Pino L.
    
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.
    
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    
    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.

USAGE
''' % (program_shortdesc)#, str(__date__))

    try:        
        # Setup argument parser
        parser = ArgumentParser(description=program_license, formatter_class=RawDescriptionHelpFormatter)
        parser.add_argument("--iface", dest='iface',required=True, metavar='IFACE', help="specifies the interface to apply iptables rules")
        group = parser.add_mutually_exclusive_group()
        group.add_argument("--log", dest='log', action='store_true', help="makes iptables rules to log the matched packets, this is assumed as default")
        group.add_argument('--drop', dest='drop', action='store_true', help="makes iptables rules to drop the matched packets")
        group.add_argument('--reject', dest='reject', action='store_true', help="makes iptables rules to drop the matched packets and sending back a packet with RST flag raised")
        parser.add_argument("--revert", dest='revert', action = 'store_true',help="restores the snapshot of iptables rules saved before s2ipt first execution")
        
        # Process arguments
        args = parser.parse_args()
        revert = args.revert
        if revert==True:
            print("restoring iptables backup...")
            revert_function()
            return 0
        
        interface = args.iface
        if(not interface):
            exit("s2ipt: error: argument --iface is required, unless you use --revert\nrun s2ipt -h for more help")
        avail = get_available_interfaces()
        if(interface not in avail):
            exit("Please enter a valid network interface")
        log = args.log
        revert = args.revert
        drop = args.drop
        reject = args.reject
        enabled_option = Constants.LOG      #default mode = LOG
        custom_chain = ''
                
        if log==True:
            print ("LOG mode enabled")
            enabled_option = Constants.LOG
            custom_chain = 'IDS'
        elif drop==True:
            print ("DROP mode enabled")
            enabled_option = Constants.DROP
            custom_chain = 'IPS'
        elif reject==True:
            print ("REJECT mode enabled")
            enabled_option = Constants.REJECT
            custom_chain = 'IPS'
        else:
            print ("LOG mode enabled")
            custom_chain = 'IDS'

        
        #reading configuration file to retrieve number of yet translated rules 
        config = ConfigParser.RawConfigParser()
        config.read(Constants.BASE_DIR+"/"+Constants.CONF_DIR+"/"+Constants.PROP_FILE)
        read_rules = config.get(Constants.CONFIG_SECTION_NAME, Constants.CONFIG_PROPERTY_NAME)   
        total_rules = 0
        translated_rules = 0
        best_effort = 0
        skip = 0
        skip_header = False
        temp_rule = ''
        
        #create chain if it doesn't exist
        out = subprocess.call("sudo iptables -L "+custom_chain+" > /dev/null 2>&1", shell=True)
        if(int(out)==1):
            subprocess.call("sudo iptables -N "+custom_chain+" 2> /dev/null", shell=True)
            
        #add jump to custom chain if it doesn't exist
        out = subprocess.call("sudo iptables -C INPUT -j "+custom_chain+" 2> /dev/null", shell=True)
        if(int(out)==1):
            subprocess.call("sudo iptables -A INPUT -j "+custom_chain+" 2> /dev/null", shell=True)
        
        out = subprocess.call("sudo iptables -C OUTPUT -j "+custom_chain+" 2> /dev/null", shell=True)
        if(int(out)==1):
            subprocess.call("sudo iptables -A OUTPUT -j "+custom_chain+" 2> /dev/null", shell=True)
        
        out = subprocess.call("sudo iptables -C FORWARD -j "+custom_chain+" 2> /dev/null", shell=True)
        if(int(out)==1):
            subprocess.call("sudo iptables -A FORWARD -j "+custom_chain+" 2> /dev/null", shell=True)
        
        #creating LOG file for the run
        time_stamp = time.strftime('%Y-%m-%d_%H:%M:%S')
        out_file_name = Constants.BASE_DIR+"/"+Constants.LOGS_DIR+"/"+time_stamp+".log"
        subprocess.call("touch "+out_file_name, shell=True)
        f_output = open(out_file_name, 'a')
        f_output.write("#####################################################################\n")
        f_output.write("#                s2ipt LOG file: "+time_stamp+ "                #\n")
        f_output.write("#####################################################################\n")
        f_output.write("\n")
        
        print("If this is the first time you're running 's2ipt',\nit may take some time to complete the task...")
        file_name = Constants.BASE_DIR+"/"+"community-rules/community.rules"
        try:
            with open(file_name, 'r')  as f:

                for line in f:
                    #skip header of community.rules
                    if not line.isspace() and skip_header==False:
                        continue
                    elif line.isspace() and skip_header==False:
                        skip_header = True
                        continue                    
                    elif line.isspace() and skip_header==True:
                        break
                    if(skip<int(read_rules)):
                        skip = skip+1
                        continue
                    total_rules = total_rules+1
                    result = RulesTranslator.translate(line, interface, custom_chain, enabled_option)
                    if(result.rule == Constants.NOT_TRANSLATED_PCRE):
                        f_output.write("Rule with sid "+result.sid+" SKIPPED: cannot translate correctly PCRE option\n")
                        pass
                    elif(result.rule == Constants.NOT_TRANSLATED_ACTION):
                        f_output.write("Rule with sid "+result.sid+" SKIPPED: rule action different from 'alert'\n")
                        pass
                    elif(result.rule == Constants.NOT_TRANSLATED_MULTIPLE_SOURCE_OR_DEST_IP_NEG):
                        f_output.write("Rule with sid "+result.sid+" SKIPPED: cannot translate multiple IP source/dest with 'negation' ! \n")
                        pass
                    elif(result.rule == Constants.NOT_TRANSLATED_NO_CONTENT_OPTION):
                        f_output.write("Rule with sid "+result.sid+" SKIPPED: too generic rule, no CONTENT to match \n")
                        pass
                    else:
                        temp_rule = result.rule + " -j LOG --log-prefix ["+custom_chain+"-"+result.sid+"]"
                        subprocess.call("sudo "+temp_rule, shell=True)
                        if(drop==True):
                            temp_rule = result.rule + " -j DROP"
                            subprocess.call("sudo "+temp_rule, shell=True)
                        elif(reject==True):
                            temp_rule = result.rule + " -j REJECT"
                            subprocess.call("sudo "+temp_rule, shell=True)
                        translated_rules = translated_rules+1
                        if(result.best_effort == True):
                            best_effort = best_effort + 1
                f_output.close()
                f.close()
                if(float(total_rules)==0):
                    percent = 0
                else:
                    percent = (float(translated_rules)/float(total_rules))*100
                if(float(translated_rules)==0):
                    be_percent = 0
                else:
                    be_percent = (float(best_effort)/float(translated_rules))*100
                
                print("Transalated %d rules out of %d total (%.2f%%)" % (translated_rules, total_rules, percent))
                print("%d rules are translated in best effort (%.2f%%)" % (best_effort, be_percent))
                new_read_rules = int(read_rules)+total_rules
                config.set(Constants.CONFIG_SECTION_NAME, Constants.CONFIG_PROPERTY_NAME, ""+str(new_read_rules))
                config.write(open(Constants.BASE_DIR+"/"+Constants.CONF_DIR+"/"+Constants.PROP_FILE,'w'))
                
                #adding RETURN rule at the end of custom chain, if it doesn't exist
                out = subprocess.call("sudo iptables -C "+custom_chain+" -j RETURN 2> /dev/null", shell=True)
                if(int(out)==1):
                    subprocess.call("sudo iptables -A "+custom_chain+" -j RETURN 2> /dev/null", shell=True)
                subprocess.call("sudo iptables-save > "+Constants.BASE_DIR+"/"+Constants.BACKUP_DIR+"/iptables-s2ipt-backup", shell=True)
                return 0
        except IOError:
            exit("File "+file_name+" not found, community-rule have to be downloaded to be translated")
    except KeyboardInterrupt:
        ### handle keyboard interrupt ###
        return 0
    except Exception, e:
#        if DEBUG or TESTRUN
        raise(e)
        indent = len(program_name) * " "
        sys.stderr.write(program_name + ": " + repr(e) + "\n")
        sys.stderr.write(indent + "  for help use --help")
        return 2

if __name__ == "__main__":
    sys.exit(main())
