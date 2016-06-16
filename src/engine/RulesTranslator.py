'''
@author: Esposito A. - Ocone L. - Pino L.
'''
import re
from domain_classes import RuleClasses
from utils import Constants

protocol = ''               #global variable to keep track of the protocol, in order to manage header length
translated_options = 0
options_to_skip = 0
enabled_option = ""         #enabled option from command line
from_value = 0
to_value = 0
comment = ''

#main function that translates a single Snort rule into iptables one
def translate(s_rule_string, interface, chain, enabled):
    global enabled_option
    global protocol
    protocol = ''
    enabled_option = enabled
    ip_rule = ""
    best_effort = False
    if(s_rule_string.startswith('#')):
        s_rule_string = s_rule_string[2:]
        
    #setting Snort rule fields, using SnortRule structure
    s_rule = RuleClasses.SnortRule(s_rule_string)
    
    snort_options = len(s_rule.options.options)

    sid = get_rule_sid(s_rule_string)
    
    #checking if pcre option can be translated
    proceed = True
    if(Constants.PCRE+":\"" in s_rule_string):
        proceed = pre_process_pcre(s_rule.options.options)
        if(proceed == False):
            tr_rule = RuleClasses.TranslationResult(Constants.NOT_TRANSLATED_PCRE, False, sid)
            return tr_rule
        else:
            best_effort = True
            
    #checking if content option is present
    proceed = True

    proceed = pre_process_content(s_rule.options.options)
    if(proceed==False):
        tr_rule = RuleClasses.TranslationResult(Constants.NOT_TRANSLATED_NO_CONTENT_OPTION, False, sid)
        return tr_rule
        
    #header translation
    ip_header = translate_header(s_rule.header, interface, chain)
    if (isinstance(ip_header, int)):
        tr_rule = RuleClasses.TranslationResult(ip_header, False, sid)
        return tr_rule
    ip_body = translate_options(s_rule.options.options)
#     if(content_present == False):
#         tr_rule = RuleClasses.TranslationResult(Constants.NOT_TRANSLATED_NO_CONTENT_PRESENT, False, sid)
#         return tr_rule
    
    if(isinstance(ip_body, int)):
        tr_rule = RuleClasses.TranslationResult(ip_body, False, sid)
        return tr_rule

    ip_rule = ip_header +" "+ ip_body
    if(snort_options != (options_to_skip+translated_options)):
        best_effort = True
    tr_rule = RuleClasses.TranslationResult(ip_rule, best_effort, sid)
    sid = ""
    return tr_rule

#function that translates Snort rule header
def translate_header(header, interface, chain):
    global protocol
    if not (header.action.lower() == Constants.ALERT_ACTION):
        return Constants.NOT_TRANSLATED_ACTION
    protocol = header.protocol.lower()
    iptables_header = "iptables -I "+chain+" 1 -i "+interface+" -p " + protocol
    
    #source IP translation
    if('[' in header.ip_source):
        header.ip_source = header.ip_source.replace("[","")
        header.ip_source = header.ip_source.replace("]","")
        print(header.ip_source)
    if(('$' in header.ip_source) or (header.ip_source.lower()==Constants.ANY)):
        #best effort?
        pass
    elif('!' in header.ip_source):
        if(',' in header.ip_source):
            return Constants.NOT_TRANSLATED_MULTIPLE_SOURCE_OR_DEST_IP_NEG
        iptables_header = iptables_header + " ! -s "+ header.ip_source[1:]
    elif(header.ip_source.strip()==Constants.ANY.lower()):
        pass
    else:
        iptables_header = iptables_header + " -s "+ header.ip_source
    
    #source port translation
    if('[' in header.port_source):
        header.port_source = header.port_source.replace("[","")
        header.port_source = header.port_source.replace("]","")
    if('!' in header.port_source):
        sourceport = header.port_source
        iptables_header = iptables_header + " -m multiport ! --sports "+ sourceport[1:]
    elif((',' in header.port_source) and not (':' in header.port_source)):
        header.port_source = header.port_source.strip()
        sourceport = header.port_source
        iptables_header = iptables_header + " -m multiport --sport "+ sourceport
    elif((',' in header.port_source) and (':' in header.port_source)):
        header.port_dest = header.port_source.strip()
        sourceport = header.port_source
        multi_sourceport = ""
        port_split = sourceport.split(',')
        for port in port_split:
            if not (':' in port):
                multi_sourceport = multi_sourceport+","+port
                continue        
            if (port.startswith(":")):
                multi_sourceport = multi_sourceport+","+str(Constants.PORT_LOWER_BOUND) + port
            elif(port.endswith(":")):
                multi_sourceport = multi_sourceport+","+port + str(Constants.PORT_UPPER_BOUND)
            else:
                multi_sourceport = multi_sourceport+","+port
            multi_sourceport = multi_sourceport[1:]  
        iptables_header = iptables_header + " -m multiport --sport "+ multi_sourceport
    elif not (header.port_source == Constants.ANY):
        sourceport = header.port_source
        iptables_header = iptables_header +" --sport "+ sourceport
        
    #destination IP translation
    if('[' in header.ip_dest):
        header.ip_dest = header.ip_dest.replace("[","")
        header.ip_dest = header.ip_dest = header.ip_dest.replace("]","")
    if(('$' in header.ip_dest) or (header.ip_source.lower()==Constants.ANY)):
        pass
    elif('!' in header.ip_dest):
        if(',' in header.ip_dest):
            return Constants.NOT_TRANSLATED_MULTIPLE_SOURCE_OR_DEST_IP_NEG
        iptables_header = iptables_header + " ! -s "+ header.ip_dest[1:]
    elif(header.ip_dest.strip()==Constants.ANY.lower()):
        pass
    else:
        iptables_header = iptables_header + " -d "+ header.ip_dest
        
    #destination port translation
    if('[' in header.port_dest):
        header.port_dest = header.port_dest.replace("[","")
        header.port_dest = header.port_dest.replace("]","")    
    if('!' in header.port_dest):
        destport = header.port_dest
        iptables_header = iptables_header + " -m multiport ! --dports "+ destport[1:]
    if((',' in header.port_dest) and not (':' in header.port_dest)):
        header.port_dest = header.port_dest.strip()
        destport = header.port_dest
        iptables_header = iptables_header + " -m multiport --dport "+ destport
    elif((',' in header.port_dest) and (':' in header.port_dest)):
        header.port_dest = header.port_dest.strip()
        destport = header.port_dest
        multi_destport = ""
        port_split = destport.split(',')
        for port in port_split:
            if not (':' in port):
                multi_destport = multi_destport+","+port
                continue        
            if (port.startswith(":")):
                multi_destport = multi_destport+","+str(Constants.PORT_LOWER_BOUND) + port
            elif(port.endswith(":")):
                multi_destport = multi_destport+","+port + str(Constants.PORT_UPPER_BOUND)
            else:
                multi_destport = multi_destport+","+port
            multi_destport = multi_destport[1:]   
        iptables_header = iptables_header + " -m multiport --dport "+ multi_destport
    elif not (header.port_dest == Constants.ANY):
        destport = header.port_dest
        iptables_header = iptables_header +" --dport "+ destport
        
    iptables_header = iptables_header.replace(Constants.HTTP_PORTS,"80")
    iptables_header = iptables_header.replace(Constants.SSH_PORTS,"22")   
    iptables_header = iptables_header.replace(Constants.FILE_DATA_PORTS,"20")   
    iptables_header = iptables_header.replace(Constants.ORACLE_PORTS,"1521")   
    iptables_header = iptables_header.replace(Constants.SIP_PORTS,"5060")
    iptables_header = iptables_header.replace(Constants.FTP_PORTS,"21")   
    return iptables_header

#function that translates Snort rule options
def translate_options(options):
    global protocol
    global translated_options
    global options_to_skip
    global from_value
    global to_value
#    global content_present
    translated_options = 0
    options_to_skip = 0
    from_value = 0
    to_value = 0
    ipt_options = []
    continue_translation = 0
    for opt in options:
        opt = opt.strip()
        if (':' in opt):    #looking for ':' char, in order to match known options   
            if(continue_translation < 0):
                return continue_translation
            opt_split = opt.split(':')
            opt_key = opt_split[0]
            opt_value = opt_split[1]
            if(opt_key.lower() == Constants.CONTENT.lower()):
#                content_present = True
                index = 2
                while(not opt_value.endswith("\"")):
                    opt_value = opt_value+opt_split[index]
                    index = index+1
                match_not = False
                if(opt_value.startswith('!')):
                    opt_value = opt_value[1:]
                    match_not = True
                st =""
                strings = []
                hex_strings = []
                hex_st =""
                hex_flag = False
                for letter in opt_value:
                    if(letter=='\"'):
                        if st:
                            strings.append(st)
                            st = ""
                        if hex_st:
                            hex_strings.append(hex_st)
                            hex_st = ""
                        continue
                    if((letter == '|') and (hex_flag == False)):
                        hex_flag = True
                        if st:
                            strings.append(st)
                            st = ""
                    elif((letter == '|') and (hex_flag == True)):
                        hex_flag = False
                        if hex_st:
                            hex_strings.append(hex_st)
                            hex_st = ""
                    elif(not (letter == '|') and (hex_flag == False)):
                        if(letter=='`'):
                            letter='\''
                        st = st+letter
                    elif(not (letter == '|') and (hex_flag == True)):
                        hex_st = hex_st+letter    
                
                strings = list(set(strings))
                hex_strings = list(set(hex_strings))
                if not match_not:
                    for s in hex_strings:
                        ipt_options.insert(0,"-m string --hex-string \"|"+s+"|\" --algo bm")
                    for s in strings:
                        ipt_options.insert(0,"-m string --string \""+s+"\" --algo bm")
                else:
                    for s in hex_strings:
                        ipt_options.insert(0,"-m string ! --hex-string \"|"+s+"|\" --algo bm")
                    for s in strings:
                        ipt_options.insert(0,"-m string ! --string \""+s+"\" --algo bm")
                translated_options = translated_options+1
            elif(opt_key.lower() == Constants.URICONTENT.lower()):
                ipt_options.insert(0,"-m string --string \""+opt_value+"\" --algo bm")
                translated_options = translated_options+1
            elif(opt_key.lower() == Constants.FLOW.lower()):
                if(Constants.ESTABLISHED in opt_value):
                    ipt_options.append("-m state --state ESTABLISHED")
                    translated_options = translated_options+1
            elif(opt_key.lower() == Constants.OFFSET.lower()):  
                from_value = min(int(from_value), int(opt_value.strip()))
                translated_options = translated_options+1
            elif(opt_key.lower() == Constants.DEPTH.lower()):
                to_value = to_value + int(opt_value.strip())
                translated_options = translated_options+1
            elif(opt_key.lower() == Constants.TOS.lower()):
                negation = ""
                if('!' in opt_value):
                    negation = '!'
                ipt_options.append("-m tos "+negation+" --tos "+opt_value)
                translated_options = translated_options+1
            elif(opt_key.lower() == Constants.IP_PROTO.lower()):
                if (protocol is not ''):
                    break
                if('<' or '>' in opt_value):
                    pass
                negation = ""
                if('!' in opt_value):
                    negation = '!'
                ipt_options.append("-p "+negation+" "+str(opt_value))
                translated_options = translated_options+1
            elif(opt_key.lower() == Constants.TTL.lower()):
                if('>' in opt_value):
                    opt_value = opt_value[1:]
                    ipt_options.append("-m ttl --ttl-gt "+str(opt_value))
                elif('<' in opt_value):
                    opt_value = opt_value[1:]
                    ipt_options.append("-m ttl --ttl-lt "+str(opt_value))
                else:
                    ipt_options.append("-m ttl --ttl-eq "+str(opt_value))        
                translated_options = translated_options+1
            elif(opt_key.lower() == Constants.MESSAGE.lower()):
                global comment
                comment = opt_value
                translated_options = translated_options+1
            elif(opt_key.lower() == Constants.PCRE.lower()):
                results = re.findall("{\d*}|{\d*,\d*}",opt_value)
                count = 0
                for res in results:
                    res = res[1:-1]
                    resSplit = res.split(',')
                    count = count + int(resSplit[0])
                protocol_length = get_protocol_length()+count
                ipt_options.append("-m length --length "+str(protocol_length)+": ")     #setting protocol_length as lower bound of incoming packet
                results = re.findall("{\d*}|{\d*,\d*}",opt_value)
            elif(opt_key.lower() == Constants.SID.lower()):
                options_to_skip = options_to_skip + 1
            elif(opt_key.lower() == Constants.REFERENCE.lower()):
                options_to_skip = options_to_skip + 1
            elif(opt_key.lower() == Constants.REV.lower()):
                options_to_skip = options_to_skip + 1
            elif(opt_key.lower() == Constants.METADATA.lower()):
                options_to_skip = options_to_skip + 1
            elif(opt_key.lower() == Constants.CLASSTYPE.lower()):
                options_to_skip = options_to_skip + 1
            elif(opt_key.lower() == Constants.PRIORITY.lower()):
                options_to_skip = options_to_skip + 1
            elif(opt_key.lower() == Constants.GID.lower()):
                options_to_skip = options_to_skip + 1
        else:
            options_to_skip = options_to_skip+1    
                         
    return stringify(ipt_options)

#getter rule sid
def get_rule_sid(rule):
    sid_str = re.findall("sid:\d+", rule)
    sid_split = sid_str[0].split(':')
    sid = sid_split[1]
    return str(sid)

#function that returns iptables rule in one output string
def stringify(options):
    global translated_options
    global comment        
    ipt_opts = ''
    for s in options:
        ipt_opts = ipt_opts+' '+s
    
    if(to_value < from_value):
        translated_options = translated_options-1
    elif(to_value == 0 and from_value == 0):
        pass
    else:
        ipt_opts = ipt_opts + " --from " + str(from_value) + " --to " + str(to_value)
    ipt_opts = ipt_opts + " -m comment --comment "+comment
#    if(enabled_option.lower()==Constants.LOG.lower()):
#        ipt_opts = ipt_opts+ " -j LOG"
#     elif(enabled_option.lower()==Constants.DROP.lower()):
#         ipt_opts = ipt_opts+ " -j DROP"
#     elif(enabled_option.lower()==Constants.REJECT.lower()):
#         ipt_opts = ipt_opts+ " -j REJECT"
    return ipt_opts.strip()


#pre processing phase, looking for 'pcre' regex not-handled 
def pre_process_pcre(options):
    for opt in options:
        opt = opt.strip()
        if (':' in opt):
            opt_split = opt.split(':')
            opt_key = opt_split[0]
            opt_value = opt_split[1]
            if(opt_key.lower() == Constants.PCRE.lower()):
                #check if '\a', '\f' or '\e' are in the pcre regex
                if('\\a' or '\\f' or '\\e' in opt_value.lower()):
                    return False
                #check if '\ddd' is in the pcre regex
                matched = re.findall("\\\\[d]\d*",opt_value)
                if(len(matched)>0):
                    return False
            else: 
                pass
    return True

def pre_process_content(options):
    for opt in options:
        opt = opt.strip()
        if (':' in opt):
            opt_split = opt.split(':')
            opt_key = opt_split[0]
            if(opt_key.lower() == Constants.CONTENT.lower()):
                return True          
            else: 
                pass
    return False


#getter of protocol length
def get_protocol_length():
    global protocol
    length = 0
    if(protocol == Constants.TCP):
        length = int(Constants.TCP_LENGTH)
    elif(protocol == Constants.UDP):
        length = int(Constants.UDP_LENGTH)
    elif(protocol == Constants.ICMP):
        length = int(Constants.ICMP_LENGTH)
    elif(protocol == Constants.IP):
        length = int(Constants.IP_LENGTH)
    return length
        
        
    
