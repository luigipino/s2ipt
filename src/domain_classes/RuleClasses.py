'''
@author: Esposito A. - Ocone L. - Pino L.
'''
class Header:
    
    def __init__(self,header_list):
        self.action = header_list[0]
        self.protocol = header_list[1]
        self.ip_source = header_list[2]
        self.port_source = header_list[3]
        self.direction = header_list[4]
        self.ip_dest = header_list[5]
        self.port_dest = header_list[6]

class Options:
    
    def __init__(self,options_list):
        self.options = options_list
        
        
class SnortRule:
    
    def __init__(self,snort_rule):
        split_list = snort_rule.split('(')
        header_string =  split_list[0]
        options_string = split_list[1]
        opt_list = options_string.split(';')
        opt_list.pop()
        self.header = Header(header_string.split())
        self.options = Options(opt_list)
        
        
class TranslationResult:
    
    def __init__(self, rule, best_effort, sid): 
        self.rule = rule
        self.best_effort = best_effort
        self.sid = sid
        