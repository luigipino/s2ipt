'''
@author: Esposito A. - Ocone L. - Pino L.
'''

BASE_DIR = "/opt/s2ipt"                         #caso reale
LOGS_DIR = "logs"
BACKUP_DIR = "backups"
IPTABLES_BACKUP = "iptables_backup"
CONF_DIR = "conf"
PROP_FILE = "config.properties"
CONFIG_SECTION_NAME = "TranslationPropertiesSection"
CONFIG_PROPERTY_NAME = "read_rules"
LOG = "log"
DROP = "drop"
REJECT = "reject"
NOT_TRANSLATED_PCRE = -1
NOT_TRANSLATED_ACTION = -2
NOT_TRANSLATED_MULTIPLE_SOURCE_OR_DEST_IP_NEG = -3
NOT_TRANSLATED_NO_CONTENT_OPTION = -4
ALERT_ACTION = "alert"
ANY = "any"
TCP = "tcp"
UDP = "udp"
ICMP = "icmp"
IP =" ip"
EXTERNAL_NET = "$EXTERNAL_NET"
HOME_NET = "$HOME_NET"
HTTP_PORTS = "$HTTP_PORTS"
SSH_PORTS = "$SSH_PORTS"
FILE_DATA_PORTS = "$FILE_DATA_PORTS"
ORACLE_PORTS = "$ORACLE_PORTS"
SIP_PORTS = "$SIP_PORTS"
FTP_PORTS = "$FTP_PORTS"
HTTP_SERVERS = "$HTTP_SERVERS"
SMTP_SERVERS = "$SMTP_SERVERS"
TELNET_SERVERS = "$TELNET_SERVERS"
PORT_LOWER_BOUND = 0
PORT_UPPER_BOUND = 65535
LEFT2RIGHT_DIR = "->"
RIGHT2LEFT_DIR = "<-"
BOTH_DIR = "<>"
MESSAGE = "msg"
CONTENT = "content"
URICONTENT = "uricontent"
FLOW = "flow"
ESTABLISHED = "established"
OFFSET ="offset"
DEPTH = "depth"
TTL ="ttl"
TOS = "tos"
IP_PROTO = "ip_proto"
PCRE = "pcre"
REV = "rev"
SID = "sid"
GID = "gid"
METADATA = "metadata"
CLASSTYPE = "classtype"
REFERENCE = "reference"
PRIORITY = "priority"
TCP_LENGTH = 40
UDP_LENGTH = 28
IP_LENGTH = 20
ICMP_LENGTH = 24        #length may between 4 and 8, which has to be summed to IP header length of 20