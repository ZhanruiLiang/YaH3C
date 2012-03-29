""" EAP authentication handler

This module sents EAPOL begin/logoff packet
and parses received EAP packet 

"""

__all__ = ["EAPAuth"]

from socket import *
import socket as Socket
import os, sys, pwd
from select import select
from time import sleep

from colorama import Fore, Style, init
# init() # required in Windows
from eappacket import *

UseColor = 0

def display_prompt(color, string):
    if UseColor:
        prompt = color + Style.BRIGHT + '==> ' + Style.RESET_ALL
        prompt += Style.BRIGHT + string + Style.RESET_ALL
        print prompt
    else:
        print string

def display_packet(packet):
    # print ethernet_header infomation
    print 'Ethernet Header Info: '
    print '\tFrom: ' + repr(packet[0:6])
    print '\tTo: ' + repr(packet[6:12])
    print '\tType: ' + repr(packet[12:14])

class EAPAuth:
    def __init__(self, login_info):
        self.loaded_plugins = []
        self.loading_plugin_names = []
        self.has_sent_logoff = False
        self.login_info = login_info

        self.retryCount = 0
        self.maxRetry = 15
        self.connected = 0

    def load_plugins(self):
        homedir = os.path.expanduser('~'+os.getenv('SUDO_USER')) 
        sys.path.insert(0, homedir + '/.yah3c')
        import yah3crc
        self.loading_plugin_names = yah3crc.plugins
        for loading_plugin_name in self.loading_plugin_names:
            loaded_plugin = __import__('plugins.' + loading_plugin_name)
            self.loaded_plugins.append(getattr(loaded_plugin, loading_plugin_name))

    def invoke_plugins(self, func_name):
        for plugin in self.loaded_plugins:
            pid = os.fork()
            if pid == 0:
                if hasattr(plugin, 'root_privilege') and plugin.root_privilege == True:
                    pass
                else:
                    uid = pwd.getpwnam(os.getenv('SUDO_USER'))[2]
                    os.setuid(uid)
                getattr(plugin, func_name)(self)
                exit(0)

    def send_start(self):
        login_info = self.login_info
        # bind the h3c client to the EAP protocal 
        self.client = socket(AF_PACKET, SOCK_RAW, htons(ETHERTYPE_PAE))
        self.client.bind((login_info[2], ETHERTYPE_PAE))
        # get local ethernet card address
        self.mac_addr = self.client.getsockname()[4]
        self.ethernet_header = get_ethernet_header(self.mac_addr, PAE_GROUP_ADDR, ETHERTYPE_PAE)

        # invoke plugins 
        self.invoke_plugins('before_auth')

        # sent eapol start packet
        eap_start_packet = self.ethernet_header + get_EAPOL(EAPOL_START)
        self.client.send(eap_start_packet)

        display_prompt(Fore.GREEN, 'Sending EAPOL start')

    def send_logoff(self):
        # invoke plugins 
        self.invoke_plugins('after_logoff')

        # sent eapol logoff packet
        eap_logoff_packet = self.ethernet_header + get_EAPOL(EAPOL_LOGOFF)
        self.client.send(eap_logoff_packet)
        self.has_sent_logoff = True

        display_prompt(Fore.GREEN, 'Sending EAPOL logoff')

    def send_response_md5(self): pass 
    def send_response_id(self, packet_id):
        self.client.send(self.ethernet_header + 
                get_EAPOL(EAPOL_EAPPACKET,
                    get_EAP(EAP_RESPONSE,
                        packet_id,
                        EAP_TYPE_ID,
                        "\x06\x07bjQ7SE8BZ3MqHhs3clMregcDY3Y=\x20\x20"+ self.login_info[0])))

    def send_response_h3c(self, packet_id):
        resp=chr(len(self.login_info[1]))+self.login_info[1]+self.login_info[0]
        eap_packet = self.ethernet_header + get_EAPOL(EAPOL_EAPPACKET, get_EAP(EAP_RESPONSE, packet_id, EAP_TYPE_H3C, resp))
        try:
            self.client.send(eap_packet)
        except Socket.error, msg:
            display_prompt(Fore.RED, "Connection error!")
            exit(-1)

    def display_login_message(self, msg):
        """
            display the messages received form the radius server,
            including the error meaasge after logging failed or 
            other meaasge from networking centre
        """
        try:
            print msg.decode('gbk')
        except UnicodeDecodeError:
            print msg


    def EAP_handler(self, eap_packet):
        vers, type, eapol_len  = unpack("!BBH",eap_packet[:4])
        if type == EAPOL_EAPPACKET:
            code, id, eap_len = unpack("!BBH", eap_packet[4:8])
            if code == EAP_SUCCESS:
                display_prompt(Fore.YELLOW, 'Got EAP Success')
                # set connected mark, this mark should be set to 0 when connection lost
                self.connected = 1
                self.retryCount = 0
                # invoke plugins 
                self.invoke_plugins('after_auth_succ')
                daemonize('/dev/null','/tmp/daemon.log','/tmp/daemon.log')
            elif code == EAP_FAILURE:
                self.connected = 0
                if (self.has_sent_logoff):
                    display_prompt(Fore.YELLOW, 'Logoff Successfully!')
                    # invoke plugins 
                    self.invoke_plugins('after_logoff')
                    self.display_login_message(eap_packet[10:])
                else:
                    display_prompt(Fore.YELLOW, 'Got EAP Failure')
                    # invoke plugins 
                    self.invoke_plugins('after_auth_fail')
                    self.display_login_message(eap_packet[10:])
                exit(-1)
            elif code == EAP_RESPONSE:
                display_prompt(Fore.YELLOW, 'Got Unknown EAP Response')
            elif code == EAP_REQUEST:
                reqtype = unpack("!B", eap_packet[8:9])[0]
                reqdata = eap_packet[9:4 + eap_len]
                if reqtype == EAP_TYPE_ID:
                    display_prompt(Fore.YELLOW, 'Got EAP Request for identity')
                    self.send_response_id(id)
                    display_prompt(Fore.GREEN, 'Sending EAP response with identity = [%s]' % self.login_info[0])
                elif reqtype == EAP_TYPE_H3C:
                    display_prompt(Fore.YELLOW, 'Got EAP Request for Allocation')
                    self.send_response_h3c(id)
                    display_prompt(Fore.GREEN, 'Sending EAP response with password')
                else:
                    display_prompt(Fore.YELLOW, 'Got unknown Request type (%i)' % reqtype)
            elif code==10 and id==5:
                self.display_login_message(eap_packet[12:])
            else:
                display_prompt(Fore.YELLOW, 'Got unknown EAP code (%i)' % code)
        else:
            display_prompt(Fore.YELLOW, 'Got unknown EAPOL type %i' % type)

    def connect(self):
        try:
            self.send_start()
            while 1:
                display_prompt(Fore.BLUE, "Waiting for reply...")
                if self.connected:
                    timeout = 3600 # in second
                else:
                    timeout = 3 # in second
                iReady, oReady, eReady = select([self.client], [], [], timeout)
                if iReady:
                    eap_packet = self.client.recv(1600)
                    # strip the ethernet_header and handle
                    self.EAP_handler(eap_packet[14:])
                else:
                    print >> sys.stderr, "Connection lost."
                    return 0
        except Socket.error as e:
            print >> sys.stderr, e
            print >> sys.stderr, "Connection error!"
            # return 0 means connect failed
            return 0
        except KeyboardInterrupt:
            # print Fore.RED + Style.BRIGHT + 'Interrupted by user' + Style.RESET_ALL
            display_prompt('Interrupted by user')
            return 1
        return 1

    def serve_forever(self):
        #print self.login_info
        self.load_plugins()
        while self.retryCount < self.maxRetry:
            result = self.connect()
            if result: break
            else:
                self.connected = 0
                self.retryCount += 1
                print 'Retry times: %d/%d, will reconnect after %d seconds.' % (
                        self.retryCount, self.maxRetry, 3)
                sleep(3)
        self.send_logoff()

def daemonize (stdin='/dev/null', stdout='/dev/null', stderr='/dev/null'):

    '''This forks the current process into a daemon. The stdin, stdout, and
    stderr arguments are file names that will be opened and be used to replace
    the standard file descriptors in sys.stdin, sys.stdout, and sys.stderr.
    These arguments are optional and default to /dev/null. Note that stderr is
    opened unbuffered, so if it shares a file with stdout then interleaved
    output may not appear in the order that you expect. '''

    # Do first fork.
    try: 
        pid = os.fork() 
        if pid > 0:
            sys.exit(0)   # Exit first parent.
    except OSError, e: 
        sys.stderr.write ("fork #1 failed: (%d) %s\n" % (e.errno, e.strerror) )
        sys.exit(1)

    # Decouple from parent environment.
    os.chdir("/") 
    os.umask(0) 
    os.setsid() 

    # Do second fork.
    try: 
        pid = os.fork() 
        if pid > 0:
            sys.exit(0)   # Exit second parent.
    except OSError, e: 
        sys.stderr.write ("fork #2 failed: (%d) %s\n" % (e.errno, e.strerror) )
        sys.exit(1)

    # Now I am a daemon!
    
    # Redirect standard file descriptors.
    si = open(stdin, 'r')
    so = open(stdout, 'a+')
    se = open(stderr, 'a+', 0)
    os.dup2(si.fileno(), sys.stdin.fileno())
    os.dup2(so.fileno(), sys.stdout.fileno())
    os.dup2(se.fileno(), sys.stderr.fileno())
