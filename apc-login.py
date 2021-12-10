#!/usr/bin/env python
#written by Ian Powers
#script tries to use default credentials on APC Network Management Card from an imported list of hosts (new line separated)

from argparse import ArgumentParser #for command line arguments
import requests                     #for making get requests
import time                         #to throttle speed of requests
import sys
from requests import Request, Session
from requests.packages.urllib3.exceptions import InsecureRequestWarning
#prevent ssl errors for popping up
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class Login:
    def __init__(self,inputFile,requestTimeout, delay, secure, proxy):
        self.inputFile = inputFile
        self.requestTimeout = requestTimeout
        self.delay = delay
        self.secure = secure
        self.proxy = proxy
    
    def run(self):
        #set counters at zero
        totalHosts = 0
        defaultCredCount = 0
        failedLoginCount = 0
        notAPC = 0
        
        if self.secure: #if secure flag is set make APC requests to https port
            apcPort = 443
            proto = "https"
        else: #otherwise make requests to http port
            apcPort = 80
            proto = "http"

        if self.proxy: #if proxy is set
            proxies = { 'http':self.proxy,
                        'https':self.proxy
            }
            
        s = requests.Session()
        defaultCreds = {"apc":"apc", "device":"apc", "readonly":"apc"}
        with open(self.inputFile,"r") as ins:
            for line in ins:
                addr=line.strip()
                totalHosts += 1
                loginUrl = proto+"://"+addr+"/logon.htm"
                loginPostUrl = proto+"://"+addr+"/Forms/login1"
                loggedInUrl = proto+"://"+addr+"/home.htm"
                logoutUrl = proto+"://"+addr+"/logout.html"
                loginFailUrl = proto+"://"+addr+"/Password"

                for username in defaultCreds:
                    try:
                        #make get request to get session cookie from server
                        if self.proxy: #if traffic needs to be proxied
                            s.get(loginUrl, timeout=self.requestTimeout, verify=False, proxies=proxies)
                            #make post request with default creds
                            r = s.post(loginPostUrl, timeout=self.requestTimeout, verify=False, data={'login_username':username,'login_password':'apc','submit':'Log+On'}, proxies=proxies)
                            if r.url == loggedInUrl:
                                print("[$] Login successful on host: "+addr+" using "+username+"/apc")
                                defaultCredCount += 1
                                #logout if the login was successful
                                s.get(logoutUrl, timeout=self.requestTimeout, verify=False, proxies=proxies)
                            elif r.url == loginFailUrl:
                                print("[X] Login failed on host: "+addr+" using "+username+"/apc")
                                failedLoginCount += 1
                                s.get(logoutUrl, timeout=self.requestTimeout, verify=False, proxies=proxies)
                            else:
                                print("[?] Was redirected to unexpected location "+str(r.url)+" on host: "+addr)
                                s.get(logoutUrl, timeout=self.requestTimeout, verify=False, proxies=proxies)
                        else: #if traffic does not need to be proxied
                            s.get(loginUrl, timeout=self.requestTimeout, verify=False)
                            #make post request with default creds
                            r = s.post(loginPostUrl, timeout=self.requestTimeout, verify=False, data={'login_username':username,'login_password':'apc','submit':'Log+On'})
                            if r.url == loggedInUrl:
                                print("[$] Login successful on host: "+addr+" using "+username+"/apc")
                                defaultCredCount += 1
                                #logout if the login was successful
                                s.get(logoutUrl, timeout=self.requestTimeout, verify=False)
                            elif r.url == loginFailUrl:
                                print("[X] Login failed on host: "+addr+" using "+username+"/apc")
                                failedLoginCount += 1
                                s.get(logoutUrl, timeout=self.requestTimeout, verify=False)
                            else:
                                print("[?] Was redirected to unexpected location "+str(r.url)+" on host: "+addr)
                                s.get(logoutUrl, timeout=self.requestTimeout, verify=False)
                        
                    except requests.exceptions.RequestException as err:
                        print("[X] bad connection on host: "+addr)
                        print err
                        notAPC += 1
                    time.sleep(self.delay)
                #end of for loop
        print("Test was performed on the provided "+str(totalHosts)+" hosts, "+str(notTQ)+" did not appear to be running APC, "+str(defaultCredCount)+" had default credentials, and "+str(failedLoginCount)+" appeared to have modified credentials")

#argument parser
if __name__ == "__main__":
    parser = ArgumentParser(
        description = "Will check if supplied list of ip's has default username and password for APC manager")

    parser.add_argument(
        '-i',
        '--inputFile',
        required=True,
        dest='inputFile',
        nargs='?',
        help='File of new line divided IP addresses to test'
    )#add argument input file

    parser.add_argument(
        '-t',
        '--timeout',
        type=int,
        default=15,
        help="timeout length for web requests, default 15 seconds",
        dest='requestTimeout'
    )#add argument timeout

    parser.add_argument(
        '-d',
        '--delay',
        type=int,
        default=0,
        help="time in seconds to delay between each login attempt to throttle assessment",
        dest='delay'
    )#add argument delay

    parser.add_argument(
        '-s',
        '--secure',
        dest='secure',
        action="store_true",
        help="check login on https port (2783) instead of http port (2780)" 
    )#add secure flag

    parser.add_argument(
        '-p',
        '--proxy',
        dest='proxy',
        help='web proxy to send requests through'
    )#add web proxy flag

    args = parser.parse_args()

    APCLogin = Login(inputFile=args.inputFile, requestTimeout=args.requestTimeout,delay=args.delay, secure=args.secure, proxy=args.proxy)
    APCLogin.run()
