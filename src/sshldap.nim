import os
import std/logging
import std/parseopt
import elvis
import system
import strformat
import strutils
import sshldap/constants
import sshldap/nenv
import sshldap/objects
import sshldap/fnmatch
import nativesockets
# import fnmatch # moved into source code
# import commandeer # use std/parseopts
# import chronicles # use std/logging

# changelog
# 0.1 time starts flowing
# 0.2 logging
# 0.3 TLS
# 0.4 local users
# 0.5 extended host filter
# 0.6 scary bug fix
# 0.7 switch to nim 2.0, use std/logging, add tests
# 0.8 fix bugs, keep logfile relative to executable, optional logging, better logging
# 0.8.1 default log level is Warn


# Variables
let version = "0.8.1"
let myname = "ssh-ldap"
let appdir = getAppDir()
let local_user_dir = "local_users"


# setup logging
proc setupLoggin(log_to_file: bool = true,
                 logfile: string = "sshldap.log",
                 loglevel: Level = lvlWarn): bool = 

  var fileLog: FileLogger
  var consoleLog: ConsoleLogger
  var rescue_console = false
  var log_to_console = false

  if log_to_file:
    try:
      fileLog = newFileLogger(fmt"{appdir}/{logfile}", levelThreshold=loglevel)
      addHandler(fileLog)
    except IOError:
      rescue_console = true
      log_to_console = true
   
  if not rescue_console:
    return true


  if log_to_console:
    consoleLog = newConsoleLogger(levelThreshold=loglevel, useStderr=true)
    addHandler(consoleLog)

  if rescue_console:
    warn fmt "could not log to file: {logfile}, using console instead"

  return true
  



# if user asks for version, show and exit
proc show_version(): void =
    echo fmt"{myname} version {version}"
    quit 0

# Parse user Options, using parseopt, kinda ugly
var search_for: string
for kind, key, val in getOpt():                                        #2
  case kind                                                            #3
  of cmdArgument:                                                      #4
    search_for=key
  of cmdLongOption, cmdShortOption:                                    #5
    case key
    of "version": show_version()
    of "v": show_version()
  of cmdEnd: discard  


# Functions
proc get_local_user(search_for: string): string =
  var result = ""
  var userfile = fmt"{appdir}/{local_user_dir}/{search_for}"
  try:
    result = readFile(userfile)
  except IOError:
    discard 
  return result 
      

proc mytest*(num: int): int =
    result = num + 4

proc check_result(resint: cint, abort=true): bool=
  var resultstr = ldap_err2string(resint)
  if resultstr == "Success":
    return true
  else:
    #info "error: ", error=resultstr
    info(fmt"error: {resultstr}")
    if abort:
      info(fmt"error: {resultstr}")
      quit 5
    else:
      return false

proc get_ldap_user(search_for: string,ldap: LDAPPtr,ldap_base: string, filter: string): seq[LDAPUser] =
  #info "getting users", users=search_for
  info(fmt"getting users {search_for}")
  var base = ldap_base
  #var filter = fmt"(&(objectclass={filter})(uid={search_for}))"
  var attrs = allocCStringArray([])
  var ldapmsg : LDAPMsg
  var ptr_ldapmsg = addr ldapmsg
  var ptr_ptr_ldapmsg = addr ptr_ldapmsg
  # Search 
  discard check_result(ldap_search_s(ldap, base, LDAP_SCOPE_SUBTREE, filter, attrs  , 0, ptr_ptr_ldapmsg ),abort=false)
  # get number of results
  var cnt = ldap_count_entries(ldap, ptr_ldapmsg)
  # if we count zero results, return
  if cnt == 0:
    info "no users found"
    return
  # otherwise, step through all results

  var current = ldap_first_entry(ldap, ptr_ldapmsg)
  var hosts: seq[string]
  var keys: seq[string]
  for i in 0 ..< cnt:

    # Sanity check
    if current == nil or isNil(current):
      break
    # Get CN
    var cn = ldap_get_dn(ldap,current)
    
    # Get Host entries
    var rhosts = ldap_get_values(ldap, current, "host")
    var rhosts_counter  = ldap_count_values(rhosts)
    for h in 0 ..< rhosts_counter:
      hosts.add($rhosts[h])
 
    # Get Public Keys
    var rkeys = ldap_get_values(ldap, current, "sshPublicKey")
    var rkeys_counter  = ldap_count_values(rkeys)
    for k in 0 ..< rkeys_counter:
      keys.add($rkeys[k])

    result.add(LDAPUser(uid: search_for,cn: $cn, hosts:hosts, keys:keys))
    current = ldap_next_entry(ldap, current)
 

proc get_group_members(search_for: string,ldap: LDAPPtr,ldap_base: string): seq[string] =
  info(fmt"getting group members {search_for}")
  var base = ldap_base
  var filter = fmt"(&(objectclass=groupOfNames)(cn={search_for}))"
  var attrs = allocCStringArray([])
  var ldapmsg : LDAPMsg
  var ptr_ldapmsg = addr ldapmsg
  var ptr_ptr_ldapmsg = addr ptr_ldapmsg
  # Search 
  discard check_result(ldap_search_s(ldap, base, LDAP_SCOPE_SUBTREE, filter, attrs  , 0, ptr_ptr_ldapmsg ), abort=false)
  # get number of results
  var cnt = ldap_count_entries(ldap, ptr_ldapmsg)
  # if we count zero results, return
  if cnt == 0:
    info "no members found"
    return
  # otherwise, step through all results

  var current = ldap_first_entry(ldap, ptr_ldapmsg)
  for i in 0 ..< cnt:

    # Sanity check
    if current == nil or isNil(current):
      break
    # Get CN
    var cn = ldap_get_dn(ldap,current)
    
    # Get member entries
    var rmember = ldap_get_values(ldap, current, "member")
    var rmember_counter  = ldap_count_values(rmember)
    for m in 0 ..< rmember_counter:
      result.add($rmember[m])
  

proc filter_access*(users: seq[LDAPUser], hostname: string): seq[LDAPUser] =
  for user in users:
    info "checking ", user
    if len(user.hosts) == 0:
      continue

    if fmt"!{hostname}" in user.hosts:
      # echo fmt"WE OUT FOR {user} (1)"
      continue

    if hostname in user.hosts:
      # echo fmt"WE OUT FOR {user} (2)"
      result.add(user)
      continue

    if "*" in user.hosts:
      # echo fmt"WE OUT FOR {user} (3)"
      result.add(user)
      continue

    for host in user.hosts:
      info "comparing host:", host
      info "with hostname", hostname
      # scary bug fix
      #if fnmatch(fmt"!{hostname}",host):
      #  info "fail"
      #  break
      if fnmatch(hostname,host):
        # echo fmt"WE OUT FOR {user} (4)"
        info "success"
        result.add(user)
        break
    # echo fmt"NOTHING FOR {user} ... (5)"

proc simple_check(host: string, search_for: string, hostname: string): bool =
  result = false # defaul deny
  if len(host) == 0:
    return false

  if fmt"!{hostname}" == host:
    return false

  if hostname == host:
    return true

  if "*" == host:
    return true

  if fnmatch(hostname,host):
     return true
     
  # scary bug fixing
  #if fnmatch(fmt"!{hostname}",host):
  #  return false
  
  #echo "simple rules done"
  # simple rules are done, now check host field in detail
proc user_ok(ldap_username: string, search_for: string): bool = 
  
  if fnmatch(search_for, fmt"!{ldap_username}"):
    info "username is forbiden", ldap_username
    return false

  if fnmatch(search_for, fmt"{ldap_username}"):
    info "username is allowed", ldap_username
    return true

  if ldap_username == "*":
    info "found *, user is allowed", ldap_username
    return true

  if ldap_username == search_for:
    info "username matches", ldap_username
    return true

  result = false # default deny

proc host_ok(ldap_hostname: string, hostname: string): bool = 
  result = false # default deny

  info "hostname", hostname
  info "ldap_hostname", ldap_hostname
  if hostname == ldap_hostname:
    info "hostname matches", ldap_hostname
    return true

  if ldap_hostname == "*":
    info "found *, host is allowed", ldap_hostname
    return true

  if fnmatch(hostname, fmt"{ldap_hostname}"):
    info "host is allowed", ldap_hostname
    return true

  if fnmatch(hostname, fmt"!{ldap_hostname}"):
    info "host is denied", ldap_hostname
    return false


proc extended_check(host: string, search_for: string, hostname: string): bool =
  result =  false
  var host_splitted = split(host, "@", 2)
  var ldap_username = host_splitted[0]
  var ldap_hostname = host_splitted[1]
  if user_ok(ldap_username, search_for) and host_ok(ldap_hostname, hostname):
    info "granting access for ", search_for
    result = true
  else:
    info "denying access for ", search_for
    result = false

proc filter_access_extended(users: seq[LDAPUser], 
                            hostname: string,
                            search_for: string): seq[LDAPUser] =
                            
  for user in users:
    var username = user.uid
    info "checking user: ", username
    for host in user.hosts:
      if "@" notin host:
        info "no @ in host field, using simple check", host
        if simple_check(host, search_for, hostname):
          info ("adding user to return list")
          result.add(user)
          break
      else:
        info "found @ in host field, using extended check", host
        if extended_check(host, search_for, hostname):
          info ("adding user to return list")
          result.add(user)
          break

proc main() =
  # Load environment / Set variables
  loadenv(fmt("{appdir}/.env"))
  var LDAP_SERVER=getEnvStr("LDAP_SERVER")
  var LDAP_USER=getEnv("LDAP_USER")
  var LDAP_PASS=getEnv("LDAP_PASS")
  var LDAP_BASE=getEnv("LDAP_BASE")
  var USE_SSL = getEnvBool("USE_SSL") ?: false
  var LDAP_USER_FILTER = getEnvStr("LDAP_USER_FILTER") ?: "person"
  var CHECK_HOST_PERMISSION=getEnvBool("CHECK_HOST_PERMISSION") ?: false
  var ALWAYS_CHECK_GROUP=getEnvBool("ALWAYS_CHECK_GROUP") ?: false 
  var ALLOW_ROOT=getEnvBool("ALLOW_ROOT") ?: false
  var LOCAL_USERS=getEnvBool("LOCAL_USERS") ?: false
  #var LDAP_PORT = cint(389)
  var filter: string
  var Users: seq[LDAP_USER]
  var output: string
  # var USE_DISKCACHE=False # Not supported
  var EXTENDED_HOST_FILTER=getEnvBool("EXTENDED_HOST_FILTER") ?: false
  

  if LDAP_SERVER == "" or LDAP_USER == "" or LDAP_BASE == "":
    echo "LDAP Configuration missing"
    quit 3
  
  if search_for=="root" and not ALLOW_ROOT:
    echo "Cowardly refusing to serve root"
    quit 2
  
  
  # LDAP Server might be a list
  # Use first of the list for now
  # Throw everything else away
  if LDAP_SERVER.contains(","):
    LDAP_SERVER = LDAP_SERVER.split(",")[0]
    
  
  # Remove quotation marks
  LDAP_SERVER = strip(LDAP_SERVER,chars={'"'})
  LDAP_USER = strip(LDAP_USER,chars={'"'})
  LDAP_PASS = strip(LDAP_PASS,chars={'"'})
  LDAP_BASE = strip(LDAP_BASE,chars={'"'})
  
  if USE_SSL:
    LDAP_SERVER = fmt("ldaps://{LDAP_SERVER}")
  else:
    LDAP_SERVER = fmt("ldap://{LDAP_SERVER}")
  
  # Get local users first
  if LOCAL_USERS:
    var user_key = get_local_user(search_for)
    if user_key != "":
      echo user_key
  
  
  # Connect to LDAP
  info "connection to ldap"
  var ldap : LDAPPtr
  discard ldap_initialize(addr ldap, LDAP_SERVER)
  #ar ldap = ldap_init(LDAP_SERVER,LDAP_PORT)
  if ldap == nil or isNil(ldap):
   error "Error with ldap_init"
   quit 4
  
  
  # Set connection options , connect and login
  info "setting ldap option"
  discard check_result(ldap_set_option(ldap, LDAP_OPT_PROTOCOL_VERSION,LDAP_VERSION_PTR))
  
  if USE_SSL:
    info "starting tls"
    discard ldap_start_tls_s(ldap,nil,nil)
    if ldap_tls_inplace(ldap) != 1:
      error "No TLS Session"
      quit 6
    else:
      info "tls session established"
  else:
    warn "not using tls"
  
  
  info "binding to ldap"
  discard check_result(ldap_simple_bind(ldap, LDAP_USER,LDAP_PASS))
  
  # Get User
  filter = fmt"(&(objectclass={LDAP_USER_FILTER})(uid={search_for}))"
  Users = get_ldap_user(search_for=search_for, ldap=ldap, ldap_base=LDAP_BASE, filter=filter)
  
  # Get Users in Group
  var groupmembers = get_group_members(search_for=search_for, ldap=ldap, ldap_base=LDAP_BASE)
  for member in groupmembers:
    filter = fmt"(objectclass={LDAP_USER_FILTER})"
    Users.add(get_ldap_user(search_for=member, ldap=ldap, ldap_base=member, filter=filter))
  
  if CHECK_HOST_PERMISSION and not EXTENDED_HOST_FILTER:
    info "using simple host check" 
    Users = filter_access(Users, getHostName())
  if CHECK_HOST_PERMISSION and EXTENDED_HOST_FILTER:
    info "using extended host check" 
    Users = filter_access_extended(Users,getHostName(), search_for) 
  
  for user in Users:
    for key in user.keys:
      info fmt"found key: {key}"
      echo key
  stdout.flushFile()
 
when isMainModule:
  # Setup Logging here, might call this later again
  discard setupLoggin()
  info "started"
  main()
