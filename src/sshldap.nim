import os
import elvis
import system
import strformat
import strutils
import sshldap/constants
import sshldap/nenv
import sshldap/objects
import sshldap/fnmatch
import commandeer
import nativesockets
import chronicles

# changelog
# 0.1 time starts flowing
# 0.2 logging
# 0.3 TLS
# 0.4 local users

# Variables
let version = "0.4"
let myname = "ssh-ldap"
let appdir = getAppDir()
let local_user_dir = "local_users"

# if user asks for version, show and exit
proc show_version(): string =
    echo fmt"{myname} version {version}"
    quit 0
#
# Parse user Options
commandline:
  argument search_for, string
  exitoption "version", "V", show_version()
  option verbose, bool, "verbose", "v"


# Functions
proc get_local_user(search_for: string): string =
  var result = ""
  var filedata: string
  var userfile = fmt"{appdir}/{local_user_dir}/{search_for}"
  try:
    result = readFile(userfile)
  except IOError:
    discard 
  return result 
      
      

proc check_result(resint: cint, abort=true): bool=
  var resultstr = ldap_err2string(resint)
  if resultstr == "Success":
    return true
  else:
    info "error: ", error=resultstr
    if abort:
      error "error: ", error=resultstr
      quit 5
    else:
      return false

proc get_ldap_user(search_for: string,ldap: LDAPPtr,ldap_base: string, filter: string): seq[LDAPUser] =
  info "getting users", users=search_for
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
  info "getting group members", members=search_for
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
  

proc filter_access(users: seq[LDAPUser], hostname: string): seq[LDAPUser] =
  for user in users:
    if len(user.hosts) == 0:
      continue

    if fmt"!{hostname}" in user.hosts:
      continue

    if hostname in user.hosts:
      result.add(user)
      continue

    if "*" in user.hosts:
      result.add(user)
      continue

    for host in user.hosts:
      if fnmatch(fmt"!{hostname}",host):
        break
      if fnmatch(hostname,host):
        result.add(user)
        break



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

if CHECK_HOST_PERMISSION:
  Users = filter_access(Users, getHostName())

for user in Users:
  for key in user.keys:
    echo key
stdout.flushFile()

