# Dynamic Link to OpenLDAP Lib
when defined(Linux):
  const libName* = "libldap_r.so"

# Set LDAP Version
var LDAP_VERSION* = 3
let LDAP_VERSION_PTR* = addr LDAP_VERSION


# Define some objects
type LDAP* = object
type LDAPPtr* = ptr LDAP
type LDAPMsg* = object

type LDAPControl = object
type LDAPControlPtr = ptr LDAPControl

# Define some constants
const
  LDAP_OPT_PROTOCOL_VERSION* = 0x0011
  LDAP_SCOPE_BASE* =  0x0000
  LDAP_SCOPE_ONELEVEL* = 0x0001
  LDAP_SCOPE_SUBTREE* = 0x0002



proc ldap_initialize*(ldap: ptr ptr LDAP, uri: cstring ): cint {.importc: "ldap_initialize", dynlib: libName.}
proc ldap_install_tls*(ldap: LDAPPtr ): cint {.importc: "ldap_install_tls", dynlib: libName.}
proc ldap_start_tls_s*(ldap: LDAPPtr, serverctrls: ptr LDAPControlPtr, clientctrls: ptr LDAPControlPtr ): cint {.importc: "ldap_start_tls_s", dynlib: libName.}
proc ldap_tls_inplace*(ldap: LDAPPtr ): cint {.importc: "ldap_tls_inplace", dynlib: libName.}
proc ldap_start_tls*(ldap: LDAPPtr ): cint {.importc: "ldap_start_tls", dynlib: libName.}
proc ldap_init*(host: cstring,port: cint ): LDAPPtr {.importc: "ldap_init", dynlib: libName.}
#proc ldap_initialize(ldap: LDAPPtr, uri: cstring ): cint {.importc: "ldap_init", dynlib: libName.}
proc ldap_simple_bind*(ldap: LDAPPtr, who: cstring, passwd: cstring ): cint {.importc: "ldap_simple_bind_s", dynlib: libName.}
proc ldap_err2string*(err: int): cstring {.importc: "ldap_err2string", dynlib: libName.}
proc ldap_set_option*(ldap: LDAPPtr ; option: cint; invalue: pointer): cint {.importc: "ldap_set_option", dynlib: libName.}
proc ldap_search_s*(ldap: LDAPPtr; base: cstring, scope: cint, filter: cstring, attrs: cstringArray, attrsonly: cint, ldapmsg: ptr ptr LDAPMsg ): cint  {.importc: "ldap_search_s", dynlib: libName.}

proc ldap_first_entry*(ldap: LDAPPtr; ldapmsg: ptr LDAPMsg): ptr LDAPMsg {.importc: "ldap_first_entry", dynlib: libName.}
proc ldap_next_entry*(ldap: LDAPPtr; ldapmsg: ptr LDAPMsg): ptr LDAPMsg {.importc: "ldap_next_entry", dynlib: libName.}
proc ldap_count_entries*(ldap: LDAPPtr; ldapmsg: ptr LDAPMsg): cint {.importc: "ldap_count_entries", dynlib: libName.}
proc ldap_msgid*(ldapmsg: ptr LDAPMsg): cint {.importc: "ldap_msgid", dynlib: libName.}
proc ldap_get_dn*(ldap: LDAPPtr, ldapmsg: ptr LDAPMsg): cstring {.importc: "ldap_get_dn", dynlib: libName.}
proc ldap_get_values*(ldap: LDAPPtr, ldapmsg: ptr LDAPMsg, attr: cstring): cstringarray {.importc: "ldap_get_values", dynlib: libName.}
proc ldap_count_values*(vals: cstringarray): cint {.importc: "ldap_count_values", dynlib: libName.}
