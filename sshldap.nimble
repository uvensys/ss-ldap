# Package

version       = "0.8.1"
author        = "sschwebel"
description   = "ssh via ldap pubkeys"
license       = "Apache-2.0"
srcDir        = "src"
bin           = @["sshldap"]


# Dependencies

requires "nim >= 2.0.0"
#requires "chronicles" #  >= 0.10.2"
#requires "commandeer" #>= 0.12.3"
requires "elvis >= 0.5.0"
# requires "fnmatch >= 1.1.0"
