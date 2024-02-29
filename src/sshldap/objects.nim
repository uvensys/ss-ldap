type LDAPUser* = object
  uid*: string
  cn*: string
  hosts*: seq[string]
  keys*: seq[string]
