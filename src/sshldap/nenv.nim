import std/[os, strutils]

# TODO: Implement error handling on custom functions
proc getEnvStr*(key: string): string = getEnv(key) ## get env value and convert to string
proc getEnvInt*(key: string): int = parseInt(getEnv(key)) ## convert getEnv value to int
proc getEnvFloat*(key: string): float = parseFloat(getEnv(key)) ## convert getEnv value to float
proc getEnvBool*(key: string): bool = parseBool(getEnv(key)) ## convert getEnv value to bool


proc loadEnv*(filename: string = ".env", upperKeys: bool = true) =
  ## loadEnv loads the '.env' file and parses it to the environment variables to be accessible
  ## || filename = custom .env filename, defaults to .env
  ## || upperKeys = environment variables will be capitalized, defaults to true

  var f: File

  if open(f, joinPath(filename)):
    for i in f.lines:
      if '=' in i:
        var tempEnv = split(i, '=',1)

        var key = tempEnv[0].strip()

        # if upperkey is set to true
        if upperKeys:
          key = key.toUpper()

        putEnv(key, tempEnv[1].strip())

  
  defer: f.close()


