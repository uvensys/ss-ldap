import strutils
import re
import unicode

proc fnmatchEscapeRe(s: string): string =
    ## Internal proc. Escapes `s` so that it is matched verbatim when used as a regular
    ## expression. Based on the ``escapeRe`` proc in the re module in the Nim standard library.
    var escaped = ""
    for c in items(s):
        case c
        of 'a'..'z', 'A'..'Z', '0'..'9', '_':
            escaped.add(c)
        else:
            escaped.add("\\" & c)
    return escaped

proc translate*(pattern: string): string =
    ## Returns the shell-style ``pattern`` converted to a regular expression.

    var i: int = 0
    var j: int = 0
    var n: int = len(pattern)
    var c: string = ""
    var inside: string = ""
    var output: string = ""

    while i < n:
        c = "" & pattern[i]
        i += 1

        if c == "*":
            output &= ".*"

        elif c == "?":
            output &= "."

        elif c == "[":
            j = i

            if j < n and pattern[j] == '!':
                j += 1
            if j < n and pattern[j] == ']':
                j += 1

            while j < n and pattern[j] != ']':
                j += 1


            if j >= n:
                output &= "\\["
            else:
                inside = pattern[i..j+1].replace("\\", "\\\\")
                i = j + 1

                if inside[0] == '!':
                    inside = "^" & inside[1..high(inside)]
                elif inside[0] == '^':
                    inside = "\\" & inside

                output = output & "[" & inside & "]"

        else:
            output &= fnmatchEscapeRe(c)

    return output & "\\Z(?ms)"


proc fnmatch*(filename: string, pattern: string): bool =
    ## Tests whether ``filename`` matches ``pattern``, returning ``True`` or ``False``.

    let f: string = unicode.toLower(filename)
    let p: string = unicode.toLower(pattern)

    return re.match(f, re(translate(p)))

