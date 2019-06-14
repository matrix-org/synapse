import sys
from tap.parser import Parser
from tap.line import Result, Unknown, Diagnostic

out = ["### TAP Output for " + sys.argv[2]]

p = Parser()

in_error = False

for line in p.parse_file(sys.argv[1]):
    if isinstance(line, Result):
        if in_error:
            out.append("")
            out.append("</pre></code></details>")
            out.append("")
            out.append("----")
            out.append("")
        in_error = False

        if not line.ok and not line.todo:
            in_error = True

            out.append("FAILURE Test #%d: ``%s``" % (line.number, line.description))
            out.append("")
            out.append("<details><summary>Show log</summary><code><pre>")

    elif isinstance(line, Diagnostic) and in_error:
        out.append(line.text)

if out:
    for line in out[:-3]:
        print(line)
