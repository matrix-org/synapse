import sys
from tap.parser import Parser
from tap.line import Result, Unknown, Diagnostic

out = []

p = Parser()

in_error = False

for line in p.parse_file(sys.argv[1]):
    if isinstance(line, Result):
        in_error = False

        if not line.ok and not line.todo:
            in_error = True

            out.append("- FAILURE Test #%d: %s" % (line.number, line.description))
            out.append("")

    elif isinstance(line, Diagnostic) and in_error:
        out.append((" " * 7) + line.text)


for line in out:
    print(line)
