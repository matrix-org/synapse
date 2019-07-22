import re
import os.path

from twisted.python.filepath import FilePath

r = re.compile(rb"defer\.returnValue\((.*)\)$", re.MULTILINE)
r2 = re.compile(rb"defer\.returnValue\(", re.MULTILINE)


for dirpath, subdirs, files in os.walk("synapse"):
    for x in files:
        x = os.path.join(dirpath, x)
        print(x)
        if x.endswith(".py"):
            file = FilePath(x)
            old = file.getContent()
            new = r.sub(br"return \1", old)
            new = r2.sub(br"return (", new)

            if old != new:
                file.setContent(new)