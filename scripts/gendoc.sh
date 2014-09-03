#!/bin/bash

MATRIXDOTORG=$HOME/workspace/matrix.org

rst2html-2.7.py --stylesheet=basic.css,nature.css ../docs/specification.rst > $MATRIXDOTORG/docs/spec/index.html
rst2html-2.7.py --stylesheet=basic.css,nature.css ../docs/client-server/howto.rst > $MATRIXDOTORG/docs/howtos/client-server.html

perl -pi -e 's#<head>#<head><link rel="stylesheet" href="/site.css">#' $MATRIXDOTORG/docs/spec/index.html $MATRIXDOTORG/docs/howtos/client-server.html

perl -pi -e 's#<body>#<body><div id="header"><div id="headerContent">&nbsp;</div></div><div id="page"><div id="wrapper"><div style="text-align: center; padding: 40px;"><img src="/matrix.png" width="305" height="130" alt="[matrix]"/></div>#' $MATRIXDOTORG/docs/spec/index.html $MATRIXDOTORG/docs/howtos/client-server.html

perl -pi -e 's#</body>#</div></div><div id="footer"><div id="footerContent">&copy 2014 Matrix.org</div></div></body>#' $MATRIXDOTORG/docs/spec/index.html $MATRIXDOTORG/docs/howtos/client-server.html