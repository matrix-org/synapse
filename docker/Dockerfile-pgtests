# Use the Sytest image that comes with a lot of the build dependencies
# pre-installed
FROM matrixdotorg/sytest:latest

# The Sytest image doesn't come with python, so install that
RUN apt-get -qq install -y python python-dev python-pip

# We need tox to run the tests in run_pg_tests.sh
RUN pip install tox

ADD run_pg_tests.sh /pg_tests.sh
ENTRYPOINT /pg_tests.sh
