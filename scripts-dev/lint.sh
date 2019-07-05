isort -y -rc synapse tests scripts-dev scripts
flake8 synapse tests
python3 -m black .
