isort -rc synapse/ tests
flake8 synapse tests
python3 -m black synapse/ tests
