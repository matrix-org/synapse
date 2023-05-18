all: lint test

lint:
	poetry run ./scripts-dev/lint.sh

test:
	poetry run trial tests
