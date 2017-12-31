.PHONY: test all

all:

build:
	docker-compose build default

shell: build
	docker-compose run default

clean:
	#docker-compose down -v
	find . -type d -iname '__pycache__' -exec rm -rf '{}' \;
	find . -type d -iname '.cache' -exec rm rf '{}' \;
	find . -type f -iname '.*.swn' -exec rm '{}' \;
	find . -type f -iname '.*.swo' -exec rm '{}' \;
	find . -type f -iname '.*.swp' -exec rm '{}' \;
	find . -type f -iname '.coverage' -exec rm '{}' \;

freeze:
	pip freeze > requirements.txt

test:
	./setup.py test
