build-core:
	docker build -t jstubbs/cloudsec .

build-exs: build-core
	docker build -t jstubbs/cloudsec-exs -f Dockerfile-exs .

build: build-core build-exs