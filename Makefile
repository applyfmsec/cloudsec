build-core:
	docker build -t jstubbs/cloudsec .

build-tests: build-core
	docker build -t jstubbs/cloudsec-tests -f Dockerfile-tests .

build-tapis: build-tests
	docker build -t jstubbs/cloudsec-tapis -f Dockerfile-tapis .

build-exs: build-tapis
	docker build -t jstubbs/cloudsec-exs -f Dockerfile-exs .

build-perf: build-core
	docker build -t jstubbs/cloudsec-tests-perf -f Dockerfile-perf .

build: build-core build-exs build-tests build-perf

test: build-tests
	docker run -it --rm jstubbs/cloudsec-tests
