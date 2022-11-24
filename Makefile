build-core:
	docker build -t jstubbs/cloudsec .

build-exs: build-core
	docker build -t jstubbs/cloudsec-exs -f Dockerfile-exs .

build-tests: build-core
	docker build -t jstubbs/cloudsec-tests -f Dockerfile-tests .

build-perf: build-core
	docker build -t jstubbs/cloudsec-tests-perf -f Dockerfile-perf .

build: build-core build-exs build-tests build-perf

test: build-tests
	docker run -it --rm jstubbs/cloudsec-tests
