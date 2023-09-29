# Build recipes for the CloudSec software container images.
# Set the IMAGE_NAMESPACE variable to define the image repository; by default, we use the
# official CloudSec resporitory on GitHub Container Registry (ghcr.io/applyfmsec)

IMAGE_NAMESPACE ?= ghcr.io/applyfmsec

all:
	$(Using image namespace: $(IMAGE_NAMESPACE))

build-core: all
	docker build -t $(IMAGE_NAMESPACE)/cloudsec .

build-tests: build-core
	docker build -t $(IMAGE_NAMESPACE)/cloudsec-tests -f Dockerfile-tests .

build-tapis: build-tests
	docker build -t $(IMAGE_NAMESPACE)/cloudsec-tapis -f Dockerfile-tapis .

build-exs: build-tapis
	docker build -t $(IMAGE_NAMESPACE)/cloudsec-exs -f Dockerfile-exs .

build-perf: build-core
	docker build -t $(IMAGE_NAMESPACE)/cloudsec-tests-perf -f Dockerfile-perf .

build: build-core build-exs build-tests build-perf

test: build-tests
	docker run -it --rm $(IMAGE_NAMESPACE)/cloudsec-tests
