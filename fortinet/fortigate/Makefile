VENDOR=fortinet
VR_NAME=fortios
IMAGE_FORMAT=qcow2
IMAGE_GLOB=*.qcow2
-include ../../makefile-sanity.include
-include ../../makefile.include
IMAGE=$(shell find . -type f -iname '*.qcow2' | head -n1 | cut -c3- )
VERSION=$(shell echo $(IMAGE) | sed 's|^fortios-v||' | sed -e 's/\.qcow2//')
.DEFAULT_GOAL=docker-build-fortigate
.PHONY: docker-build-fortigate docker-run-fortigate
docker-build-fortigate:
	-rm -rf docker/common docker/healthcheck.py docker/vrnetlab.py
	-if [ -n "$(IMAGE)" ]; then rm -f "docker/$(IMAGE)"; fi
	cp $(IMAGE) docker
	cp ../../common/*.py docker/
	cp -r ../common docker/common
	rm -rf docker/common/__pycache__ docker/common/features/__pycache__
	@echo "Building docker image using $(IMAGE) as $(REGISTRY)vr-$(VR_NAME):$(VERSION)"
	(cd docker; docker build --build-arg IMAGE=$(IMAGE) --build-arg http_proxy=$(http_proxy) --build-arg https_proxy=$(https_proxy) -t $(REGISTRY)vr-$(VR_NAME):$(VERSION) .)
	-rm -rf docker/common docker/healthcheck.py docker/vrnetlab.py
	-if [ -n "$(IMAGE)" ]; then rm -f "docker/$(IMAGE)"; fi

docker-run-fortigate:
	docker run -it -d --privileged --rm $(REGISTRY)vr-$(VR_NAME):$(VERSION) 
