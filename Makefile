
.PHONY: test
test:
	docker build . -f test/Dockerfile -t git-auth-test -q
	docker run --rm -it git-auth-test
