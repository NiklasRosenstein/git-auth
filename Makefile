
test:
	docker run --rm -it $(shell docker build . -q) nodepy ./src/client.py --test --username JohnSmith
