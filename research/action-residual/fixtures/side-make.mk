.PHONY: test

test:
	$(MAKE) -C ../.. test
	printf 'make side effect\n' > ../make-marker.txt
