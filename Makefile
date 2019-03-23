compile_generate_keys:
	gcc -o generate_keys generate_keys.c -lssl -lcrypto

generate_keys:
	./generate_keys

clean:
	rm generate_keys