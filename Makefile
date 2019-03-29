compile_generate_keys:
	gcc -o generate_keys -I ../secp256k1/src/ -I ../secp256k1/ generate_keys.c -lssl -lcrypto -lgmp

generate_keys:
	./generate_keys

clean:
	rm generate_keys