main:
	gcc -o main.out -I ../secp256k1/src/ -I ../secp256k1/ main.c -lssl -lcrypto -lgmp

clean:
	rm *.out