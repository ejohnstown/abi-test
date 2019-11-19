all: client 

client: client.c
	gcc -o client -I./local/include -L./local/lib client.c -lwolfssl -lm

clean:
	rm -rf client x509

.PHONY: all clean
