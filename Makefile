TLMI_AUTH := tlmi_auth
TLMI_CRYPTO := tlmi_crypto

#Note - you get warnings if you link with openssl > 3.0 so set COMPAT flags.
#Need to migrate to new API.

default:
	gcc -c $(TLMI_CRYPTO).c -o $(TLMI_CRYPTO).o -DOPENSSL_API_COMPAT=0x1010000L
	gcc -c $(TLMI_AUTH).c -o $(TLMI_AUTH).o
	gcc -o tlmi-auth $(TLMI_AUTH).o $(TLMI_CRYPTO).o -lssl -lcrypto

clean:
	rm tlmi-auth $(TLMI_AUTH).o $(TLMI_CRYPTO).o
