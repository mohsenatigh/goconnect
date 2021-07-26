#/bin/sh
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out crt.pem -days 1046 -nodes -config ./ssl.conf.crt -extensions ext
