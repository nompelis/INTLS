# INTLS
A plain C code to handle TLS with openSSl for your non-HTTPS webserver


SUMMARY

If you do not recognize how important HTTPS is, you still live in the early
90s. Your server needs to run over HTTPS (not plain HTTP) and most browsers
will complain if you are running a version with old ciphers and HMAC hash
functions for the digital signatures. This code allows you to run a plain
HTTP server (which means it can be your organic implementaion of HTTP) with
a version of openSSL of your choice as the TLS engine.

This code listens to port 443 with its main thread. Once a connection is
made to port 443, it will spawn a POSIX thread to handle TLS handshake and
key exchnage, and will let the thread handle or subsequent traffic in full
duplex mode.

This code works and should be bulletproof, as it is simple. HOWEVER, I am
not using anything other than the legacy Linux "fd sets" for the TCP sockets,
with "select()" for handling activity. This will _not_ work for large volumes
of traffic -- but I am not willing to write a very scalable one for you. You
can change from POSIX threads to fork()ing and bypass the problem to a large
extent.

You will need to create a certificate and server key with openssl's CLI tool.
You can ask ChatGPT (or other AI) to help you with that. You will also need
to have your browser handle this "localhost" exception for testing. But if
you have a webserver you can test it from there, and with a Let's Encrypt
certificate.

This code is subject to my licensing terms, which make me not be responsible
for how irresponsibly you will use this code... But you can send me chocolate
if this helped you learn anything.

IN 2025/08/01

