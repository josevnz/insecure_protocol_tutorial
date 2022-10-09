FROM httpd:2.4
COPY public_html/index.html /usr/local/apache2/htdocs/secret/index.html
COPY etc/httpd.conf /usr/local/apache2/conf/httpd.conf
COPY etc/httpd-ssl.conf /usr/local/apache2/conf/extra/httpd-ssl.conf
COPY etc/cert.pem /usr/local/apache2/conf/server.crt
COPY etc/cert.key /usr/local/apache2/conf/server.key
ARG PASSWORD
RUN htpasswd -dbc /usr/local/apache2/conf/.htpasswd admin ${PASSWORD}
LABEL BUILD_INSTRUCTIONS="podman build --file Dockerfile --tag kodegeek-apache-image --build-arg PASSWORD=$PASSWORD"
LABEL RUN="podman run --detach --tty --name kodegeek_apache --publish 8080:8080 --publish 8443:8443 kodegeek-apache-image"
LABEL MONITOR="podman logs --follow kodegeek_apache"
LABEL INSPECT="podman exec --interactive --tty kodegeek_apache /bin/bash"
LABEL DESCRIPTION="Sets up services that offer no encrpyption, it can be used with a sniffer to demostrate problems."
LABEL AUTHOR="Jose Vicente Nunez (kodegeek.com@protonmail.com)"