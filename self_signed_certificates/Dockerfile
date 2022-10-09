# You can use this container to generate a self signed certificate
FROM fedora:37
RUN dnf install -y nss-tools curl
RUN curl --fail --location --remote-header-name --output /usr/local/bin/mkcert 'https://dl.filippo.io/mkcert/latest?for=linux/amd64' && \
    chmod a+x /usr/local/bin/mkcert && \
    dnf clean -y all
LABEL BULILD_INSTRUCTIONS="podman build --file Dockerfile --tag mkcert_image"
LABEL RUN="mkdir --verbose --parents $HOME/Downloads/ && podman run --rm --interactive --tty --volume $HOME/Downloads:/certs mkcert_image mkcert -cert-file /certs/cert.pem -key-file /certs/cert.key dmaf5 localhost 192.168.1.30 ::1"
LABEL DESCRIPTION="Container to create self-signed SSL certificates using https://github.com/FiloSottile/mkcert/"
LABEL AUTHOR="Jose Vicente Nunez (kodegeek.com@protonmail.com)"