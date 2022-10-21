# When and why to replace insecure network protocols

The reason is that clear text protocols are trivially easy to capture and analyze; many of these services where written when Internet was on its infancy but now attacker have better tools at their disposal to capture sensitive information, it also means the bar is pretty low for this kind of attacks.

What we will learn here:

* How to use [podman](https://podman.io/) to setup thrown away services to learn about insecure settings and protocols
* How to use [tshark](https://www.wireshark.org/docs/man-pages/tshark.html) to capture and decode network traffic in real time
* How replacing obsolete services with more modern alternatives to eliminate this type of attack

This tutorial assumes you have:

* Access to podman or docker
* Privileged access, so you can run tshark and containers in special mode
* Basic knowledge of network protocols like TCP/IP, HTTP, FTP (But don't worry too much if not)

# Capturing credentials on Basic authentication against an unencrypted HTTPD Apache server

## Apache sandbox preparation

We need to create a self-signed SSL certificate for our demo, for that we will create a container based on the [Fedora 37 Linux distribution](https://hub.docker.com/_/fedora) and the [mkcert](https://github.com/FiloSottile/mkcert/) application:

```shell
[josevnz@dmaf5 self_signed_certificates]$ podman run --rm --interactive --tty --volume $HOME/Downloads:/certs mkcert_image mkcert -cert-file /certs/cert.pem -key-file /certs/cert.key dmaf5 localhost 192.168.1.30 ::1
```

Then we will use this new SSL certificates for our podman container running Apache:

[![asciicast](https://asciinema.org/a/526697.svg)](https://asciinema.org/a/526697)

Next step is to build our special [Apache container](https://www.docker.com/blog/how-to-use-the-apache-httpd-docker-official-image/):

[![asciicast](https://asciinema.org/a/526761.svg)](https://asciinema.org/a/526761)

Now we are good to go. Let's test the authentication next.

## Testing authentication with CURL

```shell
curl --silent --user admin:notsosecurepassword http://dmaf5:88080/secret/
# We use --insecure because is a self-signed certificate
curl --insecure --silent --user admin:notsosecurepassword https://dmaf5:8443/secret/
```

[![asciicast](https://asciinema.org/a/526768.svg)](https://asciinema.org/a/526768)

Time to see how much sensitive information we can get with tshark

## Using tshark to sniff the traffic between CURL and the podman container

HTTP sends data without encryption; Let me demonstrate how to create a podman container that protects a directory with a user/ password combination:

```shell
[josevnz@dmaf5 httpd]$ curl --silent --user admin:notsosecurepassword http://dmaf5:8080/secret/
<!-- Simple webpage used in our demo site. -->
<html>
<head>
    <title>ASCII art with Python 3</title>
</head>
<body bgcolor="black">
<script id="asciicast-518884" src="https://asciinema.org/a/518884.js" async></script>
</body>
</html>
```

And attacker running tshark could easily get your password (tshark expression with -Y allow us to focus on the traffic we care about):

```shell
tshark -i eno1 -Y 'http.request.method == GET and http.host == dmaf5:8080' -T json
```

The captured output may look like this:

[![asciicast](https://asciinema.org/a/526771.svg)](https://asciinema.org/a/526771)

tshark **is nice enough** to even decode the base64 password for you (```echo YWRtaW46bm90c29zZWN1cmVwYXNzd29yZA==|base64 --decode```)

**The problem is much worse than just password leaking**; Any data you transmit (sensitive documents, credit card information, etc.) can be captured and extracted later.

Now let's try using a secure connection; For our demo we will use a self-signed certificate but in production you will use a proper setup.

Because the traffic is encrypted, the following expression doesn't show any data as tshark cannot see the encrypted payload:

```shell
tshark -i eno1 -Y 'http.request.method == GET and http.host == dmaf5:8443' -T json
```

We have to go lower on the protocol stack:

```shell
tshark -i eno1 -Y 'tcp.port == 8443' -T json
```

And no password this time!

[![asciicast](https://asciinema.org/a/526769.svg)](https://asciinema.org/a/526769)

### The fix for HTTP: Switch to HTTPS

You can easily install either a self-signed certificate for your test servers using 'https://github.com/FiloSottile/mkcert/' or if you have internet facing services you can use Certbot like this (below is an ansible playbook fragment to secure a nginx proxy): 

```yaml
- name: Setup Certbot
  pip:
    requirements: /opt/requirements_certboot.txt
    virtualenv: /opt/certbot/
    virtualenv_site_packages: true
    virtualenv_command: /usr/bin/python3 -m venv
  tags: certbot_env

- name: Get SSL certificate
  command:
    argv:
      - /opt/certbot/bin/certbot
      - --nginx
      - --agree-tos
      - -m {{ ssl_maintainer_email }}
      - -d {{ inventory_hostname }}
      - --non-interactive
  notify:
    - Restart Nginx
  tags: certbot_install

- name: Creates a cron file under /etc/cron.d/certbot_renew
  ansible.builtin.cron:
    name: certboot renew
    weekday: "5"
    minute: "0"
    hour: "0"
    user: root
    job: "/opt/certbot/bin/certbot renew --quiet --pre-hook 'systemctl stop nginx' --post-hook 'systemctl start nginx'"
    cron_file: certbot_renew
  tags: certbot_renew
```

Enough of HTTP, let's examine another application

# Using Telnet and FTP when you should be using SSH, SFTP

Yes, you will be surprised how many times I still get asked to setup a ftp or a telnet server (and the answer is still the same :-)).

## Sniffing the password from an FTP server

Let's take a [vsftpd container for a spin](https://registry.hub.docker.com/r/fauria/vsftpd/#!); And will write a tshark expression that [looks for specific ftp fields](https://www.wireshark.org/docs/dfref/f/ftp.html):

```shell
podman run --detach --tty --network=host --privileged --name kodegeek_vsftpd --env FTP_USER=admin --env FTP_PASS=insecurepassword --env LOG_STDOUT=yes fauria/vsftpd
tshark -i eno1 -Y 'ftp.request.command == USER or ftp.request.command == PASS' -T json
```

And on a different terminal we establish a ftp session against our container:

```shell
josevnz@raspberrypi:~$ ftp -4 -n -v dmaf5 
Connected to dmaf5.home.
220 (vsFTPd 3.0.2)
ftp> user admin insecurepassword
331 Please specify the password.
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> 
```

Tshark will nicely spit out the user and password for us in clear text:

```json
          "ftp.request": "1",
          "ftp.response": "0",
          "USER admin\\r\\n": {
            "ftp.request.command": "USER",
            "ftp.request.arg": "admin"
          }
...
        "ftp": {
          "ftp.request": "1",
          "ftp.response": "0",
          "PASS insecurepassword\\r\\n": {
            "ftp.request.command": "PASS",
            "ftp.request.arg": "insecurepassword"
          }
        },
```

See it in action:

[![asciicast](https://asciinema.org/a/526784.svg)](https://asciinema.org/a/526784)

### The fix for FTP: Switch to SFTP

There are lots of tutorials about SFTP out there, you can get started with this one: [How to use SCP and SFTP to securely transfer files](https://www.redhat.com/sysadmin/secure-file-transfer-scp-sftp)

Finally, time to see our last application

# What do you see during a telnet session?

A telnet server is one of those services that no one should see on their networks. I won't even ask you to run a container, instead I will show you how a live capture looks like (if you are curious I used the [Docker telnet server](https://github.com/Jared-Harrington-Gibbs/Docker-Files/tree/master/telnet-server) for this demo).

Of course tshark can decode[ Telnet traffic fields](https://www.wireshark.org/docs/dfref/t/telnet.html) on real time, so let's take it for a spin.

### The fix for Telnet: Switch to SSH

Again, there is no shortage of tutorials out there: [How to access remote systems using SSH](https://www.redhat.com/sysadmin/access-remote-systems-ssh) 

```shell
[josevnz@dmaf5 InsecureContainer]$ tshark -i eno1 -Y 'telnet' -T fields -e telnet.data
Capturing on 'eno1'
Ubuntu 17.10\r\n
dmaf5 login: 
r
r
o
o
o
o
t
t
\r
\r\n
Password: 
m
a
l
w
a
r
e
\r
\r\n
Last login: Sun Oct  9 01:32:14 UTC 2022 from raspberrypi.home on pts/1\r\n
```

Which is more or less the same you see on the client side:

```shell
josevnz@raspberrypi:~$ telnet dmaf5
Trying fd22:4e39:e630:1:1937:89d4:5cbc:7a8d...
Connected to dmaf5.home.
Escape character is '^]'.
Ubuntu 17.10
dmaf5 login: root
Password: 
Last login: Sun Oct  9 01:32:14 UTC 2022 from raspberrypi.home on pts/1
```

One last time in action:

[![asciicast](https://asciinema.org/a/526785.svg)](https://asciinema.org/a/526785)

# What is next?

* There is more you can do to secure your networks. [Learn how to use Wireshark](https://www.wireshark.org/#learnWS), because the bad actors already know.
* [Get started](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/system_administrators_guide/ch-openssh) with SSH server configuration; There are [lots of resources](https://www.redhat.com/sysadmin/search/node?keys=ssh) out there.
* Get the [code from this tutorial](https://github.com/josevnz/insecure_protocol_tutorial); We managed to do a lot of work with containers, with minimum effort.
