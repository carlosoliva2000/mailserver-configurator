# mailserver-configurator
A Python script that configures and starts a mail server (designed for Docker Mailserver) in Docker, registering users initially if necessary.

Para crear un ejecutable con pyinstaller:
```
pyinstaller \
  --clean \
  --onefile \
  --name mailserver-configurator \
  mailserver-configurator.py

```
