CFTP
---

This project attempts to provide access to an encrypted filesystem via sftp

It uses docker to compile the binaries and the main Dockerfile adds the linux
binary to the busybox image to create an extremely small final image

Building
---

```bash
go build -o cftp_linux-amd64 -tags netgo *.go
# Or
./script/build
```
> `-tags netgo` will help you achieve static binaries :)

Running
---

```bash
./cftp_linux-amd64
docker run --rm -ti pdxjohnny/cftp
```

Changing The Name
---

```bash
./script/change-name $GITHUB_USERNAME $PROJECT_NAME
```


- John Andersen
