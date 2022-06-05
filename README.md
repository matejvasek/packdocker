# PackDocker

Implements subset of Docker API that is required for creating buildpack/builder images.
This allows to create buildpack/builder images if docker daemon is not available.
The resultant images are being stored as tarballs instead of being stored into daemon.

### Example

In one terminal:
```sh
packdocker -s=/tmp/d.sock -o=/tmp/out -u=testuser -p=testpwd
```

In another terminal:
```sh
export DOCKER_HOST="unix:///tmp/d.sock"
pack buildpack package example.com/boson/faas-quarkus-jvm-bp:tip --path ./buildpacks/quarkus-jvm/
pack buildpack package example.com/boson/faas-springboot-bp:tip --path ./buildpacks/springboot/
pack builder create --pull-policy=never example.com/boson/faas-jvm-builder:tip --config jvm-builder.toml
```
After this the `/tmp/out` directory will contain three tarballs (2 buildpacks, 1 builder) and `tags.json`.

The `tags.json` contains mapping between repo tag (e.g. `example.com/boson/faas-jvm-builder:tip`) and image sha256.