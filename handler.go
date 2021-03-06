package packdocker

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/gorilla/mux"
)

// NewAPIHandler returns new handler that can serve Docker API subset needed to create buildpack/builder images.
func NewAPIHandler(workDir, arch, regUname, regPwd string) http.Handler {
	h := handler{
		workDir:  workDir,
		regUname: regUname,
		regPwd:   regPwd,
		arch:     arch,
	}
	r := mux.NewRouter()

	r.Handle("/v{version:[0-9][0-9A-Za-z.-]*}/_ping", http.HandlerFunc(h.ping)).Methods("GET")
	r.Handle("/v{version:[0-9][0-9A-Za-z.-]*}/info", http.HandlerFunc(h.info)).Methods("GET")
	r.Handle("/v{version:[0-9][0-9A-Za-z.-]*}/images/{name:.*}/tag", http.HandlerFunc(h.imageTag)).Methods("POST")
	r.Handle("/v{version:[0-9][0-9A-Za-z.-]*}/images/{name:.*}/json", http.HandlerFunc(h.imageInspect)).Methods("GET")
	r.Handle("/v{version:[0-9][0-9A-Za-z.-]*}/images/get", http.HandlerFunc(h.imageSave)).Methods("GET")
	r.Handle("/v{version:[0-9][0-9A-Za-z.-]*}/images/load", http.HandlerFunc(h.imageLoad)).Methods("POST")
	return r
}

type handler struct {
	workDir  string
	regUname string
	regPwd   string
	arch     string
}

func (h handler) info(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	info := types.Info{
		OSType:       "linux",
		Architecture: h.arch,
	}
	e := json.NewEncoder(w)
	_ = e.Encode(&info)
}

func (h handler) ping(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprint(w, "OK")
}

var emptyObject = []byte{'{', '}'}

func (h handler) imageLoad(w http.ResponseWriter, r *http.Request) {

	randBytes := make([]byte, 4)
	rand.Read(randBytes)

	f, err := os.OpenFile(filepath.Join(h.workDir, hex.EncodeToString(randBytes)+"-img.tar"), os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		responseError(err, w)
		return
	}

	_, err = io.Copy(f, r.Body)
	if err != nil && !errors.Is(err, io.EOF) {
		responseError(err, w)
		return
	}
	img, err := tarball.ImageFromPath(f.Name(), nil)
	if err != nil {
		responseError(err, w)
		return
	}
	mf, err := img.Manifest()
	if err != nil {
		responseError(err, w)
		return
	}

	tarPath := fmt.Sprintf("%s.tar", mf.Config.Digest)
	err = os.Rename(f.Name(), filepath.Join(h.workDir, tarPath))
	if err != nil {
		responseError(err, w)
		return
	}

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(emptyObject)
}

func (h handler) imageTag(w http.ResponseWriter, r *http.Request) {

	pathVars := mux.Vars(r)
	imgName := pathVars["name"]
	repo := r.URL.Query()["repo"]
	tag := r.URL.Query()["tag"]

	if len(repo) != 1 || len(tag) != 1 {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"Message": "exactly one repo and tag is supported" }`))
		return
	}

	err := h.addTag(repo[0]+":"+tag[0], imgName)
	if err != nil {
		responseError(fmt.Errorf("cannot add tag: %w", err), w)
		return
	}

	w.WriteHeader(http.StatusCreated)
}

func (h handler) imageSave(w http.ResponseWriter, r *http.Request) {

	imageNames := r.URL.Query()["names"]
	if len(imageNames) != 1 {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"Message": "exactly one image is supported" }`))
		return
	}

	img, err := h.getImage(imageNames[0])
	if err != nil {
		responseError(err, w)
		return
	}

	ref, err := name.ParseReference(imageNames[0])
	if err != nil {
		responseError(err, w)
		return
	}

	_ = tarball.Write(ref, img, w)
}

func (h handler) imageInspect(w http.ResponseWriter, r *http.Request) {

	var (
		img v1.Image
		err error
	)

	pathVars := mux.Vars(r)
	imgName := pathVars["name"]

	img, err = h.getImage(imgName)
	if err != nil {
		responseError(err, w)
		return
	}

	mf, err := img.Manifest()
	if err != nil {
		responseError(err, w)
		return
	}

	cf, err := img.ConfigFile()
	if err != nil {
		responseError(err, w)
		return
	}

	layers := make([]string, 0, len(cf.RootFS.DiffIDs))
	for _, d := range cf.RootFS.DiffIDs {
		layers = append(layers, d.String())
	}

	imageInspect := types.ImageInspect{
		ID:              mf.Config.Digest.String(),
		RepoTags:        nil,
		RepoDigests:     nil,
		Parent:          "",
		Comment:         "",
		Created:         cf.Created.Format(time.RFC3339),
		Container:       cf.Container,
		ContainerConfig: nil,
		DockerVersion:   cf.DockerVersion,
		Author:          cf.Author,
		Config: &container.Config{
			Hostname:        cf.Config.Hostname,
			Domainname:      cf.Config.Domainname,
			User:            cf.Config.User,
			AttachStdin:     cf.Config.AttachStdin,
			AttachStdout:    cf.Config.AttachStdout,
			AttachStderr:    cf.Config.AttachStderr,
			ExposedPorts:    nil,
			Tty:             cf.Config.Tty,
			OpenStdin:       cf.Config.OpenStdin,
			StdinOnce:       cf.Config.StdinOnce,
			Env:             cf.Config.Env,
			Cmd:             cf.Config.Cmd,
			Healthcheck:     nil,
			ArgsEscaped:     cf.Config.ArgsEscaped,
			Image:           cf.Config.Image,
			Volumes:         cf.Config.Volumes,
			WorkingDir:      cf.Config.WorkingDir,
			Entrypoint:      cf.Config.Entrypoint,
			NetworkDisabled: cf.Config.NetworkDisabled,
			MacAddress:      cf.Config.MacAddress,
			OnBuild:         cf.Config.OnBuild,
			Labels:          cf.Config.Labels,
			StopSignal:      cf.Config.StopSignal,
			StopTimeout:     nil,
			Shell:           cf.Config.Shell,
		},
		Architecture: cf.Architecture,
		Variant:      cf.Variant,
		Os:           cf.OS,
		OsVersion:    cf.OSVersion,
		Size:         mf.Config.Size,
		VirtualSize:  mf.Config.Size,
		GraphDriver:  types.GraphDriverData{},
		RootFS: types.RootFS{
			Type:      cf.RootFS.Type,
			Layers:    layers,
			BaseLayer: "",
		},
		Metadata: types.ImageMetadata{},
	}

	w.WriteHeader(http.StatusOK)
	e := json.NewEncoder(w)
	_ = e.Encode(imageInspect)
}

func responseError(err error, w http.ResponseWriter) {
	w.WriteHeader(http.StatusInternalServerError)
	msg := struct {
		Message string
	}{
		Message: err.Error(),
	}
	e := json.NewEncoder(w)
	e.Encode(&msg)
}

func (h handler) getImage(imgName string) (v1.Image, error) {
	var (
		ref name.Reference
		err error
	)

	tarPath := filepath.Join(h.workDir, fmt.Sprintf("sha256:%s.tar", strings.TrimPrefix(imgName, "sha256:")))
	if _, err = os.Stat(tarPath); err == nil {
		return tarball.ImageFromPath(tarPath, nil)
	}

	sha, ok, err := h.getTag(imgName)
	if err != nil {
		return nil, fmt.Errorf("cannot load tag: %w", err)
	}

	if ok {
		tarPath := filepath.Join(h.workDir, fmt.Sprintf("%s.tar", sha))
		return tarball.ImageFromPath(tarPath, nil)
	}

	var opts []remote.Option

	if h.regUname != "" {
		a := &authn.Basic{
			Username: h.regUname,
			Password: h.regPwd,
		}
		opts = append(opts, remote.WithAuth(a))
	}
	opts = append(opts, remote.WithPlatform(v1.Platform{
		Architecture: h.arch,
		OS:           "linux",
	}))

	ref, err = name.ParseReference(imgName)
	if err != nil {
		return nil, err
	}
	return remote.Image(ref, opts...)
}

func (h handler) getTag(tag string) (imgRef string, ok bool, err error) {

	f, err := os.Open(filepath.Join(h.workDir, "tags.json"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", false, nil
		}
		return "", false, err
	}
	defer f.Close()

	err = syscall.Flock(int(f.Fd()), syscall.LOCK_SH)
	if err != nil {
		return "", false, err
	}

	tags := make(map[string]string)
	d := json.NewDecoder(f)
	err = d.Decode(&tags)
	if err != nil {
		return "", false, err
	}

	imgRef, ok = tags[tag]
	return imgRef, ok, nil
}

func (h handler) addTag(tag, imgRef string) error {
	f, err := os.OpenFile(filepath.Join(h.workDir, "tags.json"), os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX)
	if err != nil {
		return err
	}

	tags := make(map[string]string)

	fi, err := f.Stat()
	if err != nil {
		return err
	}
	if fi.Size() != 0 {
		d := json.NewDecoder(f)
		err = d.Decode(&tags)
		if err != nil {
			return err
		}
	}

	_, err = f.Seek(0, io.SeekStart)
	if err != nil {
		return err
	}

	err = f.Truncate(0)
	if err != nil {
		return err
	}

	tags[tag] = imgRef
	e := json.NewEncoder(f)
	return e.Encode(&tags)
}
