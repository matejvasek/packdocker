package packdocker

import (
	"encoding/base64"
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
	"github.com/docker/docker/pkg/jsonmessage"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
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
	r.Handle("/v{version:[0-9][0-9A-Za-z.-]*}/images/create", http.HandlerFunc(h.imageCreate)).Methods("POST")

	r.Handle("/v{version:[0-9][0-9A-Za-z.-]*}/{.*}", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logrus.Warn("unimplemented endpoint has been invoked")
		w.WriteHeader(http.StatusNotImplemented)
		w.Write([]byte(`{"message":"endpoint not implemented by packdocker"}`))
	}))

	return logQueriesMiddleware(r)
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
	respondError := errorResponder(w)

	randBytes := make([]byte, 4)
	rand.Read(randBytes)

	f, err := os.OpenFile(filepath.Join(h.workDir, hex.EncodeToString(randBytes)+"-img.tar"), os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		respondError(err)
		return
	}

	_, err = io.Copy(f, r.Body)
	if err != nil && !errors.Is(err, io.EOF) {
		respondError(err)
		return
	}
	img, err := tarball.ImageFromPath(f.Name(), nil)
	if err != nil {
		respondError(err)
		return
	}
	mf, err := img.Manifest()
	if err != nil {
		respondError(err)
		return
	}

	tarPath := fmt.Sprintf("%s.tar", mf.Config.Digest)
	err = os.Rename(f.Name(), filepath.Join(h.workDir, tarPath))
	if err != nil {
		respondError(err)
		return
	}

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(emptyObject)
}

func (h handler) imageTag(w http.ResponseWriter, r *http.Request) {
	respondError := errorResponder(w)

	pathVars := mux.Vars(r)
	imgName := pathVars["name"]
	repo := r.URL.Query()["repo"]
	tag := r.URL.Query()["tag"]

	if len(repo) != 1 || len(tag) != 1 {
		respondError(errors.New("exactly one repo and tag is supported"))
		return
	}

	err := h.addTag(repo[0]+":"+tag[0], imgName)
	if err != nil {
		respondError(fmt.Errorf("cannot add tag: %w", err))
		return
	}

	w.WriteHeader(http.StatusCreated)
}

func (h handler) imageSave(w http.ResponseWriter, r *http.Request) {
	respondError := errorResponder(w)

	imageNames := r.URL.Query()["names"]
	if len(imageNames) != 1 {
		respondError(errors.New("exactly one image is supported"))
		return
	}

	img, err := h.getImage(imageNames[0])
	if err != nil {
		respondError(err)
		return
	}

	ref, err := name.ParseReference(imageNames[0])
	if err != nil {
		respondError(err)
		return
	}

	err = tarball.Write(ref, img, w)
	if err != nil {
		logrus.Error(err)
	}
}

func (h handler) imageInspect(w http.ResponseWriter, r *http.Request) {
	respondError := errorResponder(w)

	var (
		img v1.Image
		err error
	)

	pathVars := mux.Vars(r)
	imgName := pathVars["name"]

	img, err = h.getImage(imgName)
	if err != nil {
		respondError(fmt.Errorf("cannot inspect image: %w", err))
		return
	}

	mf, err := img.Manifest()
	if err != nil {
		respondError(err)
		return
	}

	cf, err := img.ConfigFile()
	if err != nil {
		respondError(err)
		return
	}

	layers := make([]string, 0, len(cf.RootFS.DiffIDs))
	for _, d := range cf.RootFS.DiffIDs {
		layers = append(layers, d.String())
	}

	imageInspect := types.ImageInspect{
		ID:              mf.Config.Digest.String(),
		RepoTags:        []string{imgName},
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
	err = e.Encode(imageInspect)
	if err != nil {
		logrus.Error(err)
	}
}

func errorResponder(w http.ResponseWriter) func(err error) {
	e := json.NewEncoder(w)
	return func(err error) {
		var infe imageNotFound
		switch {
		case errors.As(err, &infe):
			logrus.Warn(err)
			w.WriteHeader(http.StatusNotFound)
		default:
			logrus.Error(err)
			w.WriteHeader(http.StatusInternalServerError)
		}
		msg := struct {
			Message string
		}{
			Message: err.Error(),
		}
		_ = e.Encode(&msg)
	}
}

type imageNotFound struct {
	img string
}

func (i imageNotFound) Error() string {
	return fmt.Sprintf("image not found: %s", i.img)
}

func (h handler) getImage(imgName string) (v1.Image, error) {
	var err error

	tarPath := filepath.Join(h.workDir, fmt.Sprintf("sha256:%s.tar", strings.TrimPrefix(imgName, "sha256:")))
	if _, err = os.Stat(tarPath); err == nil {
		return tarball.ImageFromPath(tarPath, nil)
	}

	sha, ok, err := h.getTag(imgName)
	if err != nil {
		return nil, fmt.Errorf("cannot load tag: %w", err)
	}

	if ok {
		tarPath = filepath.Join(h.workDir, fmt.Sprintf("%s.tar", sha))
		if _, err = os.Stat(tarPath); err == nil {
			return tarball.ImageFromPath(tarPath, nil)
		}
	}

	return nil, imageNotFound{img: imgName}
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

func (h handler) imageCreate(w http.ResponseWriter, r *http.Request) {
	respondError := errorResponder(w)
	fromImages := r.URL.Query()["fromImage"]
	tags := r.URL.Query()["tag"]

	if len(fromImages) != 1 || len(tags) != 1 {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"Message": "exactly one fromImage and tag is supported" }`))
		return
	}
	fromImage := fromImages[0]
	tag := tags[0]

	var ref name.Reference
	var err error

	if strings.HasPrefix(tag, "sha256:") {
		ref, err = name.NewDigest(fromImage + "@" + tag)
	} else {
		ref, err = name.NewTag(fromImage + ":" + tag)
	}
	if err != nil {
		respondError(err)
		return
	}

	var opts []remote.Option

	a := &authn.Basic{
		Username: h.regUname,
		Password: h.regPwd,
	}

	dec := json.NewDecoder(base64.NewDecoder(base64.StdEncoding,
		strings.NewReader(r.Header.Get("X-Registry-Auth"))))
	err = dec.Decode(&a)
	if err != nil {
		respondError(err)
		return
	}

	if a.Username != "" {
		opts = append(opts, remote.WithAuth(a))
	}

	opts = append(opts, remote.WithPlatform(v1.Platform{
		Architecture: h.arch,
		OS:           "linux",
	}))

	img, err := remote.Image(ref, opts...)
	if err != nil {
		respondError(err)
		return
	}

	mf, err := img.Manifest()
	if err != nil {
		respondError(err)
		return
	}

	digest := mf.Config.Digest
	tarPath := filepath.Join(h.workDir, fmt.Sprintf("%s.tar", digest))

	updates := make(chan v1.Update)
	writeErr := make(chan error)

	w.WriteHeader(http.StatusOK)

	go func() {
		e := tarball.WriteToFile(tarPath, ref, img, tarball.WithProgress(updates))
		close(updates)
		writeErr <- e
	}()

	enc := json.NewEncoder(w)

	// We already sent 200, so now we are propagating error now via JSON objects in body.
	respondError = func(err error) {
		logrus.Error(err)
		_ = enc.Encode(&jsonmessage.JSONMessage{
			Status: "Error",
			Error: &jsonmessage.JSONError{
				Code:    500,
				Message: "Error: " + err.Error(),
			},
		})
	}

	for u := range updates {
		if errors.Is(u.Error, io.EOF) {
			break
		}
		if u.Error != nil {
			respondError(u.Error)
			continue
		}
		_ = enc.Encode(&jsonmessage.JSONMessage{
			ID: "Pulling",
			Progress: &jsonmessage.JSONProgress{
				Current: u.Complete,
				Total:   u.Total,
			},
		})
	}
	err = <-writeErr
	if err != nil {
		respondError(err)
		return
	}
	_ = enc.Encode(&jsonmessage.JSONMessage{Status: fmt.Sprintf("Digest: %s", digest)})

	err = h.addTag(ref.String(), mf.Config.Digest.String())
	if err != nil {
		respondError(err)
		return
	}
}

func logQueriesMiddleware(h http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		logrus.Debugf("request: %s %s\n", request.Method, request.URL)
		h.ServeHTTP(writer, request)
	})
}
