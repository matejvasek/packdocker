package cmd

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/matejvasek/packdocker"
)

func NewRootCmd() *cobra.Command {
	var socket string
	var outDir string
	var uname string
	var pwd string
	var arch string
	var verbose bool

	cmd := &cobra.Command{
		Long: `Runs subset of Docker API needed for building buildpack/builder images.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if verbose {
				logrus.SetLevel(logrus.TraceLevel)
			}
			err := serve(cmd.Context(), socket, outDir, arch, uname, pwd)
			if strings.Contains(err.Error(), "Server closed") {
				return nil
			}
			return err
		},
	}

	cmd.Flags().StringVarP(&socket, "socket", "s", "", "Path where socket will be created and served.")
	cmd.Flags().StringVarP(&outDir, "out", "o", "", "Path well output image tarballs will be stored.")
	_ = cmd.MarkFlagRequired("socket")
	_ = cmd.MarkFlagRequired("out")
	cmd.Flags().StringVarP(&arch, "arch", "a", runtime.GOARCH, "Architecture to build for.")
	cmd.Flags().StringVarP(&uname, "user", "u", "", "Registry username.")
	cmd.Flags().StringVarP(&pwd, "password", "p", "", "Registry password.")
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output.")

	return cmd
}

func serve(ctx context.Context, socket, outDir, arch, regUname, regPwd string) error {
	var err error

	fi, err := os.Stat(socket)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("cannot stat the socket file: %w", err)
	}
	if fi != nil && (fi.Mode()&os.ModeSocket) != 0 {
		os.Remove(socket)
	}

	listener, err := net.Listen("unix", socket)
	if err != nil {
		return fmt.Errorf("cannot set up listener: %w", err)
	}
	defer os.Remove(socket)

	server := http.Server{
		Handler: packdocker.NewAPIHandler(outDir, arch, regUname, regPwd),
	}

	go func() {
		<-ctx.Done()
		c, cf := context.WithTimeout(context.Background(), time.Second*5)
		defer cf()
		_ = server.Shutdown(c)
	}()

	return server.Serve(listener)
}
