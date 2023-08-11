package services

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/datawire/dlib/dhttp"
	"github.com/datawire/dlib/dlog"
	"github.com/emissary-ingress/emissary/v3/pkg/api/agent"
)

type GRPCAgent struct {
	Port int16
}

func (a *GRPCAgent) Start(ctx context.Context) <-chan bool {
	wg := &sync.WaitGroup{}
	var opts []grpc.ServerOption
	if sizeStr := os.Getenv("KAT_GRPC_MAX_RECV_MSG_SIZE"); sizeStr != "" {
		size, err := strconv.Atoi(sizeStr)
		if err == nil {
			dlog.Printf(ctx, "setting gRPC MaxRecvMsgSize to %d bytes", size)
			opts = append(opts, grpc.MaxRecvMsgSize(size))
		}
	}
	grpcHandler := grpc.NewServer(opts...)
	dir := &director{}
	agent.RegisterDirectorServer(grpcHandler, dir)
	sc := &dhttp.ServerConfig{
		Handler: grpcHandler,
	}
	grpcErrChan := make(chan error)
	httpErrChan := make(chan error)
	ctx, cancel := context.WithCancel(ctx)

	wg.Add(2)
	go func() {
		defer wg.Done()
		dlog.Print(ctx, "starting GRPC agentcom...")
		if err := sc.ListenAndServe(ctx, fmt.Sprintf(":%d", a.Port)); err != nil {
			select {
			case grpcErrChan <- err:
			default:
			}
		}
	}()
	srv := &http.Server{Addr: ":3001"}

	http.HandleFunc("/lastSnapshot", func(w http.ResponseWriter, r *http.Request) {
		lastSnap := dir.GetLastSnapshot()
		if lastSnap == nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		ret, err := json.Marshal(lastSnap)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(ret)
	})

	go func() {
		defer wg.Done()

		dlog.Print(ctx, "Starting http server")
		if err := srv.ListenAndServe(); err != http.ErrServerClosed {
			select {
			case httpErrChan <- err:
			default:
			}
		}
	}()

	exited := make(chan bool)
	go func() {

		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt, syscall.SIGTERM)

		select {
		case err := <-grpcErrChan:
			dlog.Errorf(ctx, "GRPC service died: %+v", err)
			panic(err) // TODO: do something better
		case err := <-httpErrChan:
			dlog.Errorf(ctx, "http service died: %+v", err)
			panic(err) // TODO: do something better
		case <-c:
			dlog.Print(ctx, "Received shutdown")
		}

		ctx, timeout := context.WithTimeout(ctx, time.Second*30)
		defer timeout()
		cancel()

		grpcHandler.GracefulStop()
		_ = srv.Shutdown(ctx)
		wg.Wait()
		close(exited)
	}()
	return exited
}

type director struct {
	agent.UnimplementedDirectorServer
	lastSnapshot *agent.Snapshot
}

func (d *director) GetLastSnapshot() *agent.Snapshot {
	return d.lastSnapshot
}

// Report is invoked when a new report with a snapshot arrives
func (d *director) Report(ctx context.Context, snapshot *agent.Snapshot) (*agent.SnapshotResponse, error) {
	err := checkContext(ctx)
	if err != nil {
		return nil, err
	}

	dlog.Print(ctx, "Received snapshot")

	err = writeSnapshot(snapshot)
	if err != nil {
		return nil, err
	}

	d.lastSnapshot = snapshot
	return &agent.SnapshotResponse{}, nil
}

func (d *director) Retrieve(agentID *agent.Identity, stream agent.Director_RetrieveServer) error {
	return nil
}

func checkContext(ctx context.Context) error {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		dlog.Print(ctx, "No metadata found, not allowing request")
		err := status.Error(codes.PermissionDenied, "Missing grpc metadata")

		return err
	}

	apiKeyValues := md.Get("x-ambassador-api-key")
	if len(apiKeyValues) == 0 || apiKeyValues[0] == "" {
		dlog.Print(ctx, "api key found, not allowing request")
		err := status.Error(codes.PermissionDenied, "Missing api key")
		return err
	}
	return nil
}

func writeSnapshot(snapshot *agent.Snapshot) error {
	snapBytes, err := json.Marshal(snapshot)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile("/tmp/snapshot.json", snapBytes, 0644)
	if err != nil {
		return err
	}
	return nil
}

func (d *director) ReportStream(server agent.Director_ReportStreamServer) error {
	err := checkContext(server.Context())
	if err != nil {
		return err
	}

	var data []byte
	for {
		msg, err := server.Recv()
		data = append(data, msg.GetChunk()...)
		if err != nil {
			if err == io.EOF {
				break
			} else {
				return err
			}
		}
	}

	var snapshot agent.Snapshot
	err = json.Unmarshal(data, &snapshot)
	if err != nil {
		return err
	}

	dlog.Print(server.Context(), "Received snapshot")

	err = writeSnapshot(&snapshot)
	if err != nil {
		return err
	}

	response := &agent.SnapshotResponse{}
	err = server.SendMsg(response)
	return err
}
