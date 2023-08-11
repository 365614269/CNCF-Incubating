package services

import (
	// stdlib
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	// third party
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	metadata "google.golang.org/grpc/metadata"
	status "google.golang.org/grpc/status"

	// first party (protobuf)
	pb "github.com/emissary-ingress/emissary/v3/pkg/api/kat"

	// first party
	"github.com/datawire/dlib/dgroup"
	"github.com/datawire/dlib/dhttp"
	"github.com/datawire/dlib/dlog"
)

// GRPC server object (all fields are required).
type GRPC struct {
	Port          int16
	Backend       string
	SecurePort    int16
	SecureBackend string
	Cert          string
	Key           string

	pb.UnsafeEchoServiceServer
}

// DefaultOpts sets gRPC service options.
func DefaultOpts() []grpc.ServerOption {
	return []grpc.ServerOption{
		grpc.MaxRecvMsgSize(1024 * 1024 * 5),
		grpc.MaxSendMsgSize(1024 * 1024 * 5),
	}
}

// Start initializes the gRPC server.
func (g *GRPC) Start(ctx context.Context) <-chan bool {
	dlog.Printf(ctx, "GRPC: %s listening on %d/%d", g.Backend, g.Port, g.SecurePort)

	grpcHandler := grpc.NewServer(DefaultOpts()...)
	pb.RegisterEchoServiceServer(grpcHandler, g)

	cer, err := tls.LoadX509KeyPair(g.Cert, g.Key)
	if err != nil {
		dlog.Error(ctx, err)
		panic(err) // TODO: do something better
	}

	sc := &dhttp.ServerConfig{
		Handler: grpcHandler,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cer},
		},
	}

	grp := dgroup.NewGroup(ctx, dgroup.GroupConfig{})
	grp.Go("cleartext", func(ctx context.Context) error {
		return sc.ListenAndServe(ctx, fmt.Sprintf(":%v", g.Port))
	})
	grp.Go("tls", func(ctx context.Context) error {
		return sc.ListenAndServeTLS(ctx, fmt.Sprintf(":%v", g.SecurePort), "", "")
	})

	dlog.Print(ctx, "starting gRPC echo service")

	exited := make(chan bool)
	go func() {
		if err := grp.Wait(); err != nil {
			dlog.Error(ctx, err)
			panic(err) // TODO: do something better
		}
		close(exited)
	}()
	return exited
}

// Echo returns the an object with the HTTP context of the request.
func (g *GRPC) Echo(ctx context.Context, r *pb.EchoRequest) (*pb.EchoResponse, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, status.Error(codes.Code(13), "request has not valid context metadata")
	}

	buf := bytes.Buffer{}
	buf.WriteString("metadata received: \n")
	for k, v := range md {
		buf.WriteString(fmt.Sprintf("%v : %s\n", k, strings.Join(v, ",")))
	}
	dlog.Println(ctx, buf.String())

	request := &pb.Request{
		Headers: make(map[string]string),
	}

	response := &pb.Response{
		Headers: make(map[string]string),
	}

	// Sets request headers.
	for k, v := range md {
		request.Headers[k] = strings.Join(v, ",")
		response.Headers[k] = strings.Join(v, ",")
	}

	// Set default backend and assume we're the clear side of the world.
	backend := g.Backend

	// Checks scheme and set TLS info.
	if len(md["x-forwarded-proto"]) > 0 && md["x-forwarded-proto"][0] == "https" {
		// We're the secure side of the world, I guess.
		backend = g.SecureBackend
		request.Tls = &pb.TLS{
			Enabled: true,
		}
	}

	// Check header and delay response.
	if h, ok := md["kat-req-echo-requested-backend-delay"]; ok {
		if v, err := strconv.Atoi(h[0]); err == nil {
			dlog.Printf(ctx, "Delaying response by %v ms", v)
			time.Sleep(time.Duration(v) * time.Millisecond)
		}
	}

	// Set response date header.
	response.Headers["date"] = time.Now().Format(time.RFC1123)

	// Sets client requested metadata.
	for _, v := range md["kat-req-echo-requested-headers"] {
		if len(md[v]) > 0 {
			s := strings.Join(md[v], ",")
			response.Headers[v] = s
			p := metadata.Pairs(v, s)
			if err := grpc.SendHeader(ctx, p); err != nil {
				return nil, err
			}
		}
	}

	// Sets grpc response.
	echoRES := &pb.EchoResponse{
		Backend:  backend,
		Request:  request,
		Response: response,
	}

	// Set a log message.
	if data, err := json.MarshalIndent(echoRES, "", "  "); err == nil {
		dlog.Printf(ctx, "setting response: %s\n", string(data))
	}

	// Checks if kat-req-echo-requested-status is a valid and not OK gRPC status.
	if len(md["kat-req-echo-requested-status"]) > 0 {
		val, err := strconv.Atoi(md["kat-req-echo-requested-status"][0])
		if err == nil {
			if val < 18 || val > 0 {
				// Return response and the not OK status.
				return echoRES, status.Error(codes.Code(val), "kat-req-echo-requested-status")
			}
		}
	}

	// Returns response and the OK status.
	return echoRES, nil
}
