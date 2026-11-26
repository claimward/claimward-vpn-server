package grpcsrv

import (
	"context"
	"errors"
	"testing"

	"github.com/claimward/claimward-vpn-client/pkg/protocol"
	"github.com/claimward/claimward-vpn-server/internal/auth"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// recorder is an Authenticator that remembers which provider it was asked
// about, and refuses every token when fail is set.
type recorder struct {
	provider string
	fail     bool
}

func (r *recorder) Verify(_ context.Context, provider, _ string) (*auth.Claims, error) {
	r.provider = provider
	if r.fail {
		return nil, errors.New("no")
	}
	return &auth.Claims{Provider: provider, Subject: "s"}, nil
}

type ctxStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s ctxStream) Context() context.Context { return s.ctx }

// run drives the interceptor with the given metadata pairs and reports whether
// the handler ran, and the error.
func run(t *testing.T, a auth.Authenticator, md metadata.MD) (ran bool, err error) {
	t.Helper()
	ctx := metadata.NewIncomingContext(context.Background(), md)
	defer func() {
		if p := recover(); p != nil {
			t.Errorf("the interceptor crashed instead of answering: %v", p)
			err = status.Error(codes.Internal, "crashed")
		}
	}()
	err = AuthStreamInterceptor(a)(nil, ctxStream{ctx: ctx}, nil, func(any, grpc.ServerStream) error {
		ran = true
		return nil
	})
	return ran, err
}

// ⛔ The stream names its provider in metadata; the token is judged by that
// provider alone, and a missing or ambiguous name reaches the verifier as "".
func TestTheStreamNamesItsProvider(t *testing.T) {
	cases := []struct {
		name string
		md   metadata.MD
		want string
	}{
		{"one", metadata.Pairs("authorization", "Bearer t", protocol.MetadataProvider, "campus"), "campus"},
		{"none", metadata.Pairs("authorization", "Bearer t"), ""},
		{"two", metadata.Pairs("authorization", "Bearer t", protocol.MetadataProvider, "a", protocol.MetadataProvider, "b"), ""},
	}
	for _, c := range cases {
		a := &recorder{provider: "unset"}
		ran, err := run(t, a, c.md)
		if err != nil || !ran {
			t.Errorf("%s: ran=%v err=%v", c.name, ran, err)
		}
		if a.provider != c.want {
			t.Errorf("%s: the verifier was asked about %q, want %q", c.name, a.provider, c.want)
		}
	}
}

func TestAFailedTokenNeverReachesTheHandler(t *testing.T) {
	ran, err := run(t, &recorder{fail: true}, metadata.Pairs("authorization", "Bearer t", protocol.MetadataProvider, "campus"))
	if ran || status.Code(err) != codes.Unauthenticated {
		t.Errorf("ran=%v err=%v, want the handler skipped and Unauthenticated", ran, err)
	}
}

func TestAStreamWithNoMetadataAtAllIsRefused(t *testing.T) {
	a := &recorder{}
	var ran bool
	err := AuthStreamInterceptor(a)(nil, ctxStream{ctx: context.Background()}, nil, func(any, grpc.ServerStream) error {
		ran = true
		return nil
	})
	if ran || status.Code(err) != codes.Unauthenticated {
		t.Errorf("ran=%v err=%v", ran, err)
	}
	if got := providerFromContext(context.Background()); got != "" {
		t.Errorf("no metadata named provider %q", got)
	}
}
