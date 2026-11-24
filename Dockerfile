# claimward-server image: a static binary on distroless, running as uid 65532.
#
# The binary carries the FILE CAPABILITY cap_net_admin=+ep. A non-root uid has
# no ambient capabilities, and a container runtime's `add: [NET_ADMIN]` only
# fills the bounding and permitted sets, so without the file capability the
# first netlink call (wgctrl, nftables, interface MTU) fails with EPERM.
#
# The final stage cannot run setcap (distroless has no shell), so the
# capability is set in the build stage and the file is copied with its
# extended attributes: CI reads security.capability back from the FINAL image.
FROM --platform=$BUILDPLATFORM golang:1.27.4 AS build
ARG TARGETOS=linux
ARG TARGETARCH
RUN apt-get update \
 && apt-get install -y --no-install-recommends libcap2-bin \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags='-s -w' -o /out/claimward-server ./cmd/claimward-server
RUN setcap cap_net_admin=+ep /out/claimward-server \
 && getcap /out/claimward-server

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/claimward-server /claimward-server
USER 65532:65532
ENTRYPOINT ["/claimward-server"]
