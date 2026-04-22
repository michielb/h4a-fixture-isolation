# Multi-stage build of the h4a isolation probe fixture (MB-451).
# Stage 1: build a static Go binary. Stage 2: scratch + non-root USER so the
# caps.setuid_zero probe is meaningful (the container runs as UID 1000; a
# successful setuid(0) would indicate a CAP_SETUID leak).
#
# Build context is this directory; no other files are needed.

FROM golang:1.25-alpine AS build
WORKDIR /src
COPY main.go ./
# We never take dependencies (stdlib only) so go.mod is a single line.
RUN printf 'module h4a-probe\n\ngo 1.25\n' > go.mod
ENV CGO_ENABLED=0 GOOS=linux GOARCH=amd64
RUN go build -trimpath -ldflags "-s -w" -o /out/h4a-probe .

FROM scratch
COPY --from=build /out/h4a-probe /h4a-probe
# Non-root so caps.setuid_zero actually exercises the kernel. 1000 matches
# the platform-wide "nobody-ish" convention.
USER 1000:1000
EXPOSE 8080
ENTRYPOINT ["/h4a-probe"]
