# Build stage
FROM golang:1.22-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /app

# Copy go mod files first for caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build binary
ARG VERSION=dev
ARG COMMIT=unknown
ARG DATE=unknown
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w -X github.com/rootsploit/reconator/internal/version.Version=${VERSION} \
    -X github.com/rootsploit/reconator/internal/version.Commit=${COMMIT} \
    -X github.com/rootsploit/reconator/internal/version.Date=${DATE}" \
    -o reconator ./cmd/reconator

# Runtime stage
FROM alpine:3.20

# Install runtime dependencies and Go for installing tools
RUN apk add --no-cache \
    ca-certificates \
    chromium \
    nmap \
    git \
    libpcap \
    && rm -rf /var/cache/apk/*

# Install Go tools to /usr/local/bin
ENV GOBIN=/usr/local/bin
RUN apk add --no-cache go && \
    go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest && \
    go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest && \
    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install github.com/tomnomnom/waybackurls@latest && \
    go install github.com/lc/gau/v2/cmd/gau@latest && \
    go install github.com/sensepost/gowitness@latest && \
    go install github.com/d3mondev/puredns/v2@latest && \
    apk del go && \
    rm -rf /root/go /root/.cache

# Set up non-root user
RUN adduser -D -u 1000 reconator && \
    mkdir -p /home/reconator/.config /home/reconator/wordlists && \
    chown -R reconator:reconator /home/reconator

# Copy binary from builder
COPY --from=builder /app/reconator /usr/local/bin/reconator

# Copy wordlists if they exist
COPY --from=builder /app/wordlists/ /home/reconator/wordlists/

# Switch to non-root user
USER reconator
WORKDIR /home/reconator

# Download nuclei templates
RUN nuclei -update-templates 2>/dev/null || true

# Environment
ENV CHROMIUM_BIN="/usr/bin/chromium"

ENTRYPOINT ["reconator"]
CMD ["--help"]
