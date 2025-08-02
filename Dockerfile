# Multi-stage build for Ryzan Wallet
FROM rust:latest as builder

# Install required dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy manifests first for better caching
COPY Cargo.toml Cargo.lock ./

# Copy source code
COPY src ./src

# Build the application
RUN cargo build --release && \
    strip target/release/ryzan

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -u 1001 ryzan

# Copy binary from builder
COPY --from=builder /app/target/release/ryzan /usr/local/bin/ryzan

# Set permissions
RUN chmod +x /usr/local/bin/ryzan

# Switch to non-root user
USER ryzan
WORKDIR /home/ryzan

# Create config directory
RUN mkdir -p .config/ryzan

# Expose no ports (CLI application)
# Set environment
ENV RUST_LOG=info

# Default command
ENTRYPOINT ["ryzan"]
CMD ["--help"]