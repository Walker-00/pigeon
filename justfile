bindir := env_var('HOME') / '.local/bin'

# Build the release binary
build:
    cargo build --release

# Run the test suite
test:
    cargo test --release

# Install the `pigeon` binary to ~/.local/bin (where taloshell's mail client expects it)
install: build
    install -Dm755 target/release/pigeon {{bindir}}/pigeon

# Build, test, then install
all: test install

# Remove build artifacts
clean:
    cargo clean

# Uninstall the binary
uninstall:
    rm -f {{bindir}}/pigeon

# Run pigeon directly from the workspace, without installing
run *ARGS:
    cargo run --release -- {{ARGS}}
