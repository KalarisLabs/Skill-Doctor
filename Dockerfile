FROM rust:1.85-alpine as builder

WORKDIR /usr/src/skill-doctor
COPY . .

RUN apk add --no-cache musl-dev
RUN cargo build --release --bin skill-doctor

FROM alpine:latest

# Create a non-root user
RUN addgroup -S skilldoctor && adduser -S skilldoctor -G skilldoctor

WORKDIR /app
COPY --from=builder /usr/src/skill-doctor/target/release/skill-doctor /usr/local/bin/

RUN chmod +x /usr/local/bin/skill-doctor
USER skilldoctor

ENTRYPOINT ["skill-doctor"]
