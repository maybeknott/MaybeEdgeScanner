FROM cimg/android:2024.01.1-ndk

USER root

ARG GO_VERSION=1.24.12
ARG GRADLE_VERSION=8.14.2

ENV ANDROID_HOME=/opt/android/sdk \
    GRADLE_USER_HOME=/opt/gradle-cache \
    GOMODCACHE=/opt/go/pkg/mod \
    GOCACHE=/opt/go-build \
    PATH=/usr/local/go/bin:/opt/gradle/bin:${PATH}

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl git tar unzip \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" \
    | tar -C /usr/local -xz

RUN curl -fsSL "https://services.gradle.org/distributions/gradle-${GRADLE_VERSION}-bin.zip" -o /tmp/gradle.zip \
    && unzip -q /tmp/gradle.zip -d /opt \
    && ln -s "/opt/gradle-${GRADLE_VERSION}" /opt/gradle \
    && rm /tmp/gradle.zip

WORKDIR /workspace

COPY go-sidecar/go.mod go-sidecar/go.sum ./go-sidecar/
RUN cd go-sidecar \
    && go mod download

COPY settings.gradle build.gradle ./
COPY gradle.properties ./
COPY app/build.gradle ./app/build.gradle
RUN mkdir -p app/src/main \
    && gradle --no-daemon --refresh-dependencies :app:dependencies

COPY go-sidecar ./go-sidecar
RUN cd go-sidecar \
    && go mod tidy \
    && go mod download all \
    && go test ./...

LABEL org.opencontainers.image.title="MaybeEdgeScanner dependency cache" \
      org.opencontainers.image.description="Android Gradle and Go module dependencies warmed for MaybeEdgeScanner CI builds"
