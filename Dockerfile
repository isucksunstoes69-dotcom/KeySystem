# MC License Server - runs on a JDK (needed for jar injection).
# Data (SQLite db + uploaded jars) lives on a mounted volume at /data.
FROM eclipse-temurin:21-jdk

WORKDIR /app

# dependency jars (sqlite-jdbc + slf4j), sources, and the dashboards
COPY lib/ lib/
COPY src/ src/
COPY web/ web/

# compile once at build time
RUN javac -cp "lib/*" -d out $(find src -name '*.java')

# defaults; secrets (keys, admin token) come from runtime env vars
ENV LICENSE_DB=/data/license.db \
    LICENSE_DOWNLOADS_DIR=/data/downloads \
    LICENSE_WEB_DIR=/app/web \
    LICENSE_CLIENT_SRC=/app/src/dev/license \
    LICENSE_PORT=8080

VOLUME ["/data"]
EXPOSE 8080

# NOTE: Linux classpath separator is ':'
CMD ["sh", "-c", "java -cp \"out:lib/*\" dev.license.LicenseServer"]
