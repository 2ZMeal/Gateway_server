# 1. 빌드 스테이지
FROM eclipse-temurin:21-jdk AS builder
WORKDIR /app

# 빌드에 필요한 파일 복사
COPY gradlew .
COPY gradle gradle
COPY build.gradle .
COPY settings.gradle .
COPY src src

# 권한 부여 및 빌드
RUN sed -i 's/\r$//' ./gradlew && chmod +x ./gradlew
RUN ./gradlew bootJar -x test --no-daemon

# 2. 실행 스테이지
FROM eclipse-temurin:21-jre
WORKDIR /app

COPY --from=builder /app/build/libs/*.jar app.jar

ENTRYPOINT ["java", "-jar", "app.jar"]
