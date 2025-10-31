# Build stage
FROM maven:3-eclipse-temurin-21 AS build
WORKDIR /app
COPY . .
RUN mvn clean package -DskipTests

# Run stage
FROM openjdk:21-jdk-slim
WORKDIR /app
COPY --from=build /app/target/backdend-0.0.1-SNAPSHOT.war backdend.war
EXPOSE 8080
ENTRYPOINT ["java","-jar","backdend.war"]
