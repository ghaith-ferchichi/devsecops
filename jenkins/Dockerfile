FROM jenkins/jenkins:lts-jdk17

USER root
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && curl -fsSL https://get.docker.com | sh \
    && apt-get clean && rm -rf /var/lib/apt/lists/*
RUN usermod -aG docker jenkins
USER jenkins

RUN jenkins-plugin-cli --plugins \
    git \
    workflow-aggregator \
    docker-workflow \
    github \
    configuration-as-code \
    blueocean \
    slack
