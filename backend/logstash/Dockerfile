FROM docker.elastic.co/logstash/logstash:8.13.0

# Ensure the HTTP output plugin is present (included by default in 8.x)
RUN /usr/share/logstash/bin/logstash-plugin list | grep -q logstash-output-http \
    || /usr/share/logstash/bin/logstash-plugin install logstash-output-http

# Remove default pipeline placeholder
RUN rm -f /usr/share/logstash/pipeline/logstash.conf

# Our pipeline is mounted via docker-compose volume — this COPY is a fallback
COPY pipeline/logstash.conf /usr/share/logstash/pipeline/logstash.conf

ENV LS_JAVA_OPTS="-Xmx512m -Xms256m"
