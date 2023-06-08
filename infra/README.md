**1. Start up zookeeper container**
```bash
docker-compose -f common.yml -f ./zookeeper/zookeeper.yml up -d
```

***Check if Zookeeper is ready***
```bash
echo ruok | nc localhost 2181
```

**2. Start up kafka container**
```bash
docker-compose -f common.yml -f ./kafka/kafka_cluster.yml up -d
```

**3. Init kafka topics (Only once)**
```bash
docker-compose -f common.yml -f ./init_kafka.yml up
```

**4. Start up fluent bit container**
```bash
docker-compose -f ./common.yml -f ./fluent-bit/fluent_bit.yml up -d
```

**5. Start up filebeat container**
```bash
docker-compose -f ./common.yml -f ./filebeat/filebeat-docker.yml up -d
```

**6. Start up packetbeat container**
```bash
docker-compose -f ./common.yml -f ./packetbeat/packetbeat-docker.yml up -d
```

**7. Start up logstash container**
```bash
docker-compose -f ./common.yml -f ./elk/elk-docker.yml up -d
```

**8. View the messages in the queue**
```bash
docker exec --interactive --tty infra-kafka-broker-3-1 kafka-console-consumer --bootstrap-server infra-kafka-broker-3-1:9092 --topic filebeat-logs --from-beginning
```

***Create a topic if necessary***
```bash
docker exec infra-kafka-broker-3-1 kafka-topics --bootstrap-server infra-kafka-broker-3-1:9092 --create --topic fluentbit-logs
```