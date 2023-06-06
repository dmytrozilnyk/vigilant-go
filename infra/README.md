docker exec kafka-broker kafka-topics --bootstrap-server kafka-broker:9092 --create --topic fluentbit-logs

docker exec --interactive --tty dockers-kafka-broker-3-1 kafka-console-consumer --bootstrap-server dockers-kafka-broker-3-1:9092 --topic filebeat-logs --from-beginning