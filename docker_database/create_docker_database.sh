#!/bin/bash
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
# Create MySQL container
mysql_container_id=$(docker run -d -v "$DIR"/explicit_defaults_for_timestamp.cnf:/etc/mysql/mysql.conf.d/explicit_defaults_for_timestamp.cnf -e MYSQL_ROOT_PASSWORD=my-secret-pw mysql:5.7.19)
sleep 30

# Create databases and their users
cat "$DIR"/root.mysql.sql | docker exec -i $mysql_container_id mysql -u root --password=my-secret-pw

# Create app and strongswan databases
cat "$DIR"/app.mysql.sql | docker exec -i $mysql_container_id mysql -u test1 --password=testing test1
cat "$DIR"/ipsec.mysql.sql | docker exec -i $mysql_container_id mysql -u testipsecuser --password=testing testipsecdb

# Connect to MySQL environment
docker exec -it $mysql_container_id mysql -uroot -pmy-secret-pw


