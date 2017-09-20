create database test1;
create user 'test1' identified by 'testing';
grant all privileges on test1.* to 'test1';

create database testipsecdb;
create user 'testipsecuser' identified by 'testing';
grant all privileges on testipsecdb.* to 'testipsecuser';

-- set explicit_defaults_for_timestamp = 1;
