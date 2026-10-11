CREATE DATABASE IF NOT EXISTS netflow;

CREATE TABLE IF NOT EXISTS netflow.flows
(
    time_received DateTime64(3, 'UTC') DEFAULT now64(3, 'UTC'),
    bytes UInt64,
    packets UInt64,
    src_addr IPv6,
    dst_addr IPv6,
    proto UInt8,
    src_port UInt16,
    dst_port UInt16,
    src_as UInt32,
    dst_as UInt32,
    src_as_org LowCardinality(String),
    dst_as_org LowCardinality(String),
    src_country LowCardinality(String),
    dst_country LowCardinality(String)
)
ENGINE = MergeTree
PARTITION BY toDate(time_received)
ORDER BY (time_received, src_addr, dst_addr, proto);

ALTER TABLE netflow.flows
    ADD COLUMN IF NOT EXISTS src_as_org LowCardinality(String) AFTER dst_as;
ALTER TABLE netflow.flows
    ADD COLUMN IF NOT EXISTS dst_as_org LowCardinality(String) AFTER src_as_org;
