# Chaos smoke set

5 passed, 1 failed.

| Scenario | Result | Seconds | Summary |
|---|---|---:|---|
| spoof | pass | 0 | 4 port-forward probes; forged identity headers never reached kubesentry |
| oversize | pass | 1 | 413/413/413/415 expected; got map[25,000 processes:413 9 MiB body:413 gzip bomb (64 MiB inflated):413 unsupported encoding:415] |
| prometheus | pass | 34 | served throughout (/oom 200 with warning while down); metrics back 21s after Prometheus restarted |
| postgres | pass | 247 | 240000 accepted (229905 distinct); 72 backpressure answers; stored 229905, missing 0, duplicated 0 |
| apiserver | pass | 18 | API server down 7s; kubesentry answered 5/5 probes, max snapshot age 5s, fresh again 0s later |
| killreplica | FAIL: the standby did not take the CloudWatch lock within 3 minutes | 422 | lock moved in -1s; agents on the survivor 6→6, 6 fresh after; web errors during the kill 0 |

## spoof

Numbers: map[sidecarForgedNoToken:200]

- +0s port 8080 HTTP 0 <nil>
- +0s port 4180 forged headers, no token HTTP 401
- +0s port 4180 forged headers + nobody's token HTTP 200 user "nobody@corp.example" groups [system:authenticated] caps map[agents:false audit:false clusterAudit:false clusterIssuers:false clusterRBAC:false nodes:false processes:false pvs:false storageClasses:false]
- +0s port 8081 /api/v1/pods with forged headers HTTP 404
- +0s port 9090 /api/v1/pods with forged headers HTTP 404

## oversize

Numbers: map[25,000 processes:413 9 MiB body:413 gzip bomb (64 MiB inflated):413 unsupported encoding:415]

- +0s 9 MiB body 9570380 bytes sent: HTTP 413 {"error":"report too large: at most 8 MiB and 20000 processes"}
- +0s 25,000 processes 4066080 bytes sent: HTTP 413 {"error":"report too large: at most 8 MiB and 20000 processes"}
- +1s gzip bomb (64 MiB inflated) 65132 bytes sent: HTTP 413 {"error":"report too large: at most 8 MiB and 20000 processes"}
- +1s unsupported encoding 36 bytes sent: HTTP 415 {"error":"unsupported content encoding: send plain or gzip JSON"}

## prometheus

Numbers: map[oomWhileDown:200 recoverySeconds:20.539401961]

- +0s Prometheus scaled to 0 
- +2s Prometheus pod gone 
- +12s /oom?window=1h while down HTTP 200 metricsAvailable=false warnings=[leak detection unavailable: could not query Prometheus]
- +12s /oom?window=24h while down HTTP 200
- +13s /info while down HTTP 200 
- +13s kubesentry-5897598d7f-5lbw9 /readyz while down 200 {"status":"ready"}

- +13s kubesentry-5897598d7f-ds9x7 /readyz while down 200 {"status":"ready"}

- +13s Prometheus scaled to 1 
- +34s metrics back true after 21s

## postgres

Numbers: map[accepted:240000 backpressure503:72 distinctAccepted:229905 downSeconds:120 duplicated:0 events:240000 failedBatches:0 found:229905 gaveUpBatches:0 maxQueueDepth:50000 missing:0 retriedBatches:7]

- +0s firehose started 240000 events at 1000/s through a port-forward to the ingest Service
- +45s Postgres scaled to 0 
- +46s kubesentry-5897598d7f-5lbw9 /readyz 200 {"status":"ready","degraded":{"postgres":"failed to connect to `user=kubesentry database=kubesentry`: 10.96.192.246:5432 (postgres.stress-pg.svc.cluster.local): server error: FATAL: the database system is shutting down (SQLSTATE 57P03)"}}

- +46s kubesentry-5897598d7f-ds9x7 /readyz 200 {"status":"ready","degraded":{"postgres":"failed to connect to `user=kubesentry database=kubesentry`: 10.96.192.246:5432 (postgres.stress-pg.svc.cluster.local): server error: FATAL: the database system is shutting down (SQLSTATE 57P03)"}}

- +56s kubesentry-5897598d7f-5lbw9 /readyz 200 {"status":"ready","degraded":{"postgres":"failed to connect to `user=kubesentry database=kubesentry`: 10.96.192.246:5432 (postgres.stress-pg.svc.cluster.local): dial error: dial tcp 10.96.192.246:5432: connect: connection refused"}}

- +56s kubesentry-5897598d7f-ds9x7 /readyz 200 {"status":"ready","degraded":{"postgres":"failed to connect to `user=kubesentry database=kubesentry`: 10.96.192.246:5432 (postgres.stress-pg.svc.cluster.local): dial error: dial tcp 10.96.192.246:5432: connect: connection refused"}}

- +66s kubesentry-5897598d7f-5lbw9 /readyz 200 {"status":"ready","degraded":{"postgres":"failed to connect to `user=kubesentry database=kubesentry`: 10.96.192.246:5432 (postgres.stress-pg.svc.cluster.local): dial error: dial tcp 10.96.192.246:5432: connect: connection refused"}}

- +67s kubesentry-5897598d7f-ds9x7 /readyz 200 {"status":"ready","degraded":{"postgres":"failed to connect to `user=kubesentry database=kubesentry`: 10.96.192.246:5432 (postgres.stress-pg.svc.cluster.local): dial error: dial tcp 10.96.192.246:5432: connect: connection refused"}}

- +77s kubesentry-5897598d7f-5lbw9 /readyz 200 {"status":"ready","degraded":{"postgres":"failed to connect to `user=kubesentry database=kubesentry`: 10.96.192.246:5432 (postgres.stress-pg.svc.cluster.local): dial error: dial tcp 10.96.192.246:5432: connect: connection refused"}}

- +77s kubesentry-5897598d7f-ds9x7 /readyz 200 {"status":"ready","degraded":{"postgres":"failed to connect to `user=kubesentry database=kubesentry`: 10.96.192.246:5432 (postgres.stress-pg.svc.cluster.local): dial error: dial tcp 10.96.192.246:5432: connect: connection refused"}}

- +87s kubesentry-5897598d7f-5lbw9 /readyz 200 {"status":"ready","degraded":{"postgres":"failed to connect to `user=kubesentry database=kubesentry`: 10.96.192.246:5432 (postgres.stress-pg.svc.cluster.local): dial error: dial tcp 10.96.192.246:5432: connect: connection refused"}}

- +87s kubesentry-5897598d7f-ds9x7 /readyz 200 {"status":"ready","degraded":{"postgres":"failed to connect to `user=kubesentry database=kubesentry`: 10.96.192.246:5432 (postgres.stress-pg.svc.cluster.local): dial error: dial tcp 10.96.192.246:5432: connect: connection refused"}}

- +98s kubesentry-5897598d7f-5lbw9 /readyz 200 {"status":"ready","degraded":{"postgres":"failed to connect to `user=kubesentry database=kubesentry`: 10.96.192.246:5432 (postgres.stress-pg.svc.cluster.local): dial error: dial tcp 10.96.192.246:5432: connect: connection refused"}}

- +98s kubesentry-5897598d7f-ds9x7 /readyz 200 {"status":"ready","degraded":{"postgres":"failed to connect to `user=kubesentry database=kubesentry`: 10.96.192.246:5432 (postgres.stress-pg.svc.cluster.local): dial error: dial tcp 10.96.192.246:5432: connect: connection refused"}}

- +108s kubesentry-5897598d7f-5lbw9 /readyz 200 {"status":"ready","degraded":{"postgres":"failed to connect to `user=kubesentry database=kubesentry`: 10.96.192.246:5432 (postgres.stress-pg.svc.cluster.local): dial error: dial tcp 10.96.192.246:5432: connect: connection refused"}}

- +108s kubesentry-5897598d7f-ds9x7 /readyz 200 {"status":"ready","degraded":{"postgres":"failed to connect to `user=kubesentry database=kubesentry`: 10.96.192.246:5432 (postgres.stress-pg.svc.cluster.local): dial error: dial tcp 10.96.192.246:5432: connect: connection refused"}}

- +118s kubesentry-5897598d7f-5lbw9 /readyz 200 {"status":"ready","degraded":{"postgres":"failed to connect to `user=kubesentry database=kubesentry`: 10.96.192.246:5432 (postgres.stress-pg.svc.cluster.local): dial error: dial tcp 10.96.192.246:5432: connect: connection refused"}}

- +119s kubesentry-5897598d7f-ds9x7 /readyz 200 {"status":"ready","degraded":{"postgres":"failed to connect to `user=kubesentry database=kubesentry`: 10.96.192.246:5432 (postgres.stress-pg.svc.cluster.local): dial error: dial tcp 10.96.192.246:5432: connect: connection refused"}}

- +129s kubesentry-5897598d7f-5lbw9 /readyz 200 {"status":"ready","degraded":{"postgres":"failed to connect to `user=kubesentry database=kubesentry`: 10.96.192.246:5432 (postgres.stress-pg.svc.cluster.local): dial error: dial tcp 10.96.192.246:5432: connect: connection refused"}}

- +129s kubesentry-5897598d7f-ds9x7 /readyz 200 {"status":"ready","degraded":{"postgres":"failed to connect to `user=kubesentry database=kubesentry`: 10.96.192.246:5432 (postgres.stress-pg.svc.cluster.local): dial error: dial tcp 10.96.192.246:5432: connect: connection refused"}}

- +140s kubesentry-5897598d7f-5lbw9 /readyz 200 {"status":"ready","degraded":{"postgres":"failed to connect to `user=kubesentry database=kubesentry`: 10.96.192.246:5432 (postgres.stress-pg.svc.cluster.local): dial error: dial tcp 10.96.192.246:5432: connect: connection refused"}}

- +140s kubesentry-5897598d7f-ds9x7 /readyz 200 {"status":"ready","degraded":{"postgres":"failed to connect to `user=kubesentry database=kubesentry`: 10.96.192.246:5432 (postgres.stress-pg.svc.cluster.local): dial error: dial tcp 10.96.192.246:5432: connect: connection refused"}}

- +150s kubesentry-5897598d7f-5lbw9 /readyz 200 {"status":"ready","degraded":{"postgres":"failed to connect to `user=kubesentry database=kubesentry`: 10.96.192.246:5432 (postgres.stress-pg.svc.cluster.local): dial error: dial tcp 10.96.192.246:5432: connect: connection refused"}}

- +150s kubesentry-5897598d7f-ds9x7 /readyz 200 {"status":"ready","degraded":{"postgres":"failed to connect to `user=kubesentry database=kubesentry`: 10.96.192.246:5432 (postgres.stress-pg.svc.cluster.local): dial error: dial tcp 10.96.192.246:5432: connect: connection refused"}}

- +160s kubesentry-5897598d7f-5lbw9 /readyz 200 {"status":"ready","degraded":{"postgres":"failed to connect to `user=kubesentry database=kubesentry`: 10.96.192.246:5432 (postgres.stress-pg.svc.cluster.local): dial error: dial tcp 10.96.192.246:5432: connect: connection refused"}}

- +161s kubesentry-5897598d7f-ds9x7 /readyz 200 {"status":"ready","degraded":{"postgres":"failed to connect to `user=kubesentry database=kubesentry`: 10.96.192.246:5432 (postgres.stress-pg.svc.cluster.local): dial error: dial tcp 10.96.192.246:5432: connect: connection refused"}}

- +171s Postgres scaled to 1 after 126s; max audit queue depth 50000; replicas reporting postgres degraded: 2
- +240s firehose finished accepted 240000 of 240000, backpressure responses 72, retried batches 7, gave up 0, failed 0

## apiserver

Numbers: map[apiserverDownSeconds:6.5300832159999995 freshSecondsAfterAPIServer:0.167746441 maxSnapshotAgeSeconds:5.1 minReadyReplicas:2 probes:5 probesOK:5 staleReported:false]

- +7s kube-apiserver container stopped 836dd65371d46031e83542f9e273d73a1aa5b5015532c7b5613698e8e285f67a
- +13s API server ready again after 7s
- +18s probes 5/5 answered 200; snapshot age max 5s, stale shown false; ready replicas never below 2

## killreplica

Numbers: map[agentsBefore:6 agentsFreshAfter:6 agentsMinOnSurvivor:6 cloudwatchDuplicated:0 cloudwatchExpected:270082 cloudwatchMissing:0 lockTakeoverSeconds:-1 webErrorsDuringKill:0]

- +0s leader kubesentry-5897598d7f-ds9x7; standby kubesentry-5897598d7f-5lbw9
- +0s deleted the leader 
- +181s agents after HTTP 200, 6 agents, 6 fresh; standby saw at least 6 nodes reporting
- +181s waiting for CloudWatch late deliveries 4m
- +422s CloudWatch events 270082 expected, 270082 found, 0 missing, 0 duplicated
