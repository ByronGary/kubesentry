# Chaos smoke set

3 passed, 0 failed.

| Scenario | Result | Seconds | Summary |
|---|---|---:|---|
| spoof | pass | 1 | 4 port-forward probes; forged identity headers never reached kubesentry |
| oversize | pass | 1 | 413/413/413/415 expected; got map[25,000 processes:413 9 MiB body:413 gzip bomb (64 MiB inflated):413 unsupported encoding:415] |
| apiserver | pass | 15 | API server down 4s; kubesentry answered 4/4 probes, max snapshot age 6s, fresh again 0s later |

## spoof

Numbers: map[sidecarForgedHeadersNoToken:401 sidecarForgedHeadersWithNobodysToken:HTTP 200 as nobody@corp.example]

- +0s port 8080 HTTP 0 <nil>
- +0s port 4180 forged headers, no token HTTP 401
- +0s port 4180 forged headers + nobody's token HTTP 200 user "nobody@corp.example" groups [system:authenticated] caps map[agents:false audit:false clusterAudit:false clusterIssuers:false clusterRBAC:false nodes:false processes:false pvs:false storageClasses:false]
- +0s port 8081 /api/v1/pods with forged headers HTTP 404
- +1s port 9090 /api/v1/pods with forged headers HTTP 404

## oversize

Numbers: map[25,000 processes:413 9 MiB body:413 gzip bomb (64 MiB inflated):413 unsupported encoding:415]

- +0s 9 MiB body 9570380 bytes sent: HTTP 413 {"error":"report too large: at most 8 MiB and 20000 processes"}
- +1s 25,000 processes 4066080 bytes sent: HTTP 413 {"error":"report too large: at most 8 MiB and 20000 processes"}
- +1s gzip bomb (64 MiB inflated) 65132 bytes sent: HTTP 413 {"error":"report too large: at most 8 MiB and 20000 processes"}
- +1s unsupported encoding 36 bytes sent: HTTP 415 {"error":"unsupported content encoding: send plain or gzip JSON"}

## apiserver

Numbers: map[apiserverDownSeconds:4.42924213 freshSecondsAfterAPIServer:0.184024793 maxSnapshotAgeSeconds:6.1 minReadyReplicas:2 probes:4 probesOK:4 staleReported:false]

- +7s kube-apiserver container stopped e186457b0dfab68b52c4cfe43476dc17029b5036875fa85a5a3683f05a9f8e66
- +11s API server ready again after 4s
- +15s caution: transient forbidden errors in kubesentry's log after the restart 24 lines, e.g. [pod/kubesentry-7dfc6d58b5-hqbmm/server] E1011 21:17:43.306587       1 reflector.go:227] "Failed to watch" err="jobs.batch is forbidden: User \"system:serviceaccount:kubesentry:kubesentry\" cannot watch resource \"jobs\"…
- +15s probes 4/4 answered 200; snapshot age max 6s, stale shown false; ready replicas never below 2
