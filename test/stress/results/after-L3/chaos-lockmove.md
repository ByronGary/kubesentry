# Chaos smoke set

2 passed, 0 failed.

| Scenario | Result | Seconds | Summary |
|---|---|---:|---|
| killreplica | pass | 274 | lock moved to the replacement pod in 2.6s; agents on the survivor 6→6, 6 fresh after; web errors 0 |
| standby | pass | 282 | lock moved to the standby in 5.1s; agents on the survivor 6→6, 6 fresh after; web errors 0 |

## killreplica

Numbers: map[agentsBefore:6 agentsFreshAfter:6 agentsMinOnSurvivor:6 cloudwatchDuplicated:0 cloudwatchExpected:2105643 cloudwatchMissing:0 lockTakeoverSeconds:2.5828987679999997 newHolderIP:10.240.0.25 standbyIP:10.240.0.22 webErrorsDuringMove:0]

- +1s leader (pg_locks) kubesentry-7dfc6d58b5-zxs7x 10.240.0.23 holds advisory lock 4138823262; standby kubesentry-7dfc6d58b5-jnpxl
- +1s deleted the leader the Deployment creates a replacement
- +3s lock taken by the replacement pod kubesentry-7dfc6d58b5-kqdxq (10.240.0.25) after 2.6s
- +25s agents after HTTP 200, 6 agents, 6 fresh; nodes reporting to kubesentry-7dfc6d58b5-jnpxl never below 6
- +25s waiting for CloudWatch late deliveries 4m
- +274s CloudWatch events 2105643 expected, 2105643 found, 0 missing, 0 duplicated

## standby

Numbers: map[agentsBefore:6 agentsFreshAfter:6 agentsMinOnSurvivor:6 cloudwatchDuplicated:0 cloudwatchExpected:2196812 cloudwatchMissing:0 lockTakeoverSeconds:5.100626935 newHolderIP:10.240.0.22 standbyIP:10.240.0.22 webErrorsDuringMove:0]

- +0s leader (pg_locks) kubesentry-7dfc6d58b5-kqdxq 10.240.0.25 holds advisory lock 4138823262; standby kubesentry-7dfc6d58b5-jnpxl
- +1s scaled to 1 with the leader marked cheapest to delete 
- +6s lock taken by the standby kubesentry-7dfc6d58b5-jnpxl (10.240.0.22) after 5.1s
- +28s agents after HTTP 200, 6 agents, 6 fresh; nodes reporting to kubesentry-7dfc6d58b5-jnpxl never below 6
- +28s waiting for CloudWatch late deliveries 4m
- +276s CloudWatch events 2196812 expected, 2196812 found, 0 missing, 0 duplicated
- +282s scaled back to 2 
