{{/* ---------- names and labels ---------- */}}

{{- define "kubesentry.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* Full name. With the release name "kubesentry" it is just "kubesentry". */}}
{{- define "kubesentry.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "kubesentry.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "kubesentry.labels" -}}
helm.sh/chart: {{ include "kubesentry.chart" . }}
app.kubernetes.io/name: {{ include "kubesentry.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ include "kubesentry.imageTag" (dict "image" .Values.image "root" .) | trunc 63 | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: kubesentry
{{- with .Values.commonLabels }}
{{ toYaml . }}
{{- end }}
{{- end -}}

{{- define "kubesentry.selectorLabels" -}}
app.kubernetes.io/name: {{ include "kubesentry.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: server
{{- end -}}

{{- define "kubesentry.agentSelectorLabels" -}}
app.kubernetes.io/name: {{ include "kubesentry.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: agent
{{- end -}}

{{- define "kubesentry.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "kubesentry.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "kubesentry.agentServiceAccountName" -}}
{{- if .Values.agent.serviceAccount.create -}}
{{- default (printf "%s-agent" (include "kubesentry.fullname" .)) .Values.agent.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.agent.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "kubesentry.agentNamespace" -}}
{{- default .Release.Namespace .Values.agent.namespace -}}
{{- end -}}

{{/* ---------- images ---------- */}}

{{- define "kubesentry.imageTag" -}}
{{- default .root.Chart.AppVersion .image.tag -}}
{{- end -}}

{{/* repository:tag, or repository@digest when a digest is set. */}}
{{- define "kubesentry.image" -}}
{{- if .image.digest -}}
{{- printf "%s@%s" .image.repository .image.digest -}}
{{- else -}}
{{- printf "%s:%s" .image.repository (include "kubesentry.imageTag" .) -}}
{{- end -}}
{{- end -}}

{{/* ---------- derived settings ---------- */}}

{{/* Effective -auth-mode. */}}
{{- define "kubesentry.authMode" -}}
{{- if .Values.auth.mode -}}
{{- .Values.auth.mode -}}
{{- else if .Values.oauth2Proxy.enabled -}}
proxy
{{- else -}}
token
{{- end -}}
{{- end -}}

{{/* Unix socket between the oauth2-proxy sidecar and kubesentry, in a shared emptyDir. */}}
{{- define "kubesentry.webSocketDir" -}}/var/run/kubesentry{{- end -}}
{{- define "kubesentry.webSocket" -}}{{ include "kubesentry.webSocketDir" . }}/web.sock{{- end -}}

{{/* Container port behind the web Service. */}}
{{- define "kubesentry.webPort" -}}
{{- if .Values.oauth2Proxy.enabled -}}4180{{- else -}}8080{{- end -}}
{{- end -}}

{{- define "kubesentry.clusterName" -}}
{{- default .Values.eks.clusterName .Values.clusterName -}}
{{- end -}}

{{- define "kubesentry.awsRegion" -}}
{{- if and .Values.prometheus.amp.enabled .Values.prometheus.amp.region -}}
{{- .Values.prometheus.amp.region -}}
{{- else -}}
{{- .Values.eks.region -}}
{{- end -}}
{{- end -}}

{{/* Comma list of enabled audit sources, empty when none. */}}
{{- define "kubesentry.auditSources" -}}
{{- $s := list -}}
{{- if .Values.audit.sources.webhook.enabled }}{{ $s = append $s "webhook" }}{{ end -}}
{{- if .Values.audit.sources.cloudwatch.enabled }}{{ $s = append $s "cloudwatch" }}{{ end -}}
{{- if .Values.audit.sources.file.path }}{{ $s = append $s "file" }}{{ end -}}
{{- join "," $s -}}
{{- end -}}

{{/* Token Secret names: the user's existingSecret, or the one the chart generates. */}}
{{- define "kubesentry.apiTokenSecret" -}}
{{- default (printf "%s-api" (include "kubesentry.fullname" .)) .Values.tokens.api.existingSecret -}}
{{- end -}}
{{- define "kubesentry.agentTokenSecret" -}}
{{- default (printf "%s-agent" (include "kubesentry.fullname" .)) .Values.tokens.agent.existingSecret -}}
{{- end -}}
{{- define "kubesentry.auditTokenSecret" -}}
{{- default (printf "%s-audit" (include "kubesentry.fullname" .)) .Values.tokens.audit.existingSecret -}}
{{- end -}}

{{/* The server accepts agent reports when the chart runs agents or an agent token is supplied. */}}
{{- define "kubesentry.agentTokenWanted" -}}
{{- if or .Values.agent.enabled .Values.tokens.agent.existingSecret -}}true{{- end -}}
{{- end -}}

{{- define "kubesentry.ingestScheme" -}}
{{- if .Values.tls.enabled -}}https{{- else -}}http{{- end -}}
{{- end -}}

{{/* Ingest URL agents and webhook senders use. */}}
{{- define "kubesentry.ingestURL" -}}
{{- printf "%s://%s-ingest.%s.svc:8081" (include "kubesentry.ingestScheme" .) (include "kubesentry.fullname" .) .Release.Namespace -}}
{{- end -}}

{{/* CA file source for the agent: explicit secret or config map, else the server's TLS secret when it is reachable. */}}
{{- define "kubesentry.agentCASource" -}}
{{- if .Values.agent.tls.caSecret -}}
secret
{{- else if .Values.agent.tls.caConfigMap -}}
configMap
{{- else if and .Values.tls.enabled (eq (include "kubesentry.agentNamespace" .) .Release.Namespace) -}}
serverSecret
{{- end -}}
{{- end -}}

{{/*
Scalar for a flag value. Helm reads YAML numbers as float64, which print as
1.048576e+06; whole numbers are printed as integers instead.
*/}}
{{- define "kubesentry.scalar" -}}
{{- if kindIs "float64" . -}}
{{- if eq . (float64 (int64 .)) -}}{{ int64 . }}{{- else -}}{{ . }}{{- end -}}
{{- else -}}
{{- . -}}
{{- end -}}
{{- end -}}

{{/* "k=v,k=v" from a map, keys sorted. */}}
{{- define "kubesentry.kvList" -}}
{{- $out := list -}}
{{- range $k, $v := . -}}
{{- $out = append $out (printf "%s=%s" $k (include "kubesentry.scalar" $v)) -}}
{{- end -}}
{{- join "," $out -}}
{{- end -}}

{{/* ---------- guardrails ---------- */}}

{{- define "kubesentry.validate" -}}
{{- $v := .Values -}}
{{- $mode := include "kubesentry.authMode" . -}}
{{- $sources := include "kubesentry.auditSources" . -}}
{{- if and (gt (int $v.replicas) 1) (eq $v.audit.store "memory") $sources -}}
{{- fail (printf "kubesentry: replicas=%d with audit.store=memory and audit sources enabled (%s): each replica would keep a different, partial audit history. Set audit.store=postgres with audit.postgres.existingSecret, or replicas=1." (int $v.replicas) $sources) -}}
{{- end -}}
{{- if and (eq $mode "proxy") (not $v.oauth2Proxy.enabled) (empty $v.auth.trustedProxyCIDRs) -}}
{{- fail "kubesentry: auth.mode=proxy without oauth2Proxy.enabled needs auth.trustedProxyCIDRs, the addresses of the SSO proxy allowed to send identity headers. Otherwise enable the oauth2Proxy sidecar." -}}
{{- end -}}
{{- if and (eq $mode "proxy") (not $v.oauth2Proxy.enabled) (not $v.auth.allowAnyProxy) -}}
{{- range $v.auth.trustedProxyCIDRs -}}
{{- if hasSuffix "/0" (trim .) -}}
{{- fail (printf "kubesentry: auth.trustedProxyCIDRs contains %s, which lets anyone who reaches the web port claim any identity. Name the SSO proxy's addresses, or set auth.allowAnyProxy=true if a network policy admits only the proxy." .) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- if and $v.audit.sources.cloudwatch.enabled (not $v.eks.clusterName) (not $v.audit.sources.cloudwatch.logGroup) -}}
{{- fail "kubesentry: audit.sources.cloudwatch.enabled needs eks.clusterName (log group /aws/eks/<name>/cluster) or an explicit audit.sources.cloudwatch.logGroup." -}}
{{- end -}}
{{- if eq $mode "none" -}}
{{- fail "kubesentry: auth.mode=none is only allowed on loopback, and the chart exposes the web port. Use token, or proxy with oauth2Proxy.enabled." -}}
{{- end -}}
{{- if and $v.oauth2Proxy.enabled (ne $mode "proxy") -}}
{{- fail (printf "kubesentry: oauth2Proxy.enabled needs auth.mode=proxy (or empty), not %q." $mode) -}}
{{- end -}}
{{- if $v.oauth2Proxy.enabled -}}
{{- if not $v.oauth2Proxy.existingSecret -}}
{{- fail "kubesentry: oauth2Proxy.enabled needs oauth2Proxy.existingSecret, a Secret with the OAuth client secret and a cookie secret." -}}
{{- end -}}
{{- if not $v.oauth2Proxy.clientID -}}
{{- fail "kubesentry: oauth2Proxy.enabled needs oauth2Proxy.clientID." -}}
{{- end -}}
{{- if and (has $v.oauth2Proxy.provider (list "oidc" "entra-id")) (not $v.oauth2Proxy.issuerURL) -}}
{{- fail (printf "kubesentry: oauth2Proxy.provider=%s needs oauth2Proxy.issuerURL." $v.oauth2Proxy.provider) -}}
{{- end -}}
{{- if and (eq $v.oauth2Proxy.sessionStore.type "redis") (not $v.oauth2Proxy.sessionStore.redis.connectionURL) (empty $v.oauth2Proxy.sessionStore.redis.clusterConnectionURLs) -}}
{{- fail "kubesentry: oauth2Proxy.sessionStore.type=redis needs sessionStore.redis.connectionURL (or clusterConnectionURLs with useCluster)." -}}
{{- end -}}
{{- end -}}
{{- if and (eq $v.audit.store "postgres") (not $v.audit.postgres.existingSecret) -}}
{{- fail "kubesentry: audit.store=postgres needs audit.postgres.existingSecret, a Secret holding the DSN." -}}
{{- end -}}
{{- if and $v.prometheus.amp.enabled (not $v.prometheus.amp.workspaceURL) -}}
{{- fail "kubesentry: prometheus.amp.enabled needs prometheus.amp.workspaceURL." -}}
{{- end -}}
{{- if and $v.prometheus.amp.enabled $v.prometheus.url -}}
{{- fail "kubesentry: set either prometheus.url or prometheus.amp, not both." -}}
{{- end -}}
{{- if and $v.tls.enabled (not $v.tls.existingSecret) -}}
{{- fail "kubesentry: tls.enabled needs tls.existingSecret, a kubernetes.io/tls Secret." -}}
{{- end -}}
{{- end -}}

{{/* ---------- server flags ---------- */}}

{{- define "kubesentry.serverArgs" -}}
{{- $v := .Values -}}
{{- $mode := include "kubesentry.authMode" . -}}
{{- $a := list -}}
{{- /* listeners */ -}}
{{- if $v.oauth2Proxy.enabled -}}
{{- /* Only the sidecar, which shares the socket's volume, reaches the web listener: no TCP web port at all. */ -}}
{{- $a = append $a (printf "-addr=unix://%s" (include "kubesentry.webSocket" .)) -}}
{{- else -}}
{{- $a = append $a "-addr=:8080" -}}
{{- end -}}
{{- with $v.server.allowedHosts }}{{ $a = append $a (printf "-allowed-hosts=%s" (join "," .)) }}{{ end -}}
{{- $a = append $a "-ingest-addr=:8081" -}}
{{- $a = append $a "-ops-addr=:9090" -}}
{{- if $v.server.pprof }}{{ $a = append $a "-pprof=true" }}{{ end -}}
{{- if $v.tls.enabled -}}
{{- $a = append $a "-tls-cert=/etc/kubesentry/tls/tls.crt" -}}
{{- $a = append $a "-tls-key=/etc/kubesentry/tls/tls.key" -}}
{{- end -}}
{{- with include "kubesentry.clusterName" . }}{{ $a = append $a (printf "-cluster-name=%s" .) }}{{ end -}}
{{- /* auth */ -}}
{{- $a = append $a (printf "-auth-mode=%s" $mode) -}}
{{- if eq $mode "proxy" -}}
{{- $a = append $a (printf "-auth-user-header=%s" $v.auth.userHeader) -}}
{{- $a = append $a (printf "-auth-groups-header=%s" $v.auth.groupsHeader) -}}
{{- if not $v.oauth2Proxy.enabled -}}
{{- /* With the sidecar the socket is the only trusted path; CIDRs apply to an SSO proxy elsewhere. */ -}}
{{- $a = append $a (printf "-auth-trusted-proxy-cidrs=%s" (join "," $v.auth.trustedProxyCIDRs)) -}}
{{- if $v.auth.allowAnyProxy }}{{ $a = append $a "-auth-allow-any-proxy=true" }}{{ end -}}
{{- end -}}
{{- with $v.auth.usernamePrefix }}{{ $a = append $a (printf "-auth-username-prefix=%s" .) }}{{ end -}}
{{- with $v.auth.groupsPrefix }}{{ $a = append $a (printf "-auth-groups-prefix=%s" .) }}{{ end -}}
{{- if $v.auth.groupMap }}{{ $a = append $a "-auth-group-map-file=/etc/kubesentry/auth/group-map.json" }}{{ end -}}
{{- if not (kindIs "invalid" $v.auth.authzQPS) }}{{ $a = append $a (printf "-authz-qps=%s" (include "kubesentry.scalar" $v.auth.authzQPS)) }}{{ end -}}
{{- with $v.auth.authzCacheTTL }}{{ $a = append $a (printf "-authz-cache-ttl=%s" .) }}{{ end -}}
{{- with $v.auth.authzDenyTTL }}{{ $a = append $a (printf "-authz-deny-ttl=%s" .) }}{{ end -}}
{{- $a = append $a (printf "-authz-share-by-groups=%t" $v.auth.shareByGroups) -}}
{{- end -}}
{{- /* server tuning */ -}}
{{- $s := $v.server -}}
{{- if not (kindIs "invalid" $s.cache) }}{{ $a = append $a (printf "-cache=%t" $s.cache) }}{{ end -}}
{{- range $flag, $val := dict "kube-qps" $s.kubeQPS "kube-burst" $s.kubeBurst "snapshot-min-interval" $s.snapshotMinInterval "snapshot-max-delay" $s.snapshotMaxDelay "rate-limit" $s.rateLimit "rate-burst" $s.rateBurst "max-inflight" $s.maxInflight "max-inflight-per-identity" $s.maxInflightPerIdentity -}}
{{- if not (kindIs "invalid" $val) }}{{ $a = append $a (printf "-%s=%s" $flag (include "kubesentry.scalar" $val)) }}{{ end -}}
{{- end -}}
{{- with $s.systemPrincipalPrefixes }}{{ $a = append $a (printf "-system-principal-prefixes=%s" (join "," .)) }}{{ end -}}
{{- with $s.builtinRBACPrefixes }}{{ $a = append $a (printf "-builtin-rbac-prefixes=%s" (join "," .)) }}{{ end -}}
{{- with $s.nodeLabelKeysAdd }}{{ $a = append $a (printf "-node-label-keys-add=%s" (join "," .)) }}{{ end -}}
{{- /* policy: system namespaces, thresholds, pricing */ -}}
{{- with $v.systemNamespaces.replace }}{{ $a = append $a (printf "-system-namespaces=%s" (join "," .)) }}{{ end -}}
{{- $addNS := $v.systemNamespaces.add | default (list) -}}
{{- $agentNS := include "kubesentry.agentNamespace" . -}}
{{- if and $v.agent.enabled (ne $agentNS .Release.Namespace) (not (has $agentNS $addNS)) -}}
{{- $addNS = append $addNS $agentNS -}}
{{- end -}}
{{- with $addNS }}{{ $a = append $a (printf "-system-namespaces-add=%s" (join "," .)) }}{{ end -}}
{{- $t := $v.thresholds -}}
{{- $tflags := dict "restartWarn" "restart-warn" "restartCrit" "restart-crit" "oomRecent" "oom-recent" "pendingGrace" "pending-grace" "notReadyGrace" "not-ready-grace" "terminatingGrace" "terminating-grace" "recentPod" "recent-pod" "activityWindow" "activity-window" "pvcMinAge" "pvc-min-age" "leakCritHours" "leak-crit-hours" "leakMinSlope" "leak-min-slope" "leakMinR2" "leak-min-r2" "leakDropRatio" "leak-drop-ratio" "leakMinPoints" "leak-min-points" "certCritCap" "cert-crit-cap" "certWarnCap" "cert-warn-cap" -}}
{{- range $key, $flag := $tflags -}}
{{- $val := index $t $key -}}
{{- if not (kindIs "invalid" $val) }}{{ $a = append $a (printf "-%s=%s" $flag (include "kubesentry.scalar" $val)) }}{{ end -}}
{{- end -}}
{{- if not (kindIs "invalid" $v.pricing.defaultPrice) }}{{ $a = append $a (printf "-pvc-default-price=%s" (include "kubesentry.scalar" $v.pricing.defaultPrice)) }}{{ end -}}
{{- with $v.pricing.ebsPrices }}{{ $a = append $a (printf "-ebs-prices=%s" (include "kubesentry.kvList" .)) }}{{ end -}}
{{- with $v.pricing.classPrices }}{{ $a = append $a (printf "-pvc-class-prices=%s" (include "kubesentry.kvList" .)) }}{{ end -}}
{{- /* owners and production namespaces */ -}}
{{- with $v.alerts.ownerAnnotation }}{{ $a = append $a (printf "-owner-annotation=%s" .) }}{{ end -}}
{{- with $v.alerts.production.labelKey }}{{ $a = append $a (printf "-production-label=%s=%s" . (toString $v.alerts.production.labelValue)) }}{{ end -}}
{{- /* prometheus */ -}}
{{- $p := $v.prometheus -}}
{{- $region := include "kubesentry.awsRegion" . -}}
{{- if $p.amp.enabled -}}
{{- $a = append $a (printf "-prometheus-url=%s" $p.amp.workspaceURL) -}}
{{- $a = append $a "-prometheus-sigv4=true" -}}
{{- else if $p.url -}}
{{- $a = append $a (printf "-prometheus-url=%s" $p.url) -}}
{{- else -}}
{{- $a = append $a (printf "-prometheus-autodiscover=%t" $p.autodiscover) -}}
{{- with $p.service }}{{ $a = append $a (printf "-prometheus-service=%s" .) }}{{ end -}}
{{- end -}}
{{- with $p.selector }}{{ $a = append $a (printf "-prometheus-selector=%s" .) }}{{ end -}}
{{- if $p.ksmLimits }}{{ $a = append $a "-prometheus-ksm-limits=true" }}{{ end -}}
{{- with $p.leakScan.interval }}{{ $a = append $a (printf "-leak-scan-interval=%s" .) }}{{ end -}}
{{- with $p.leakScan.window }}{{ $a = append $a (printf "-leak-scan-window=%s" .) }}{{ end -}}
{{- with $region }}{{ $a = append $a (printf "-aws-region=%s" .) }}{{ end -}}
{{- /* audit */ -}}
{{- $au := $v.audit -}}
{{- $a = append $a (printf "-audit-store=%s" $au.store) -}}
{{- if eq $au.store "postgres" -}}
{{- with $au.postgres.schema }}{{ $a = append $a (printf "-pg-schema=%s" .) }}{{ end -}}
{{- if not (kindIs "invalid" $au.postgres.maxConns) }}{{ $a = append $a (printf "-pg-max-conns=%s" (include "kubesentry.scalar" $au.postgres.maxConns)) }}{{ end -}}
{{- with $au.postgres.queryTimeout }}{{ $a = append $a (printf "-pg-query-timeout=%s" .) }}{{ end -}}
{{- with $au.retention }}{{ $a = append $a (printf "-audit-retention=%s" .) }}{{ end -}}
{{- else if not (kindIs "invalid" $au.maxEvents) -}}
{{- $a = append $a (printf "-audit-max-events=%s" (include "kubesentry.scalar" $au.maxEvents)) -}}
{{- end -}}
{{- if $au.redactExecArgs }}{{ $a = append $a "-audit-redact-exec-args=true" }}{{ end -}}
{{- with $au.sources.file.path -}}
{{- $a = append $a (printf "-audit-log-file=%s" .) -}}
{{- if $au.sources.file.fromStart }}{{ $a = append $a "-audit-from-start=true" }}{{ end -}}
{{- end -}}
{{- $cw := $au.sources.cloudwatch -}}
{{- if $cw.enabled -}}
{{- $a = append $a "-cloudwatch=true" -}}
{{- $a = append $a (printf "-cloudwatch-log-group=%s" (default (printf "/aws/eks/%s/cluster" $v.eks.clusterName) $cw.logGroup)) -}}
{{- with $cw.streamPrefix }}{{ $a = append $a (printf "-cloudwatch-stream-prefix=%s" .) }}{{ end -}}
{{- with $cw.start }}{{ $a = append $a (printf "-cloudwatch-start=%s" .) }}{{ end -}}
{{- with $cw.endpoint }}{{ $a = append $a (printf "-cloudwatch-endpoint=%s" .) }}{{ end -}}
{{- end -}}
{{- if $v.eks.awsAuth.read }}{{ $a = append $a "-aws-auth=true" }}{{ end -}}
{{- range $v.extraArgs }}{{ $a = append $a . }}{{ end -}}
{{- toYaml $a -}}
{{- end -}}

{{/* ---------- agent flags ---------- */}}

{{- define "kubesentry.agentArgs" -}}
{{- $g := .Values.agent -}}
{{- $a := list (printf "-server=%s" (include "kubesentry.ingestURL" .)) -}}
{{- if $g.fanout -}}
{{- $a = append $a (printf "-server-fanout=%s-ingest-headless.%s.svc" (include "kubesentry.fullname" .) .Release.Namespace) -}}
{{- end -}}
{{- with $g.interval }}{{ $a = append $a (printf "-interval=%s" .) }}{{ end -}}
{{- if not (kindIs "invalid" $g.jitter) }}{{ $a = append $a (printf "-jitter=%s" (include "kubesentry.scalar" $g.jitter)) }}{{ end -}}
{{- if not (kindIs "invalid" $g.gzip) }}{{ $a = append $a (printf "-gzip=%t" $g.gzip) }}{{ end -}}
{{- if not (kindIs "invalid" $g.maxProcesses) }}{{ $a = append $a (printf "-max-processes=%s" (include "kubesentry.scalar" $g.maxProcesses)) }}{{ end -}}
{{- if include "kubesentry.agentCASource" . -}}
{{- $a = append $a (printf "-ca-file=/etc/kubesentry/ca/%s" $g.tls.caKey) -}}
{{- end -}}
{{- range $g.extraArgs }}{{ $a = append $a . }}{{ end -}}
{{- toYaml $a -}}
{{- end -}}
