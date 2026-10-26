{{/* Chart name */}}
{{- define "sbi-ha-gateway.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* Fully qualified app name */}}
{{- define "sbi-ha-gateway.fullname" -}}
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

{{/* Chart label */}}
{{- define "sbi-ha-gateway.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* Common labels */}}
{{- define "sbi-ha-gateway.labels" -}}
helm.sh/chart: {{ include "sbi-ha-gateway.chart" . }}
{{ include "sbi-ha-gateway.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{/* Selector labels */}}
{{- define "sbi-ha-gateway.selectorLabels" -}}
app.kubernetes.io/name: {{ include "sbi-ha-gateway.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/* ServiceAccount name */}}
{{- define "sbi-ha-gateway.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "sbi-ha-gateway.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/* Bundled NATS labels. Its own app.kubernetes.io/name, so that the gateway's selector
(name + instance) never matches a NATS pod. */}}
{{- define "sbi-ha-gateway.natsSelectorLabels" -}}
app.kubernetes.io/name: {{ include "sbi-ha-gateway.name" . }}-nats
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "sbi-ha-gateway.natsLabels" -}}
helm.sh/chart: {{ include "sbi-ha-gateway.chart" . }}
{{ include "sbi-ha-gateway.natsSelectorLabels" . }}
app.kubernetes.io/component: nats
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{/* True when the chart deploys its own NATS: no URL given and nats.deploy on. */}}
{{- define "sbi-ha-gateway.natsBundled" -}}
{{- if and (not .Values.config.nats.url) .Values.nats.deploy -}}true{{- end -}}
{{- end -}}

{{/* The NATS URL the gateway is configured with: config.nats.url when set, else the
bundled NATS, else a render error. */}}
{{- define "sbi-ha-gateway.natsURL" -}}
{{- if .Values.config.nats.url -}}
{{- .Values.config.nats.url -}}
{{- else if .Values.nats.deploy -}}
{{- printf "nats://%s-nats:4222" (include "sbi-ha-gateway.fullname" .) -}}
{{- else -}}
{{- fail "config.nats.url is required when nats.deploy=false: set it to the NATS your applications use." -}}
{{- end -}}
{{- end -}}

{{/*
Milliseconds in a duration value: "500ms", "5s", "1m", "1h" (the forms the schema admits).
*/}}
{{- define "sbi-ha-gateway.ms" -}}
{{- $v := toString . -}}
{{- if hasSuffix "ms" $v -}}{{ trimSuffix "ms" $v | int64 }}
{{- else if hasSuffix "s" $v -}}{{ mul (trimSuffix "s" $v | int64) 1000 }}
{{- else if hasSuffix "m" $v -}}{{ mul (trimSuffix "m" $v | int64) 60000 }}
{{- else -}}{{ mul (trimSuffix "h" $v | int64) 3600000 }}
{{- end -}}
{{- end -}}

{{/*
The Secret holding the admin port's token: config.admin.tokenSecret, or the one the chart
creates (admin-token-secret.yaml).
*/}}
{{- define "sbi-ha-gateway.adminTokenSecret" -}}
{{- .Values.config.admin.tokenSecret | default (printf "%s-admin-token" (include "sbi-ha-gateway.fullname" .)) -}}
{{- end -}}

{{/*
"true" when the admin port is served with TLS: asked for, and a certificate to serve it with.
Without tls.existingSecret only a trial install gets here (deployment.yaml fails the others).
*/}}
{{- define "sbi-ha-gateway.adminTLS" -}}
{{- if and .Values.config.admin.tls .Values.tls.existingSecret }}true{{ end -}}
{{- end -}}

{{/*
NRF registration (config.nrf): on when apiRoot is set. The profiles file is what
NRF_PROFILES_FILE points at; nrfCheck stops a render the gateway would refuse at start.
*/}}
{{- define "sbi-ha-gateway.nrfEnabled" -}}
{{- if .Values.config.nrf.apiRoot }}true{{ end }}
{{- end }}

{{- define "sbi-ha-gateway.nrfProfiles" -}}
{{- dict "profiles" .Values.config.nrf.profiles | toPrettyJson }}
{{- end }}

{{- define "sbi-ha-gateway.nrfCheck" -}}
{{- with .Values.config.nrf }}
{{- if and .apiRoot (not .profiles) }}
{{- fail "config.nrf.apiRoot needs config.nrf.profiles: the NF profiles to register" }}
{{- end }}
{{- if and .profiles (not .apiRoot) }}
{{- fail "config.nrf.profiles needs config.nrf.apiRoot: the NRF to register them with" }}
{{- end }}
{{- end }}
{{- end }}

{{/* Environment the gateway and the deregistration Job share: the NRF and the outbound TLS. */}}
{{- define "sbi-ha-gateway.nrfEnv" -}}
- name: NRF_API_ROOT
  value: {{ .Values.config.nrf.apiRoot | quote }}
- name: NRF_PROFILES_FILE
  value: "/etc/sbi-gateway/nrf/profiles.json"
{{- with .Values.config.nrf.heartbeatTimer }}
- name: NRF_HEARTBEAT_TIMER
  value: {{ . | quote }}
{{- end }}
{{- end }}

{{- define "sbi-ha-gateway.outboundTLSEnv" -}}
{{- with .Values.config.mtls }}
{{- range $env, $path := dict "MTLS_OUTBOUND_CERT_FILE" .outboundCertFile "MTLS_OUTBOUND_KEY_FILE" .outboundKeyFile "MTLS_OUTBOUND_CA_FILE" .outboundCAFile }}
{{- if $path }}
- name: {{ $env }}
  value: {{ $path | quote }}
{{- end }}
{{- end }}
{{- end }}
{{- end }}
