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
