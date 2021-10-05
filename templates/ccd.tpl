{{- if (ne .ClientAddress "dynamic") }}
ifconfig-push {{ .ClientAddress }} 255.255.255.0
{{- end }}
{{- range $route := .CustomRoutes }}
push "route {{ $route.Address }} {{ $route.Mask }}" # {{ $route.Description }}
{{- end }}
