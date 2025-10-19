package main

deny[msg] {
  input.kind == "Deployment"
  not input.spec.template.spec.securityContext.runAsNonRoot
  msg := "Containers must not run as root"
}

deny[msg] {
  input.kind == "Deployment"
  not input.spec.selector.matchLabels["app"]
  msg := "Containers must provide app label for pod selectors"
}

deny[msg] {
  input.kind == "Deployment"
  input.spec.replicas > 3
  msg := sprintf("Replicas must be 3 or fewer (found %v)", [input.spec.replicas])
}
