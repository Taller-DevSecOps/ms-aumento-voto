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

deny[msg] {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  # If either memory or cpu is missing or different, this condition is true (and triggers deny)
  not (container.resources.limits.memory == "256Mi" and container.resources.limits.cpu == "200m")
  cname := container_name(container)
  msg := sprintf("Container %v must set resources.limits.memory to 256Mi and resources.limits.cpu to 200m", [cname])
}
