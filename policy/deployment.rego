package main

import rego.v1
import data.kubernetes

name := input.metadata.name
deployment := input
containers = deployment.spec.template.spec.containers

# check kind deployment
deny contains msg if {
    not deployment.kind == "Deployment"
    msg = sprintf("%s resource must be of kind Deployment", [name])
}

# checking there is a namespace
deny contains msg if {
    not deployment.metadata.namespace
    msg = sprintf("%s resource must include a namespace", [name])
}

# checking there are CPU request
deny contains msg if {
    some container in containers
    not container.resources.requests.cpu
    msg = sprintf("container %s in %s must include CPU requests", [container.name, name])
}

# checking there are memory request
deny contains msg if {
    some container in containers
    not container.resources.requests.memory
    msg = sprintf("container %s in %s must include memory requests", [container.name, name])
}

# checking there are CPU limits
deny contains msg if {
    some container in containers
    not container.resources.limits.cpu
    msg = sprintf("container %s in %s must include CPU limits", [container.name, name])
}

# checking there are memory limits
deny contains msg if {
    some container in containers
    not container.resources.limits.memory
    msg = sprintf("container %s in %s must include memory limits", [container.name, name])
}

# checking all containers have a defined image
deny contains msg if {
    some container in containers
    not container.image
    msg = sprintf("container %s in %s must have an image", [container.name, name])
}
