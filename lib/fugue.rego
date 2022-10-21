package fugue

# Library

# Deprecated: please use `input_resource_types`
resource_types_v0 = resource_types

input_resource_types = resource_types

# Internal: please use `input_resource_types`
resource_types = {rt |
  r = input.resources[_]
  rt = r._type
}

resources_by_type = {rt: rs |
  resource_types[rt]
  rs = {ri: r |
    r = input.resources[ri]
    r._type == rt
  }
}

resource_providers = {provider |
  r = input.resources[_]
  provider = r._provider
}

resources(rt) = ret {
  ret = resources_by_type[rt]
} {
  # Make sure we always return something rather than failing when the resource
  # type is not available.
  not resource_types[rt]
  ret = {}
}

allow_resource(resource) = ret {
  ret := allow({"resource": resource})
}

allow(params) = ret {
  ret := {
    "valid": true,
    "id": params.resource.id,
    "type": params.resource._type,
    "message": object.get(params, "message", ""),
  }
}

deny_resource(resource) = ret {
  ret = deny({"resource": resource})
}

deny_resource_with_message(resource, message) = ret {
  ret := deny({"resource": resource, "message": message})
}

deny(params) = ret {
  ret := {
    "valid": false,
    "id": params.resource.id,
    "type": params.resource._type,
    "message": object.get(params, "message", ""),
    "attribute": object.get(params, "attribute", null),
  }
}

missing_resource(resource_type) = ret {
  ret := missing({"resource_type": resource_type})
}

missing_resource_with_message(resource_type, message) = ret {
  ret := missing({"resource_type": resource_type, "message": message})
}

missing(params) = ret {
  ret := {
    "valid": false,
    "id": "",
    "type": params.resource_type,
    "message": object.get(params, "message", "invalid"),
  }
}

report_v0(message, policy) = ret {
  ok := all([p.valid | policy[p]])
  msg := {true: "", false: message}
  ret := {
    "valid": ok,
    "message": msg[ok],
    "resources": policy,
  }
}

input_type = "tf_runtime"
