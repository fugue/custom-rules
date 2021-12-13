package rules.ec2_approved_ami

__rego__metadoc__ := {
  "title": "AWS.EC2.Instance-ApprovedAMI",
  "description": "All EC2 instances must use an approved AMI. Replace the AMI ID below with your AMI ID.",
  "custom": {
    "providers": ["AWS"],
    "severity": "Medium"
  }
}

input_type = "tf"

resource_type = "AWS.EC2.Instance"

default allow = false

approved_amis = {
  'ami-04b762b4289fba92b'
}

allow {
    ami = input.ami  # Pull out AMIs
    approved_amis[ami]  # Assert
}