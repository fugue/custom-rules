# Provider: AWS
# Resource-Type: AWS.EC2.Instance
# Description: All EC2 instances must use an approved AMI. Replace the AMI ID below with your AMI ID.

approved_amis = {
  'ami-04b762b4289fba92b'
}

allow {
    ami = input.ami  # Pull out AMIs
    approved_amis[ami]  # Assert
}