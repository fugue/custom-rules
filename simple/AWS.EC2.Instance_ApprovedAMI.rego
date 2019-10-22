# AWS.EC2.Instance
# All EC2 instances must use an approved AMI. Replace the AMI ID below with your AMI ID.

approved_ami = {
  'ami-04b762b4289fba92b'
}

allow {
    ami = input.ami  # Pull out AMIs
    approved_ami[ami]  # Assert 
}