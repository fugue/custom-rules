# For AWS resources that support tags, require a tag named Stage with a value Prod

allow {
  input.tags.Stage == "Prod"
}
