resource "aws_instance" "bad" {

}

resource "invalid_resource" "also_bad" {
  name = "has spaces"  # spaces in resource ref
}

variable "bad_var" {

output "bad_output" {
  value = aws_instance.bad.invalid_output  # invalid reference
}