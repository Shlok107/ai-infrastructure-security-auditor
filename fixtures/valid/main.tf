resource "aws_instance" "web" {
  ami           = "ami-0c55b6598b98611f8"
  instance_type = "t2.micro"

  tags = {
    Name = "web-server"
  }
}

variable "instance_type" {
  description = "EC2 instance type"
  type        = string
  default     = "t2.micro"
}

output "instance_ip" {
  value = aws_instance.web.private_ip
}