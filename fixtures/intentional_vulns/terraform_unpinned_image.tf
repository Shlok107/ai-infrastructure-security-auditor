resource "aws_instance" "web" {
  ami = "ami-0c55b6598b98611f8"  # unpinned AMI - will change
  instance_type = "t2.micro"
}