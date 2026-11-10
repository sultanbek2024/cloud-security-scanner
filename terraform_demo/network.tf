# Серверлік қауіпсіздік тобы (Security Group)
resource "aws_security_group" "prod_web_sg" {
  name        = "production-web-sg"
  description = "Production Web Server SG"

  # Қауіпті: SSH (22) бүкіл әлемге ашық
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Қауіпті: RDP (3389) бүкіл әлемге ашық
  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["::/0"]
  }
}
