# Серверлік қауіпсіздік тобы (Security Group)
# Terraform кодында SSH (22) ЖАБЫҚ, тек қауіпсіз HTTPS (443) рұқсат етілген.
# Бірақ бұлттық консольде әкімші оны 0.0.0.0/0 үшін ашып қойған (ClickOps / Manual Drift).
resource "aws_security_group" "prod_web_sg" {
  name        = "vulnerable-ssh-sg"
  description = "Production Web Server SG with HTTPS only"

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Shift-Left IaC тексеруіне арналған кодтық қателік (Код деңгейіндегі қауіп)
resource "aws_security_group" "legacy_backend_sg" {
  name        = "legacy-backend-sg"
  description = "Legacy Backend SG with insecure open RDP"

  ingress {
    from_port        = 3389
    to_port          = 3389
    protocol         = "tcp"
    ipv6_cidr_blocks = ["::/0"]
  }
}
