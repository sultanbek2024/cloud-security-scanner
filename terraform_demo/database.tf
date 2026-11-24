# Мәліметтер базасы (Terraform-да қауіпсіз: publicly_accessible = false)
# Бұлтта әкімші оны интернетке ашып қойған (ClickOps / Manual Drift).
resource "aws_db_instance" "production_db" {
  identifier          = "vulnerable-public-db"
  allocated_storage   = 50
  engine              = "postgres"
  instance_class      = "db.t3.micro"
  publicly_accessible = false # Қауіпсіз жабық
}
