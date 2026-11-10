# Мәліметтер базасы
resource "aws_db_instance" "production_db" {
  allocated_storage   = 50
  engine              = "postgres"
  instance_class      = "db.t3.micro"
  publicly_accessible = true # Қауіпті: дерекқор интернетке ашық
}
