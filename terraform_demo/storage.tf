# S3 сақтау қоймасы
resource "aws_s3_bucket" "confidential_data" {
  bucket = "company-finance-reports"
  acl    = "public-read" # Қауіпті: жария оқу
}

# EBS сақтау дискісі
resource "aws_ebs_volume" "database_disk" {
  availability_zone = "us-east-1a"
  size              = 100
  encrypted         = false # Қауіпті: шифрланбаған
}
