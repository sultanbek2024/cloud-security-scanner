# S3 сақтау қоймасы (Terraform-да қауіпсіз private және SSE қосулы)
# Бұлттық ортада бұл бакеттен шифрлау өшірілген немесе PAB ашылған (ClickOps / Manual Drift).
resource "aws_s3_bucket" "confidential_data" {
  bucket = "vulnerable-public-bucket"
  acl    = "private"

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}

# Shift-Left IaC: EBS сақтау дискісі кодта шифрланбаған
resource "aws_ebs_volume" "database_disk" {
  availability_zone = "us-east-1a"
  size              = 100
  encrypted         = false # Shift-Left: кодтағы қате
}
