# AWS Output Terraform
output "demo_bucket" {
  value = "s3://${aws_s3_bucket.bucket.id}"
}