# Falcon API Credentials
variable "falcon_client_id" {
    description = "The CrowdStrike Falcon API client ID"
    type = string
    sensitive = true
}
variable "falcon_client_secret" {
    description = "The CrowdStrike Falcon API client secret"
    type = string
    sensitive = true
}
variable "unique_id" {
    description = "A unique identifier appended to S3 Bucket"
    type = string
}
#

variable "region" {
    description = "AWS Region to deploy resources."
    type = string
    default = "us-east-1"
}
variable "env_alias" {
    description = "Demo alias is prepended to all created resource names"
    type = string
    default = "quickscan-pro-demo"
}
variable "lambda_function_filename" {
    description = "The name of the archive to use for the lambda function"
    type = string
    default = "lambda-function.zip"
}
variable "lambda_mitigate_threats" {
    description = "Remove malicious files from the bucket as they are discovered."
    type = string
    default = "TRUE"
}
variable "environment_tag" {
    description = "Environment tag"
    type        = string
    default     = "QuikScan Pro Demo"
}
variable "lambda_description" {
    description = "The description used for the lambda function"
    type = string
    default = "QuikScan Pro Demo Function"
}
resource "random_string" "random" {
  length           = 4
  special          = false
  lower            = false
}