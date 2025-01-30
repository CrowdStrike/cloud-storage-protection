locals {
    secret_body = jsonencode({
        FalconClientId = "${var.falcon_client_id}"
        FalconSecret = "${var.falcon_client_secret}"
    })
}

resource "aws_secretsmanager_secret" "secret" {
  name = "${var.env_alias}-secret-${random_string.random.result}"
}

resource "aws_secretsmanager_secret_version" "secret_version" {
  secret_id     = aws_secretsmanager_secret.secret.id
  secret_string = local.secret_body
}