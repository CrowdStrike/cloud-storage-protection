terraform {
  required_providers {
    azurerm = {
      source = "hashicorp/azurerm"
      version = "=3.105.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "3.7.2"
    }
  }
}

# Generate a random suffix to be used in resource names
resource "random_string" "resource_suffix" {
  length  = 8
  special = false
  upper   = false
}
