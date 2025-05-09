resource "azurerm_resource_group" "resource_group" {
  name = "${var.project}-rg-${random_string.resource_suffix.result}"
  location = var.location
}
