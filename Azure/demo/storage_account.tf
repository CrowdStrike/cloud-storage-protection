resource "azurerm_storage_account" "storage_account" {
  name = "${var.project}sa${random_string.resource_suffix.result}"
  resource_group_name = azurerm_resource_group.resource_group.name
  location = var.location
  account_tier = "Standard"
  account_replication_type = "LRS"
}
