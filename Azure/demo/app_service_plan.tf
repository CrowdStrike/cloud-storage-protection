resource "azurerm_service_plan" "app_service_plan" {
  name                = "${var.project}-plan-${random_string.resource_suffix.result}"
  resource_group_name = azurerm_resource_group.resource_group.name
  location            = var.location
  os_type             = "Linux"
  sku_name            = "Y1"
}
