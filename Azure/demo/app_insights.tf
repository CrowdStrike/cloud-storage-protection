resource "azurerm_application_insights" "application_insights" {
  name                = "${var.project}-insights-${random_string.resource_suffix.result}"
  location            = var.location
  resource_group_name = azurerm_resource_group.resource_group.name
  application_type    = "web"
}
