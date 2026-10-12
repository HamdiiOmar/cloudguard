# INTENTIONALLY INSECURE demo for CloudGuard. Never deploy this.

resource "azurerm_storage_account" "insecure" {
  name                            = "stinsecure001"
  resource_group_name             = "rg-demo"
  location                        = "westeurope"
  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  allow_nested_items_to_be_public = true
  https_traffic_only_enabled      = false
  min_tls_version                 = "TLS1_0"
}

# Hardened storage account, for contrast.
resource "azurerm_storage_account" "hardened" {
  name                            = "sthardened001"
  resource_group_name             = "rg-demo"
  location                        = "westeurope"
  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  allow_nested_items_to_be_public = false
  https_traffic_only_enabled      = true
  min_tls_version                 = "TLS1_2"

  network_rules {
    default_action = "Deny"
  }
}

resource "azurerm_network_security_group" "web" {
  name                = "nsg-web"
  location            = "westeurope"
  resource_group_name = "rg-demo"

  security_rule {
    name                       = "allow-rdp"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "3389"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}

resource "azurerm_network_security_rule" "ssh" {
  name                        = "allow-ssh"
  priority                    = 110
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "22"
  source_address_prefix       = "Internet"
  destination_address_prefix  = "*"
  resource_group_name         = "rg-demo"
  network_security_group_name = azurerm_network_security_group.web.name
}
