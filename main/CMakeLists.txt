idf_component_register(
    SRCS "test_esp_main.c"
    INCLUDE_DIRS "."
    REQUIRES esp_wifi esp_event esp_netif nvs_flash esp_timer driver
)

target_link_options(${COMPONENT_LIB} PUBLIC
    "-Wl,--wrap=esp_netif_receive"
    "-Wl,--wrap=esp_wifi_internal_tx"
    "-Wl,--wrap=esp_wifi_internal_tx_by_ref"
)