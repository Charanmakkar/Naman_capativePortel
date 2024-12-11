idf_component_register(SRCS "softap_sta.c"
                    INCLUDE_DIRS "."
                    REQUIRES lwip
                    REQUIRES esp_wifi
                    REQUIRES nvs_flash
                    REQUIRES esp_http_server
                    REQUIRES spiffs
                    REQUIRES json
                    REQUIRES driver)

spiffs_create_partition_image(storage ../data FLASH_IN_PROJECT)