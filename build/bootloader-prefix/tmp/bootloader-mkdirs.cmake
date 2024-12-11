# Distributed under the OSI-approved BSD 3-Clause License.  See accompanying
# file Copyright.txt or https://cmake.org/licensing for details.

cmake_minimum_required(VERSION 3.5)

file(MAKE_DIRECTORY
  "C:/Users/ridhi/esp/v5.2/esp-idf/components/bootloader/subproject"
  "C:/naman24/coimbature/test1/softap_sta/build/bootloader"
  "C:/naman24/coimbature/test1/softap_sta/build/bootloader-prefix"
  "C:/naman24/coimbature/test1/softap_sta/build/bootloader-prefix/tmp"
  "C:/naman24/coimbature/test1/softap_sta/build/bootloader-prefix/src/bootloader-stamp"
  "C:/naman24/coimbature/test1/softap_sta/build/bootloader-prefix/src"
  "C:/naman24/coimbature/test1/softap_sta/build/bootloader-prefix/src/bootloader-stamp"
)

set(configSubDirs )
foreach(subDir IN LISTS configSubDirs)
    file(MAKE_DIRECTORY "C:/naman24/coimbature/test1/softap_sta/build/bootloader-prefix/src/bootloader-stamp/${subDir}")
endforeach()
if(cfgdir)
  file(MAKE_DIRECTORY "C:/naman24/coimbature/test1/softap_sta/build/bootloader-prefix/src/bootloader-stamp${cfgdir}") # cfgdir has leading slash
endif()
