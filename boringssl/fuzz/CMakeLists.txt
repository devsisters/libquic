include_directories(../include)

add_executable(
  privkey

  privkey.cc
)

target_link_libraries(privkey Fuzzer)
target_link_libraries(privkey bsslcrypto)

add_executable(
  cert

  cert.cc
)

target_link_libraries(cert Fuzzer)
target_link_libraries(cert bsslcrypto)

add_executable(
  spki

  spki.cc
)

target_link_libraries(spki Fuzzer)
target_link_libraries(spki bsslcrypto)

add_executable(
  pkcs8

  pkcs8.cc
)

target_link_libraries(pkcs8 Fuzzer)
target_link_libraries(pkcs8 bsslcrypto)

add_executable(
  server

  server.cc
)

target_link_libraries(server Fuzzer)
target_link_libraries(server bsslcrypto)
target_link_libraries(server bssl)

add_executable(
  client

  client.cc
)

target_link_libraries(client Fuzzer)
target_link_libraries(client bsslcrypto)
target_link_libraries(client bssl)
