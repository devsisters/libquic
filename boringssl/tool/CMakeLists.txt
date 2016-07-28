include_directories(../include)

add_executable(
  bssl_test

  args.cc
  ciphers.cc
  client.cc
  const.cc
  digest.cc
  generate_ed25519.cc
  genrsa.cc
  pkcs12.cc
  rand.cc
  server.cc
  speed.cc
  tool.cc
  transport_common.cc
)

if (APPLE OR WIN32 OR ANDROID)
  target_link_libraries(bssl_test bssl bsslcrypto)
else()
  find_library(FOUND_LIBRT rt)
  if (FOUND_LIBRT)
    target_link_libraries(bssl_test bssl bsslcrypto -lrt)
  else()
    target_link_libraries(bssl_test bssl bsslcrypto)
  endif()
endif()
