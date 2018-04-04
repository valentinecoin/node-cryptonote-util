// Copyright (c) 2012-2013 The Cryptonote developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <vector>

#include "serialization.h"
#include "debug_archive.h"
#include "crypto/chacha8.h"
#include "crypto/crypto.h"
#include "crypto/hash.h"

// read
template <template <bool> class Archive>
bool do_serialize(Archive<false> &ar, std::vector<Crypto::Signature> &v)
{
  size_t cnt = v.size();
  v.clear();

  // very basic sanity check
  if (ar.remaining_bytes() < cnt*sizeof(Crypto::Signature)) {
    ar.stream().setstate(std::ios::failbit);
    return false;
  }

  v.reserve(cnt);
  for (size_t i = 0; i < cnt; i++) {
    v.resize(i+1);
    ar.serialize_blob(&(v[i]), sizeof(Crypto::Signature), "");
    if (!ar.stream().good())
      return false;
  }
  return true;
}

// write
template <template <bool> class Archive>
bool do_serialize(Archive<true> &ar, std::vector<Crypto::Signature> &v)
{
  if (0 == v.size()) return true;
  ar.begin_string();
  size_t cnt = v.size();
  for (size_t i = 0; i < cnt; i++) {
    ar.serialize_blob(&(v[i]), sizeof(Crypto::Signature), "");
    if (!ar.stream().good())
      return false;
  }
  ar.end_string();
  return true;
}

BLOB_SERIALIZER(Crypto::chacha8_iv);
BLOB_SERIALIZER(Crypto::Hash);
BLOB_SERIALIZER(Crypto::PublicKey);
BLOB_SERIALIZER(Crypto::SecretKey);
BLOB_SERIALIZER(Crypto::KeyImage);
BLOB_SERIALIZER(Crypto::Signature);
VARIANT_TAG(debug_archive, Crypto::Hash, "hash");
VARIANT_TAG(debug_archive, Crypto::PublicKey, "public_key");
VARIANT_TAG(debug_archive, Crypto::SecretKey, "secret_key");
VARIANT_TAG(debug_archive, Crypto::KeyImage, "key_image");
VARIANT_TAG(debug_archive, Crypto::Signature, "signature"); 
