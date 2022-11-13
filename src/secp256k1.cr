module Secp256k1
  extend self

  def sign_recoverable(hash : Bytes, seckey : Bytes)
    ctx = LibSecp256k1.context_create(LibSecp256k1::SECP256K1_CONTEXT_SIGN | LibSecp256k1::SECP256K1_CONTEXT_VERIFY)
    LibSecp256k1.context_randomize(ctx, random_bytes(32))
    
    signature = LibSecp256k1::EcdsaRecoverableSignature.new
    if (LibSecp256k1.ecdsa_sign_recoverable(ctx, pointerof(signature), hash, seckey, nil, nil) != 1)
      raise "Failed to sign recoverable"
    end

    output = Bytes.new(64)
    recid = Int32.new(0)
    if (LibSecp256k1.ecdsa_recoverable_signature_serialize_compact(ctx, output, pointerof(recid), pointerof(signature)) != 1)
      raise "Failed to serialize recoverable signature"
    end

    compact = IO::Memory.new
    compact.write(output)
    # recid = 3
    recid.to_u8.to_io(compact, IO::ByteFormat::LittleEndian)

    LibSecp256k1.context_destroy(ctx)

    compact.to_slice
  end

  # secp256k1_ecdsa_verify(ctx : Context, sig : EcdsaSignature*, msghash32 : UInt8*, pubkey : Pubkey*) : LibC::Int
  def verify(sig : Bytes, hash : Bytes, pubkey : Bytes) : Bool
    ctx = LibSecp256k1.context_create(LibSecp256k1::SECP256K1_CONTEXT_SIGN | LibSecp256k1::SECP256K1_CONTEXT_VERIFY)
    LibSecp256k1.context_randomize(ctx, random_bytes(32))

    signature = LibSecp256k1::EcdsaSignature.new
    if (LibSecp256k1.ecdsa_signature_parse_compact(ctx, pointerof(signature), sig) != 1)
      raise "Failed to parse signature"
    end

    pub = LibSecp256k1::Pubkey.new
    if (LibSecp256k1.ec_pubkey_parse(ctx, pointerof(pub), pubkey, pubkey.size) != 1)
      raise "Failed to parse pubkey"
    end

    result = LibSecp256k1.ecdsa_verify(ctx, pointerof(signature), hash, pointerof(pub))

    LibSecp256k1.context_destroy(ctx)

    result == 1 ? true : false
  end

  # secp256k1_ecdsa_recover(ctx : Context, pubkey : Pubkey*, sig : EcdsaRecoverableSignature*, msghash32 : UInt8*) : LibC::Int
  def recover(sig : Bytes, msghash32 : Bytes) : Bytes
    ctx = LibSecp256k1.context_create(LibSecp256k1::SECP256K1_CONTEXT_SIGN | LibSecp256k1::SECP256K1_CONTEXT_VERIFY)
    LibSecp256k1.context_randomize(ctx, random_bytes(32))

    recid = sig[64]
    signature = LibSecp256k1::EcdsaRecoverableSignature.new
    
    if (LibSecp256k1.ecdsa_recoverable_signature_parse_compact(ctx, pointerof(signature), sig, recid) != 1)
      raise "Failed to parse recoverable signature"
    end

    pubkey = LibSecp256k1::Pubkey.new
    if (LibSecp256k1.ecdsa_recover(ctx, pointerof(pubkey), pointerof(signature), msghash32) != 1)
      raise "Failed to recover pubkey"
    end

    compact = serialize_public_key(ctx, pubkey)
    LibSecp256k1.context_destroy(ctx)
    
    compact
  end
  
  def generate_private_key : Bytes
    seckey = Bytes.new(32)
    ctx = LibSecp256k1.context_create(LibSecp256k1::SECP256K1_CONTEXT_SIGN | LibSecp256k1::SECP256K1_CONTEXT_VERIFY)
    LibSecp256k1.context_randomize(ctx, random_bytes(32))

    loop do
      seckey = random_bytes(32)

      if (LibSecp256k1.ec_seckey_verify(ctx, seckey) == 1)
        break
      end
    end
    LibSecp256k1.context_destroy(ctx)

    seckey
  end 

  def generate_public_key(seckey) : Bytes
    ctx = LibSecp256k1.context_create(LibSecp256k1::SECP256K1_CONTEXT_SIGN | LibSecp256k1::SECP256K1_CONTEXT_VERIFY)
    LibSecp256k1.context_randomize(ctx, random_bytes(32))
    pubkey = LibSecp256k1::Pubkey.new

    if (LibSecp256k1.ec_pubkey_create(ctx, pointerof(pubkey), seckey) != 1)
      raise "Error creating public key"
    end

    compact = serialize_public_key(ctx, pubkey)
    LibSecp256k1.context_destroy(ctx)
    
    compact
  end

  private def serialize_public_key(ctx, pubkey)
    # ctx = LibSecp256k1.context_create(LibSecp256k1::SECP256K1_CONTEXT_SIGN | LibSecp256k1::SECP256K1_CONTEXT_VERIFY)
    # LibSecp256k1.context_randomize(ctx, random_bytes(32))
    output = Bytes.new(33)
    len = output.size.to_u64

    if (LibSecp256k1.ec_pubkey_serialize(ctx, output, pointerof(len), pointerof(pubkey), LibSecp256k1::SECP256K1_EC_COMPRESSED) != 1)
      raise "Error serializing public key"
    end

    # LibSecp256k1.context_destroy(ctx)
    output
  end

  def random_bytes(size) : Bytes
    Random::Secure.random_bytes(size)
  end

  def sha256(message : String, tag : String = "exarete") : Bytes
    sha256(message.to_slice, tag.to_slice)
  end

  def sha256(message : Bytes, tag : Bytes) : Bytes
    ctx = LibSecp256k1.context_create(LibSecp256k1::SECP256K1_CONTEXT_SIGN | LibSecp256k1::SECP256K1_CONTEXT_VERIFY)
    LibSecp256k1.context_randomize(ctx, random_bytes(32))
    hash = Bytes.new(32)
    res = LibSecp256k1.tagged_sha256(ctx, hash, tag, tag.size, message, message.size)
    raise "Error hashing message" unless res == 1
    LibSecp256k1.context_destroy(ctx)

    hash
  end
end