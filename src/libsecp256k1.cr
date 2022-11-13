# TODO: Write documentation for `Libsecp256k1`
@[Link("secp256k1")]
lib LibSecp256k1
  # All flags' lower 8 bits indicate what they're for. Do not use directly.
  SECP256K1_FLAGS_TYPE_MASK               = ((1 << 8) - 1)
  SECP256K1_FLAGS_TYPE_CONTEXT            = (1 << 0)
  SECP256K1_FLAGS_TYPE_COMPRESSION        = (1 << 1)
  
  # The higher bits contain the actual data. Do not use directly.
  SECP256K1_FLAGS_BIT_CONTEXT_VERIFY      = (1 << 8)
  SECP256K1_FLAGS_BIT_CONTEXT_SIGN        = (1 << 9)
  SECP256K1_FLAGS_BIT_CONTEXT_DECLASSIFY  = (1 << 10)
  SECP256K1_FLAGS_BIT_COMPRESSION         = (1 << 8)

  # Flags to pass to secp256k1_context_create, secp256k1_context_preallocated_size, and
  # secp256k1_context_preallocated_create.
  SECP256K1_CONTEXT_VERIFY      = (SECP256K1_FLAGS_TYPE_CONTEXT | SECP256K1_FLAGS_BIT_CONTEXT_VERIFY)
  SECP256K1_CONTEXT_SIGN        = (SECP256K1_FLAGS_TYPE_CONTEXT | SECP256K1_FLAGS_BIT_CONTEXT_SIGN)
  SECP256K1_CONTEXT_DECLASSIFY  = (SECP256K1_FLAGS_TYPE_CONTEXT | SECP256K1_FLAGS_BIT_CONTEXT_DECLASSIFY)
  SECP256K1_CONTEXT_NONE        = (SECP256K1_FLAGS_TYPE_CONTEXT)

  # Flag to pass to secp256k1_ec_pubkey_serialize.
  SECP256K1_EC_COMPRESSED       = (SECP256K1_FLAGS_TYPE_COMPRESSION | SECP256K1_FLAGS_BIT_COMPRESSION)
  SECP256K1_EC_UNCOMPRESSED     = (SECP256K1_FLAGS_TYPE_COMPRESSION)
  
  TAG_PUBKEY_EVEN = 2
  TAG_PUBKEY_ODD = 3
  TAG_PUBKEY_UNCOMPRESSED = 4
  TAG_PUBKEY_HYBRID_EVEN = 6
  TAG_PUBKEY_HYBRID_ODD = 7
  alias ContextStruct = Void
  alias ScratchSpaceStruct = Void
  type Context = Void*
  fun context_create = secp256k1_context_create(flags : LibC::UInt) : Context
  fun context_clone = secp256k1_context_clone(ctx : Context) : Context
  fun context_destroy = secp256k1_context_destroy(ctx : Context)
  fun context_set_illegal_callback = secp256k1_context_set_illegal_callback(ctx : Context, fun : (LibC::Char*, Void* -> Void), data : Void*)
  fun context_set_error_callback = secp256k1_context_set_error_callback(ctx : Context, fun : (LibC::Char*, Void* -> Void), data : Void*)
  fun scratch_space_create = secp256k1_scratch_space_create(ctx : Context, size : LibC::SizeT) : ScratchSpace
  type ScratchSpace = Void*
  fun scratch_space_destroy = secp256k1_scratch_space_destroy(ctx : Context, scratch : ScratchSpace)
  fun ec_pubkey_parse = secp256k1_ec_pubkey_parse(ctx : Context, pubkey : Pubkey*, input : UInt8*, inputlen : LibC::SizeT) : LibC::Int
  struct Pubkey
    data : UInt8[64]
  end
  fun ec_pubkey_serialize = secp256k1_ec_pubkey_serialize(ctx : Context, output : UInt8*, outputlen : LibC::SizeT*, pubkey : Pubkey*, flags : LibC::UInt) : LibC::Int
  fun ec_pubkey_cmp = secp256k1_ec_pubkey_cmp(ctx : Context, pubkey1 : Pubkey*, pubkey2 : Pubkey*) : LibC::Int
  fun ecdsa_signature_parse_compact = secp256k1_ecdsa_signature_parse_compact(ctx : Context, sig : EcdsaSignature*, input64 : UInt8*) : LibC::Int
  struct EcdsaSignature
    data : UInt8[64]
  end
  fun ecdsa_signature_parse_der = secp256k1_ecdsa_signature_parse_der(ctx : Context, sig : EcdsaSignature*, input : UInt8*, inputlen : LibC::SizeT) : LibC::Int
  fun ecdsa_signature_serialize_der = secp256k1_ecdsa_signature_serialize_der(ctx : Context, output : UInt8*, outputlen : LibC::SizeT*, sig : EcdsaSignature*) : LibC::Int
  fun ecdsa_signature_serialize_compact = secp256k1_ecdsa_signature_serialize_compact(ctx : Context, output64 : UInt8*, sig : EcdsaSignature*) : LibC::Int
  fun ecdsa_verify = secp256k1_ecdsa_verify(ctx : Context, sig : EcdsaSignature*, msghash32 : UInt8*, pubkey : Pubkey*) : LibC::Int
  fun ecdsa_signature_normalize = secp256k1_ecdsa_signature_normalize(ctx : Context, sigout : EcdsaSignature*, sigin : EcdsaSignature*) : LibC::Int
  alias NonceFunction = (UInt8*, UInt8*, UInt8*, UInt8*, Void*, LibC::UInt -> LibC::Int)
  fun ecdsa_sign = secp256k1_ecdsa_sign(ctx : Context, sig : EcdsaSignature*, msghash32 : UInt8*, seckey : UInt8*, noncefp : NonceFunction, ndata : Void*) : LibC::Int
  fun ec_seckey_verify = secp256k1_ec_seckey_verify(ctx : Context, seckey : UInt8*) : LibC::Int
  fun ec_pubkey_create = secp256k1_ec_pubkey_create(ctx : Context, pubkey : Pubkey*, seckey : UInt8*) : LibC::Int
  fun ec_seckey_negate = secp256k1_ec_seckey_negate(ctx : Context, seckey : UInt8*) : LibC::Int
  fun ec_privkey_negate = secp256k1_ec_privkey_negate(ctx : Context, seckey : UInt8*) : LibC::Int
  fun ec_pubkey_negate = secp256k1_ec_pubkey_negate(ctx : Context, pubkey : Pubkey*) : LibC::Int
  fun ec_seckey_tweak_add = secp256k1_ec_seckey_tweak_add(ctx : Context, seckey : UInt8*, tweak32 : UInt8*) : LibC::Int
  fun ec_privkey_tweak_add = secp256k1_ec_privkey_tweak_add(ctx : Context, seckey : UInt8*, tweak32 : UInt8*) : LibC::Int
  fun ec_pubkey_tweak_add = secp256k1_ec_pubkey_tweak_add(ctx : Context, pubkey : Pubkey*, tweak32 : UInt8*) : LibC::Int
  fun ec_seckey_tweak_mul = secp256k1_ec_seckey_tweak_mul(ctx : Context, seckey : UInt8*, tweak32 : UInt8*) : LibC::Int
  fun ec_privkey_tweak_mul = secp256k1_ec_privkey_tweak_mul(ctx : Context, seckey : UInt8*, tweak32 : UInt8*) : LibC::Int
  fun ec_pubkey_tweak_mul = secp256k1_ec_pubkey_tweak_mul(ctx : Context, pubkey : Pubkey*, tweak32 : UInt8*) : LibC::Int
  fun context_randomize = secp256k1_context_randomize(ctx : Context, seed32 : UInt8*) : LibC::Int
  fun ec_pubkey_combine = secp256k1_ec_pubkey_combine(ctx : Context, out : Pubkey*, ins : Pubkey**, n : LibC::SizeT) : LibC::Int
  fun tagged_sha256 = secp256k1_tagged_sha256(ctx : Context, hash32 : UInt8*, tag : UInt8*, taglen : LibC::SizeT, msg : UInt8*, msglen : LibC::SizeT) : LibC::Int
  alias EcdhHashFunction = (UInt8*, UInt8*, UInt8*, Void* -> LibC::Int)
  fun ecdh = secp256k1_ecdh(ctx : Context, output : UInt8*, pubkey : Pubkey*, seckey : UInt8*, hashfp : EcdhHashFunction, data : Void*) : LibC::Int
  fun xonly_pubkey_parse = secp256k1_xonly_pubkey_parse(ctx : Context, pubkey : XonlyPubkey*, input32 : UInt8*) : LibC::Int
  struct XonlyPubkey
    data : UInt8[64]
  end
  fun xonly_pubkey_serialize = secp256k1_xonly_pubkey_serialize(ctx : Context, output32 : UInt8*, pubkey : XonlyPubkey*) : LibC::Int
  fun xonly_pubkey_cmp = secp256k1_xonly_pubkey_cmp(ctx : Context, pk1 : XonlyPubkey*, pk2 : XonlyPubkey*) : LibC::Int
  fun xonly_pubkey_from_pubkey = secp256k1_xonly_pubkey_from_pubkey(ctx : Context, xonly_pubkey : XonlyPubkey*, pk_parity : LibC::Int*, pubkey : Pubkey*) : LibC::Int
  fun xonly_pubkey_tweak_add = secp256k1_xonly_pubkey_tweak_add(ctx : Context, output_pubkey : Pubkey*, internal_pubkey : XonlyPubkey*, tweak32 : UInt8*) : LibC::Int
  fun xonly_pubkey_tweak_add_check = secp256k1_xonly_pubkey_tweak_add_check(ctx : Context, tweaked_pubkey32 : UInt8*, tweaked_pk_parity : LibC::Int, internal_pubkey : XonlyPubkey*, tweak32 : UInt8*) : LibC::Int
  fun keypair_create = secp256k1_keypair_create(ctx : Context, keypair : Keypair*, seckey : UInt8*) : LibC::Int
  struct Keypair
    data : UInt8[96]
  end
  fun keypair_sec = secp256k1_keypair_sec(ctx : Context, seckey : UInt8*, keypair : Keypair*) : LibC::Int
  fun keypair_pub = secp256k1_keypair_pub(ctx : Context, pubkey : Pubkey*, keypair : Keypair*) : LibC::Int
  fun keypair_xonly_pub = secp256k1_keypair_xonly_pub(ctx : Context, pubkey : XonlyPubkey*, pk_parity : LibC::Int*, keypair : Keypair*) : LibC::Int
  fun keypair_xonly_tweak_add = secp256k1_keypair_xonly_tweak_add(ctx : Context, keypair : Keypair*, tweak32 : UInt8*) : LibC::Int
  fun context_preallocated_size = secp256k1_context_preallocated_size(flags : LibC::UInt) : LibC::SizeT
  fun context_preallocated_create = secp256k1_context_preallocated_create(prealloc : Void*, flags : LibC::UInt) : Context
  fun context_preallocated_clone_size = secp256k1_context_preallocated_clone_size(ctx : Context) : LibC::SizeT
  fun context_preallocated_clone = secp256k1_context_preallocated_clone(ctx : Context, prealloc : Void*) : Context
  fun context_preallocated_destroy = secp256k1_context_preallocated_destroy(ctx : Context)
  fun ecdsa_recoverable_signature_parse_compact = secp256k1_ecdsa_recoverable_signature_parse_compact(ctx : Context, sig : EcdsaRecoverableSignature*, input64 : UInt8*, recid : LibC::Int) : LibC::Int
  struct EcdsaRecoverableSignature
    data : UInt8[65]
  end
  fun ecdsa_recoverable_signature_convert = secp256k1_ecdsa_recoverable_signature_convert(ctx : Context, sig : EcdsaSignature*, sigin : EcdsaRecoverableSignature*) : LibC::Int
  fun ecdsa_recoverable_signature_serialize_compact = secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx : Context, output64 : UInt8*, recid : LibC::Int*, sig : EcdsaRecoverableSignature*) : LibC::Int
  fun ecdsa_sign_recoverable = secp256k1_ecdsa_sign_recoverable(ctx : Context, sig : EcdsaRecoverableSignature*, msghash32 : UInt8*, seckey : UInt8*, noncefp : NonceFunction, ndata : Void*) : LibC::Int
  fun ecdsa_recover = secp256k1_ecdsa_recover(ctx : Context, pubkey : Pubkey*, sig : EcdsaRecoverableSignature*, msghash32 : UInt8*) : LibC::Int
  alias NonceFunctionHardened = (UInt8*, UInt8*, LibC::SizeT, UInt8*, UInt8*, UInt8*, LibC::SizeT, Void* -> LibC::Int)
  fun schnorrsig_sign = secp256k1_schnorrsig_sign(ctx : Context, sig64 : UInt8*, msg32 : UInt8*, keypair : Keypair*, aux_rand32 : UInt8*) : LibC::Int
  fun schnorrsig_sign_custom = secp256k1_schnorrsig_sign_custom(ctx : Context, sig64 : UInt8*, msg : UInt8*, msglen : LibC::SizeT, keypair : Keypair*, extraparams : SchnorrsigExtraparams*) : LibC::Int
  struct SchnorrsigExtraparams
    magic : UInt8[4]
    noncefp : NonceFunctionHardened
    ndata : Void*
  end
  fun schnorrsig_verify = secp256k1_schnorrsig_verify(ctx : Context, sig64 : UInt8*, msg : UInt8*, msglen : LibC::SizeT, pubkey : XonlyPubkey*) : LibC::Int
  $context_no_precomp : Context
  $nonce_function_rfc6979 : NonceFunction
  $nonce_function_default : NonceFunction
  $ecdh_hash_function_sha256 : EcdhHashFunction
  $ecdh_hash_function_default : EcdhHashFunction
  $nonce_function_bip340 : NonceFunctionHardened
end

require "./secp256k1"

# module LibSecp256k1
#   VERSION = "0.1.0"
#   # TODO: Put your code here
# end
