require "./spec_helper"

describe Secp256k1 do
  context "key gen" do
    it "gens new private key" do
      seckey = Secp256k1.generate_private_key
      seckey.should be_a(Bytes)
      seckey.size.should eq(32)
    end

    it "gens pub key" do
      seckey = "a76287f61affecccf6c0c1aaec787ddb7268c424e3e4f0714a2efb1dd363d0a4"
      pubkey = Secp256k1.generate_public_key(seckey.hexbytes)

      pubkey.should be_a(Bytes)
      pubkey.size.should eq(33)

      pubkey.hexstring.should eq("02c1e6bf97233b8cce8fd577531ed25e3ac19037ee7be757bb7ac12dea99e02706")
    end
  end

  context "sign recoverable" do
    it "signs the message" do
      seckey = "a76287f61affecccf6c0c1aaec787ddb7268c424e3e4f0714a2efb1dd363d0a4"
      message = "hello world"
      hash = Secp256k1.sha256(message)
      
      signature = Secp256k1.sign_recoverable(hash, seckey.hexbytes)

      signature.hexstring.should eq("586e0bc614b46c8b653a7c5b619fcf9d42d7959ac98b1bf8dfd88b28865b2a9e60625a0bf2dd6c9ee26d7d7ca384206fd46aa1d9db1eac710621db60075e516900")
    end

    it "recovers pubkey from the signature" do
      signature = "586e0bc614b46c8b653a7c5b619fcf9d42d7959ac98b1bf8dfd88b28865b2a9e60625a0bf2dd6c9ee26d7d7ca384206fd46aa1d9db1eac710621db60075e516900"
      seckey = "a76287f61affecccf6c0c1aaec787ddb7268c424e3e4f0714a2efb1dd363d0a4"
      message = "hello world"
      hash = Secp256k1.sha256(message)
      pubkey = Secp256k1.recover(signature.hexbytes, hash)
      
      pubkey.hexstring.should eq("02c1e6bf97233b8cce8fd577531ed25e3ac19037ee7be757bb7ac12dea99e02706")
    end

    it "verifies the signature" do
      signature = "586e0bc614b46c8b653a7c5b619fcf9d42d7959ac98b1bf8dfd88b28865b2a9e60625a0bf2dd6c9ee26d7d7ca384206fd46aa1d9db1eac710621db60075e516900"
      pubkey = "02c1e6bf97233b8cce8fd577531ed25e3ac19037ee7be757bb7ac12dea99e02706"
      message = "hello world"
      hash = Secp256k1.sha256(message)
      
      Secp256k1.verify(signature.hexbytes, hash, pubkey.hexbytes).should be_true
    end
  end

  context "sha256" do
    it "works" do
      Secp256k1.sha256("hello").hexstring.should eq("e9cf0bd8cbd696bf315a9dc40651808a2b89c127a265e41520c0e4911f0a5a74")
    end

    it "works as in lib" do
      expected_hash = Bytes[
        0x04, 0x7A, 0x5E, 0x17, 0xB5, 0x86, 0x47, 0xC1,
        0x3C, 0xC6, 0xEB, 0xC0, 0xAA, 0x58, 0x3B, 0x62,
        0xFB, 0x16, 0x43, 0x32, 0x68, 0x77, 0x40, 0x6C,
        0xE2, 0x76, 0x55, 0x9A, 0x3B, 0xDE, 0x55, 0xB3
      ]

      Secp256k1.sha256("msg", "tag").should eq(expected_hash)
    end
  end
end
