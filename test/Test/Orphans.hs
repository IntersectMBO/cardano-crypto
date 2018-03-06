{-# LANGUAGE TypeApplications  #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE UndecidableInstances #-}

module Test.Orphans
    (
    ) where

import Foundation
import Foundation.Parser (elements)
import Basement.Nat

import Inspector.Display
import Inspector.Parser

import Crypto.Error

import Data.ByteArray (Bytes)
import Data.ByteString (ByteString)

import qualified Cardano.Crypto.Encoding.Seed as Seed
import qualified Crypto.ECC.P256 as P256
import qualified Cardano.Crypto.Wallet.Types as Wallet
import qualified Cardano.Crypto.Wallet       as Wallet
import qualified Crypto.DLEQ as DLEQ
import qualified Cardano.Crypto.Praos.VRF as VRF
import qualified Crypto.Encoding.BIP39 as BIP39

instance Display Seed.ScrambleIV where
    display = displayByteArrayAccess
    encoding _ = "hexadecimal"
    comment _ = Just "valid value are only 4 bytes long (8 hexadecimal characters)"
instance HasParser Seed.ScrambleIV where
    getParser = do
        bs <- strParser >>= parseByteArray
        case Seed.mkScrambleIV bs of
            CryptoFailed err -> reportError (Expected "ScrambleIV" (show err))
            CryptoPassed r   -> pure r

instance HasParser P256.Scalar where
    getParser = P256.Scalar <$> getParser
instance Display P256.Scalar where
    encoding _ = encoding (Proxy @Integer)
    display = display . P256.unScalar

instance Display Wallet.DerivationScheme where
    encoding _ = "string \"derivation-scheme1\""
    display Wallet.DerivationScheme1 = "\"derivation-scheme1\""
    display Wallet.DerivationScheme2 = "\"derivation-scheme2\""
    comment _ = Just "valid values are: \"derivation-scheme1\" or \"derivation-scheme2\""
instance HasParser Wallet.DerivationScheme where
    getParser = do
        str <- strParser
        case str of
            "derivation-scheme1" -> pure Wallet.DerivationScheme1
            "derivation-scheme2" -> pure Wallet.DerivationScheme2
            s                    -> reportError (Expected "derivation-scheme1 or derivation-scheme2" s)

instance Display Wallet.XPub where
    display = displayByteArrayAccess . Wallet.unXPub
    encoding _ = "hexadecimal"
    comment _ = Just "extended public key"
instance HasParser Wallet.XPub where
    getParser = strParser >>= parseByteArray >>= \s -> case Wallet.xpub s of
        Left err -> reportError $ Expected "xPub" (fromList err)
        Right e  -> pure e

instance Display Wallet.XPrv where
    display = displayByteArrayAccess
    encoding _ = "hexadecimal"
    comment _ = Just "encrypted extended private key"
instance HasParser Wallet.XPrv where
    getParser = strParser >>= parseByteArray >>= \s -> case Wallet.xprv (s :: Bytes) of
        Left err -> reportError $ Expected "xPrv" (fromList err)
        Right e  -> pure e

instance Display Wallet.XSignature where
    display = displayByteArrayAccess
    encoding _ = "hexadecimal"
    comment _ = Just "extended signature"
instance HasParser Wallet.XSignature where
    getParser = strParser >>= parseByteArray >>= \s -> case Wallet.xsignature s of
        Left err -> reportError $ Expected "XSignature" (fromList err)
        Right e  -> pure e

instance HasParser DLEQ.Challenge where
    getParser = DLEQ.Challenge <$> getParser
instance Display DLEQ.Challenge where
    encoding _ = "hex"
    display (DLEQ.Challenge c) = display c

instance HasParser DLEQ.Proof where
    getParser = do
        elements "challenge: "
        c <- getParser
        elements ", z: "
        DLEQ.Proof c <$> getParser
instance Display DLEQ.Proof where
    encoding _ = "challenge: " <> encoding (Proxy @DLEQ.Challenge) <> ", z: " <> encoding (Proxy @P256.Scalar)
    display (DLEQ.Proof c z) = "challenge: " <> display c <> ", z: " <> display z

instance HasParser VRF.SecretKey where
    getParser = c <$> getParser
      where
        c :: Bytes -> VRF.SecretKey
        c = VRF.secretKeyFromBytes
instance Display VRF.SecretKey where
    encoding _ = "hex"
    display = display . (VRF.secretKeyToBytes :: VRF.SecretKey -> Bytes)

instance HasParser VRF.PublicKey where
    getParser = c <$> getParser
      where
        c :: Bytes -> VRF.PublicKey
        c = either (error . fromList) id . VRF.publicKeyFromBytes
instance Display VRF.PublicKey where
    display = display . (VRF.publicKeyToBytes :: VRF.PublicKey -> Bytes)
    encoding _ = "hex"

instance HasParser VRF.Proof where
    getParser = do
        elements "u: "
        u <- getParser
        elements ", "
        VRF.Proof u <$> getParser
instance Display VRF.Proof where
    encoding _ = "u: `Public Key`, " <> encoding (Proxy :: Proxy DLEQ.Proof)
    display (VRF.Proof u dleq) = "u: " <> display u <> ", " <> display dleq

instance Display (BIP39.Entropy n) where
    display = displayByteArrayAccess . BIP39.entropyRaw
    encoding _ = "hexadecimal"
instance (KnownNat n, KnownNat csz, NatWithinBound Int n, BIP39.ValidEntropySize n, BIP39.CheckSumBits n ~ csz) => HasParser (BIP39.Entropy n) where
    getParser = do
        bs <- strParser >>= parseByteArray
        case BIP39.toEntropy bs of
            Nothing -> reportError (Expected "Entropy" "not the correct size")
            Just r  -> pure r
instance Display ByteString where
    display = displayByteArrayAccess
    encoding _ = "hexadecimal"
instance HasParser ByteString where
    getParser = strParser >>= parseByteArray
