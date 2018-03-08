{-# LANGUAGE TypeApplications  #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE UndecidableInstances #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Test.Orphans
    (
    ) where

import Foundation
import Foundation.Parser (elements, ParseError(..), reportError, takeAll)
import Basement.Nat
import Basement.String.Builder (emit, emitChar)

import Basement.Block (Block)

import Inspector

import Crypto.Error

import Data.ByteArray (Bytes, convert)
import Data.ByteString (ByteString)

import qualified Cardano.Crypto.Encoding.Seed as Seed
import qualified Crypto.ECC.P256 as P256
import qualified Cardano.Crypto.Wallet.Types as Wallet
import qualified Cardano.Crypto.Wallet       as Wallet
import qualified Crypto.DLEQ as DLEQ
import qualified Cardano.Crypto.Praos.VRF as VRF
import qualified Crypto.Encoding.BIP39 as BIP39

instance Inspectable Seed.ScrambleIV where
    parser _ = do
        bs <- parser Proxy
        case Seed.mkScrambleIV bs of
            CryptoFailed err -> reportError (Expected "ScrambleIV" (show err))
            CryptoPassed r   -> pure r
    documentation _ = "hexadecimal encoded bytes"
    exportType _ Rust = emit "[u8;4]"
    exportType _ t    = exportType (Proxy @(Block Word8)) t
    display t = display t . (convert :: Seed.ScrambleIV -> Block Word8)

instance Inspectable P256.Scalar where
    parser _ = P256.Scalar <$> parser Proxy
    documentation _ = documentation (Proxy @Integer)
    exportType _ = exportType (Proxy @Integer)
    display t = display t . P256.unScalar

instance Inspectable Wallet.DerivationScheme where
    documentation _ = "DerivationScheme: either 'derivation-scheme1' or 'derivation-scheme2'"
    exportType _ =  exportType (Proxy @String)
    parser _ = (elements "\"derivation-scheme1\"" >> pure Wallet.DerivationScheme1)
           <|> (elements "\"derivation-scheme2\"" >> pure Wallet.DerivationScheme2)
           <|> (takeAll >>= reportError . Expected "'derivation-scheme1' or 'derivation-scheme2'")
    display _ Wallet.DerivationScheme1 = emit "\"derivation-scheme1\""
    display _ Wallet.DerivationScheme2 = emit "\"derivation-scheme2\""

instance Inspectable Wallet.XPub where
    parser _ = do
        b <- parser Proxy
        case Wallet.xpub b of
            Left err -> reportError $ Expected "XPub" (fromList err)
            Right e  -> pure e
    documentation _ = "hexadecimal encoded bytes"
    exportType _ = exportType (Proxy @(Block Word8))
    display t = display t . Wallet.unXPub

instance Inspectable Wallet.XPrv where
    parser _ = do
        b <- parser Proxy
        case Wallet.xprv (b :: Bytes) of
            Left err -> reportError $ Expected "XPrv" (fromList err)
            Right e  -> pure e
    documentation _ = "hexadecimal encoded bytes"
    exportType _ = exportType (Proxy @(Block Word8))
    display t = display t . (convert :: Wallet.XPrv -> Block Word8)

instance Inspectable Wallet.XSignature where
    parser _ = do
        b <- parser Proxy
        case Wallet.xsignature b of
            Left err -> reportError $ Expected "XSignature" (fromList err)
            Right e  -> pure e
    documentation _ = "hexadecimal encoded bytes"
    exportType _ = exportType (Proxy @(Block Word8))
    display t = display t . (convert :: Wallet.XSignature -> Block Word8)

instance Inspectable DLEQ.Challenge where
    documentation _ = "hexadecimal encoded bytes"
    display t (DLEQ.Challenge c) = display t c
    exportType _ = exportType (Proxy @(Block Word8))
    parser _ = DLEQ.Challenge <$> parser Proxy

instance Inspectable DLEQ.Proof where
    documentation _ = "tuple of a challenge key and a `z`"
    exportType _ t = emitChar '(' <> exportType (Proxy @DLEQ.Challenge) t <> emit ", " <> exportType (Proxy @P256.Scalar) t <> emitChar ')'
    display Rust (DLEQ.Proof u dleq) = emit "(" <> display Rust u <> emit ", " <> display Rust dleq <> emit ")"
    display t    (DLEQ.Proof u dleq) = emit "challenge: " <> display t u <> emit ", z: " <> display t dleq
    parser _ = do
        elements "challenge: "
        c <- parser Proxy
        elements ", z: "
        DLEQ.Proof c <$> parser Proxy

instance Inspectable VRF.SecretKey where
    documentation _ = "hexadecimal encoded bytes"
    exportType _ = exportType (Proxy @(Block Word8))
    display t = display t . (VRF.secretKeyToBytes :: VRF.SecretKey -> Block Word8)
    parser _ = VRF.secretKeyFromBytes <$> parser (Proxy @(Block Word8))

instance Inspectable VRF.PublicKey where
    documentation _ = "hexadecimal encoded bytes"
    exportType _ = exportType (Proxy @(Block Word8))
    display t = display t . (VRF.publicKeyToBytes :: VRF.PublicKey -> Block Word8)
    parser _ = do
        b <- parser (Proxy @(Block Word8))
        case VRF.publicKeyFromBytes (b :: Block Word8) of
            Left err -> reportError $ Expected "VRF.PublicKey" (fromList err)
            Right v -> pure v

instance Inspectable VRF.Proof where
    documentation _ = "tuple of a public key and a DLEQ Proof"
    exportType _ Rust = emitChar '(' <> exportType (Proxy @VRF.PublicKey) Rust <> emit ", " <> exportType (Proxy @DLEQ.Proof) Rust <> emitChar ')'
    exportType _ t    = exportType (Proxy @(Block Word8)) t
    parser _ = do
        elements "u: "
        u <- parser Proxy
        elements ", "
        VRF.Proof u <$> parser Proxy
    display Rust (VRF.Proof u dleq) = emit "(" <> display Rust u <> emit ", " <> display Rust dleq <> emit ")"
    display t    (VRF.Proof u dleq) = emit "u: " <> display t    u <> emit ", " <> display t dleq

instance (BIP39.ValidEntropySize n, BIP39.ValidChecksumSize n csz) => Inspectable (BIP39.Entropy n) where
    documentation _ = "hexadecimal encoded bytes"
    display t = display t . BIP39.entropyRaw
    exportType _ = exportType (Proxy @(Block Word8))
    parser _ = do
        bs <- parser (Proxy @(Block Word8))
        case BIP39.toEntropy  @n bs of
            Nothing -> reportError (Expected "Entropy" "not the correct size, or invalid checksum")
            Just r  -> pure r
instance Inspectable BIP39.Seed where
    documentation _ = "hexadecimal encoded bytes"
    exportType _ = exportType (Proxy @(Block Word8))
    parser _ = convert <$> parser (Proxy @(Block Word8))
    display t = display t . (convert :: BIP39.Seed -> Block Word8)
instance Inspectable ByteString where
    documentation _ = "hexadecimal encoded bytes"
    exportType _ = exportType (Proxy @(Block Word8))
    parser _ = convert <$> parser (Proxy @(Block Word8))
    display t = display t . (convert :: ByteString -> Block Word8)
