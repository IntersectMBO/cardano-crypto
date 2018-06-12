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

import Inspector
import qualified Inspector.TestVector.Types as Type
import qualified Inspector.TestVector.Value as Value

import Crypto.Error

import Data.ByteArray (Bytes, convert, ByteArrayAccess)
import Data.ByteString (ByteString)

import qualified Cardano.Crypto.Encoding.Seed as Seed
import qualified Crypto.ECC.P256 as P256
import qualified Cardano.Crypto.Wallet.Types as Wallet
import qualified Cardano.Crypto.Wallet       as Wallet
import qualified Crypto.DLEQ as DLEQ
import qualified Cardano.Crypto.Praos.VRF as VRF
import qualified Crypto.Encoding.BIP39 as BIP39

toBytes :: ByteArrayAccess ba => ba -> Bytes
toBytes = convert

instance Inspectable Seed.ScrambleIV where
    documentation _ = "Seed scramble IV of 8 bytes"
    exportType    _ = Type.Array $ Type.SizedArray Type.Unsigned8 8
    builder         = builder . toBytes
    parser        v = do
        bs <- parser v :: Either String ByteString
        case Seed.mkScrambleIV bs of
            CryptoFailed err -> Left $ "Expected a `ScrambleIV'" <> show err
            CryptoPassed r   -> pure r

instance Inspectable P256.Scalar where
    documentation _ = "P256 Scalar"
    exportType    _ = Type.Array $ Type.UnsizedArray Type.Unsigned8
    builder         = builder . (P256.scalarToBytes :: P256.Scalar -> Bytes)
    parser        v = P256.keyFromBytes <$> (parser v :: Either String Bytes)

instance Inspectable Wallet.DerivationScheme where
    documentation _ = "Wallet's derivation schemes: String either \"derivation-scheme1\" or \"derivation-scheme2\""
    exportType    _ = Type.String
    builder Wallet.DerivationScheme1 = Value.String "derivation-scheme1"
    builder Wallet.DerivationScheme2 = Value.String "derivation-scheme2"
    parser          = withString "DerivationScheme" $ \str -> case str of
        "derivation-scheme1" -> pure Wallet.DerivationScheme1
        "derivation-scheme2" -> pure Wallet.DerivationScheme2
        _                    -> Left $ "Expected either `derivation-scheme1' or `derivation-scheme2' but found: `" <> str <> "'"

instance Inspectable Wallet.XPub where
    documentation _ = "Wallet's extended public key"
    exportType    _ = Type.Array $ Type.SizedArray Type.Unsigned8 64
    builder         = builder . Wallet.unXPub
    parser        v = do
        bs <- parser v :: Either String ByteString
        case Wallet.xpub bs of
            Left err -> Left $ "Expected `xPub' " <> fromList err
            Right e  -> pure e

instance Inspectable Wallet.XPrv where
    documentation _ = "Wallet's extended private key"
    exportType    _ = Type.Array $ Type.SizedArray Type.Unsigned8 96
    builder         = builder . Wallet.unXPrv
    parser        v = do
        bs <- parser v :: Either String ByteString
        case Wallet.xprv bs of
            Left err -> Left $ "Expected `xPrv' " <> fromList err
            Right e  -> pure e

instance Inspectable Wallet.XSignature where
    documentation _ = "Wallet's extended signature"
    exportType    _ = Type.Array $ Type.SizedArray Type.Unsigned8 64
    builder         = builder . toBytes
    parser        v = do
        bs <- parser v :: Either String ByteString
        case Wallet.xsignature bs of
            Left err -> Left $ "Expected `xPrv' " <> fromList err
            Right e  -> pure e

instance Inspectable DLEQ.Challenge where
    documentation _ = "DLEQ's Challenge"
    exportType    _ = Type.Array $ Type.UnsizedArray Type.Unsigned8
    builder         = builder . toBytes
    parser        v = DLEQ.Challenge <$> parser v

instance Inspectable DLEQ.Proof where
    documentation _ = "DLEQ's Proof"
    exportType    _ = Type.Object $ Type.ObjectDef
        [ ( "challenge", exportType (Proxy @DLEQ.Challenge))
        , ( "z",         exportType (Proxy @P256.Scalar))
        ]
    builder (DLEQ.Proof challenge z) = Value.Object $ Value.ObjectDef
        [ ( "challenge", builder challenge)
        , ( "z",         builder z)
        ]
    parser          = withStructure "DLEQ Proof" $ \obj -> do
        challenge <- parser =<< field obj "challenge"
        z         <- parser =<< field obj "z"
        pure $ DLEQ.Proof challenge z

instance Inspectable VRF.SecretKey where
    documentation _ = "VRF's secret key"
    exportType    _ = Type.Array $ Type.UnsizedArray Type.Unsigned8
    builder         = builder . (VRF.secretKeyToBytes :: VRF.SecretKey -> Bytes)
    parser        v = c <$> parser v
      where
        c :: Bytes -> VRF.SecretKey
        c = VRF.secretKeyFromBytes

instance Inspectable VRF.PublicKey where
    documentation _ = "VRF's public key"
    exportType    _ = Type.Array $ Type.UnsizedArray Type.Unsigned8
    builder         = builder . (VRF.publicKeyToBytes :: VRF.PublicKey -> Bytes)
    parser        v = c =<< parser v
      where
        c :: Bytes -> Either String VRF.PublicKey
        c bs = fromList `first` VRF.publicKeyFromBytes bs

instance Inspectable VRF.Proof where
    documentation _ = "VRF's Proof"
    exportType    _ = Type.Object $ Type.ObjectDef
        [ ( "pk",   exportType (Proxy @VRF.PublicKey))
        , ( "dleq", exportType (Proxy @DLEQ.Proof))
        ]
    builder (VRF.Proof pk dleq) = Value.Object $ Value.ObjectDef
        [ ( "pk",   builder pk)
        , ( "dleq", builder dleq)
        ]
    parser          = withStructure "VRF Proof" $ \obj -> do
        pk   <- parser =<< field obj "pk"
        dleq <- parser =<< field obj "dleq"
        pure $ VRF.Proof pk dleq

instance (BIP39.ValidEntropySize n, BIP39.ValidChecksumSize n csz) => Inspectable (BIP39.Entropy n) where
    documentation _ = "BIP39 Entropy"
    exportType    _ = Type.Array $ Type.UnsizedArray Type.Unsigned8
    builder         = builder . BIP39.entropyRaw
    parser v = do
        bs <- parser v
        case BIP39.toEntropy (bs :: Bytes) of
            Nothing -> Left "Expected `Entropy' not the correct size"
            Just r  -> pure r

instance Inspectable BIP39.Seed where
    documentation _ = "BIP39 Seed"
    exportType    _ = Type.Array $ Type.UnsizedArray Type.Unsigned8
    builder         = builder . toBytes
    parser        v = convert <$> (parser v :: Either String ByteString)

instance Inspectable ByteString where
    documentation _ = "Some random bytes"
    exportType    _ = Type.Array $ Type.UnsizedArray Type.Unsigned8
    builder         = builder . toBytes
    parser        v = convert <$> (parser v :: Either String Bytes)
