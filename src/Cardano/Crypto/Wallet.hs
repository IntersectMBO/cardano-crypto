-- |
-- Module      : Cardano.Crypto.Wallet
-- Description : HD Wallet routines
-- Maintainer  : vincent@typed.io
--
-- This provide similar functionality than BIP32 but using
-- Ed25519 arithmetic instead of P256K1 arithmethic.
--
-- Key can be hierarchically derived from private key in two
-- fashion: Hardened or Normal.
--
-- In the hardened scheme, the child secret key is not linearly
-- derived, so that the child public key have no way
-- to be efficiently computed from the parent public key.
--
-- The normal scheme, allows anyone to derive public keys from
-- public key.
--
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
module Cardano.Crypto.Wallet
    ( ChainCode(..)
    -- * Extended Private & Public types
    , XPrv
    , XPub
    , XSignature
    , generate
    , xprv
    , xpub
    , unXPrv
    , unXPub
    , toXPub
    , xPubGetPublicKey
    -- * Derivation function
    , deriveXPrvHardened
    , deriveXPrv
    , deriveXPub
    -- * Signature & Verification from extended types
    , sign
    , verify
    ) where

import           Crypto.OpenSSL.Random (randBytes)
import qualified Crypto.PubKey.Ed25519 as Ed25519
import qualified Crypto.ECC.Edwards25519 as Edwards25519
import           Crypto.Hash (SHA512, hash)
import qualified Crypto.MAC.HMAC as HMAC
import           Crypto.Error (throwCryptoError)
import           Data.Word
import           Data.ByteString (ByteString)
import qualified Data.ByteString as B (pack)
import           Data.ByteArray (ByteArrayAccess, convert)
import qualified Data.ByteArray as B (splitAt, length, append)

import Debug.Trace

newtype ChainCode = ChainCode ByteString
    deriving (Show,Eq)

data XPrv = XPrv !Edwards25519.Scalar !ChainCode

data XPub = XPub !Edwards25519.PointCompressed !ChainCode
    deriving (Eq)

newtype XSignature = XSignature Edwards25519.Signature

generate :: (ByteArrayAccess passPhrase, ByteArrayAccess seed)
         => seed
         -> passPhrase
         -> Maybe XPrv
generate seed passPhrase
    | B.length seed < 32 = Nothing
    | otherwise          =
        let (iL, iR) = hFinalize
                     $ flip HMAC.update ("Root Seed Chain" :: ByteString)
                     $ hInitSeed seed
         in Just $ XPrv (Edwards25519.scalar iL) iR

-- | Simple constructor
xprv :: ByteArrayAccess bin => bin -> Either String XPrv
xprv bs
    | B.length bs /= 64 = Left ("error: xprv need to be 64 bytes: got " ++ show (B.length bs) ++ " bytes")
    | otherwise         =
        let (b1, b2) = B.splitAt 32 $ convert bs
         in Right $ XPrv (Edwards25519.scalar b1) (ChainCode b2)

unXPrv :: XPrv -> ByteString
unXPrv (XPrv prv (ChainCode cc)) = B.append (Edwards25519.unScalar prv) cc

xpub :: ByteString -> Either String XPub
xpub bs
    | B.length bs /= 64 = Left ("error: xprv need to be 64 bytes: got " ++ show (B.length bs) ++ " bytes")
    | otherwise         =
        let (b1, b2) = B.splitAt 32 bs
         in Right $ XPub (Edwards25519.pointCompressed b1) (ChainCode $ convert b2)

unXPub :: XPub -> ByteString
unXPub (XPub pub (ChainCode cc)) = B.append (Edwards25519.unPointCompressed pub) cc

-- | Generate extended public key from private key
toXPub :: XPrv -> XPub
toXPub (XPrv sec ccode) = XPub (Edwards25519.scalarToPoint sec) ccode

-- | Return the Ed25519 public key associated with a XPub context
xPubGetPublicKey :: XPub -> Ed25519.PublicKey
xPubGetPublicKey (XPub pub _) =
    throwCryptoError $ Ed25519.publicKey $ Edwards25519.unPointCompressed pub

deriveXPrvHardened :: ByteArrayAccess passPhrase => passPhrase -> XPrv -> Word32 -> XPrv
deriveXPrvHardened _ (XPrv sec ccode) n =
    let (iL, iR) = walletHash $ DerivationHashHardened sec ccode n
     in XPrv (Edwards25519.scalar iL) iR

-- | Derive a child extended private key from an extended private key
deriveXPrv :: ByteArrayAccess passPhrase => passPhrase -> XPrv -> Word32 -> XPrv
deriveXPrv _ (XPrv sec ccode) n =
    let !pub     = Edwards25519.scalarToPoint sec
        (iL, iR) = walletHash $ DerivationHashNormal pub ccode n
        !derived = Edwards25519.scalar iL
     in XPrv (Edwards25519.scalarAdd sec derived) iR

-- | Derive a child public from an extended public key
deriveXPub :: XPub -> Word32 -> XPub
deriveXPub (XPub pub ccode) n =
    let (iL, iR) = walletHash $ DerivationHashNormal pub ccode n
        !derived = Edwards25519.scalarToPoint $ Edwards25519.scalar iL
     in XPub (Edwards25519.pointAdd pub derived) iR

sign :: (ByteArrayAccess passPhrase, ByteArrayAccess msg)
     => passPhrase
     -> XPrv
     -> msg
     -> XSignature
sign _ (XPrv priv (ChainCode cc)) ba =
    XSignature $ Edwards25519.sign priv cc ba
    {-
    let sec = throwCryptoError $ Ed25519.secretKey $ Edwards25519.unScalar priv
        pub = throwCryptoError $ Ed25519.publicKey $ Edwards25519.unPointCompressed (Edwards25519.scalarToPoint priv) -- point
        -- pub = Ed25519.toPublic sec
     in Ed25519.sign sec pub ba
     -}

verify :: ByteArrayAccess msg => XPub -> msg -> XSignature -> Bool
verify (XPub point _) ba (XSignature signature) =
    let pub = throwCryptoError $ Ed25519.publicKey $ Edwards25519.unPointCompressed point
        sig = throwCryptoError $ Ed25519.signature $ Edwards25519.unSignature signature
     in Ed25519.verify pub ba sig

-- hashing methods either hardened or normal
data DerivationHash where
    DerivationHashHardened :: Edwards25519.Scalar          -> ChainCode -> Word32 -> DerivationHash
    DerivationHashNormal   :: Edwards25519.PointCompressed -> ChainCode -> Word32 -> DerivationHash

walletHash :: DerivationHash -> (ByteString, ChainCode)
walletHash (DerivationHashHardened sec cc w) =
    hFinalize
            $ flip HMAC.update (encodeIndex w)
            $ flip HMAC.update (Edwards25519.unScalar sec)
            $ flip HMAC.update hardenedTag
            $ hInit cc
walletHash (DerivationHashNormal pub cc w) =
    hFinalize
            $ flip HMAC.update (encodeIndex w)
            $ flip HMAC.update (Edwards25519.unPointCompressed pub)
            $ flip HMAC.update normalTag
            $ hInit cc

hardenedTag = B.pack $ map (fromIntegral . fromEnum) "HARD"
normalTag   = B.pack $ map (fromIntegral . fromEnum) "NORM"

-- | Encode a Word32 in Big endian
encodeIndex :: Word32 -> ByteString
encodeIndex w = B.pack [d,c,b,a]
  where
    a = fromIntegral w
    b = fromIntegral (w `div` 0xff)
    c = fromIntegral (w `div` 0xffff)
    d = fromIntegral (w `div` 0xffffff)

hInit :: ChainCode -> HMAC.Context SHA512
hInit (ChainCode key) = HMAC.initialize key

hInitSeed :: ByteArrayAccess seed => seed -> HMAC.Context SHA512
hInitSeed seed = HMAC.initialize seed

hFinalize :: HMAC.Context SHA512 -> (ByteString, ChainCode)
hFinalize ctx =
    let (b1, b2) = B.splitAt 32 $ convert $ HMAC.finalize ctx
     in (b1, ChainCode b2)
