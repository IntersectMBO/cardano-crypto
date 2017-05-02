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
{-# LANGUAGE GADTs               #-}
{-# LANGUAGE OverloadedStrings   #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeOperators       #-}

module Cardano.Crypto.Wallet
    ( ChainCode(..)
    -- * Extended Private & Public types
    , XPrv
    , XPub
    , XSignature
    , generate
    , xprv
    , xpub
    , xsignature
    , unXPrv
    , unXPub
    , unXSignature
    , toXPub
    , xPubGetPublicKey
    , xPrvChangePass
    -- * Derivation function
    , deriveXPrvHardened
    , deriveXPrv
    , deriveXPub
    -- * Signature & Verification from extended types
    , sign
    , verify
    ) where

import           Control.DeepSeq                 (NFData)
import qualified Crypto.ECC.Edwards25519         as Edwards25519
import           Crypto.Error                    (throwCryptoError)
import           Crypto.Hash                     (SHA512, hash)
import qualified Crypto.MAC.HMAC                 as HMAC
import           Crypto.OpenSSL.Random           (randBytes)
import qualified Crypto.PubKey.Ed25519           as Ed25519
import           Data.ByteArray                  (ByteArrayAccess, convert)
import qualified Data.ByteArray                  as B (append, length, splitAt)
import           Data.ByteString                 (ByteString)
import qualified Data.ByteString                 as B (pack)
import           Data.Hashable                   (Hashable)
import           Data.Word
import           GHC.Generics                    (Generic)

import           Cardano.Crypto.Wallet.Encrypted
import           Cardano.Crypto.Wallet.Pure      (XPub (..), deriveXPub, hFinalize,
                                                  hInitSeed)
import           Cardano.Crypto.Wallet.Types

import           GHC.Stack

newtype XPrv = XPrv EncryptedKey
    deriving (NFData)

newtype XSignature = XSignature
    { unXSignature :: ByteString
    } deriving (Show, Eq, Ord, NFData, Hashable)

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
         in Just $ XPrv $ encryptedCreate iL passPhrase iR

-- | Simple constructor
xprv :: ByteArrayAccess bin => bin -> Either String XPrv
xprv bs =
      maybe (Left "error: xprv need to be 32*3 bytes") (Right . XPrv)
    $ encryptedKey
    $ convert bs

unXPrv :: XPrv -> ByteString
unXPrv (XPrv e) = unEncryptedKey e

xpub :: ByteString -> Either String XPub
xpub bs
    | B.length bs /= 64 = Left ("error: xprv need to be 64 bytes: got " ++ show (B.length bs) ++ " bytes")
    | otherwise         =
        let (b1, b2) = B.splitAt 32 bs
         in Right $ XPub (Edwards25519.pointCompressed b1) (ChainCode $ convert b2)

unXPub :: XPub -> ByteString
unXPub (XPub pub (ChainCode cc)) = B.append (Edwards25519.unPointCompressed pub) cc

xsignature :: ByteString -> Either String XSignature
xsignature bs
    | B.length bs /= 64 = Left ("error: xsignature need to be 64 bytes: got " ++ show (B.length bs) ++ " bytes")
    | otherwise         = Right $ XSignature bs

-- | Generate extended public key from private key
toXPub :: HasCallStack => XPrv -> XPub
toXPub (XPrv encryptedKey) =
    XPub (Edwards25519.pointCompressed $ encryptedPublic encryptedKey)
         (ChainCode $ encryptedChainCode encryptedKey)

-- | Return the Ed25519 public key associated with a XPub context
xPubGetPublicKey :: XPub -> Ed25519.PublicKey
xPubGetPublicKey (XPub pub _) =
    throwCryptoError $ Ed25519.publicKey $ Edwards25519.unPointCompressed pub

xPrvChangePass :: (ByteArrayAccess oldPassPhrase, ByteArrayAccess newPassPhrase)
	           => oldPassPhrase -- ^ passphrase to decrypt the current encrypted key
		       -> newPassPhrase -- ^ new passphrase to use for the new encrypted key
               -> XPrv
               -> XPrv
xPrvChangePass oldPass newPass (XPrv encryptedKey) =
    XPrv $ encryptedChangePass oldPass newPass encryptedKey

deriveXPrvHardened :: ByteArrayAccess passPhrase => passPhrase -> XPrv -> Word32 -> XPrv
deriveXPrvHardened passPhrase (XPrv ekey) n =
    XPrv (encryptedDeriveHardened ekey passPhrase n)

-- | Derive a child extended private key from an extended private key
deriveXPrv :: ByteArrayAccess passPhrase => passPhrase -> XPrv -> Word32 -> XPrv
deriveXPrv passPhrase (XPrv ekey) n =
    XPrv (encryptedDeriveNormal ekey passPhrase n)

sign :: (ByteArrayAccess passPhrase, ByteArrayAccess msg)
     => passPhrase
     -> XPrv
     -> msg
     -> XSignature
sign passphrase (XPrv ekey) ba =
    XSignature $ let (Signature sig) = encryptedSign ekey passphrase ba in sig

verify :: ByteArrayAccess msg => XPub -> msg -> XSignature -> Bool
verify (XPub point _) ba (XSignature signature) =
    let pub = throwCryptoError $ Ed25519.publicKey $ Edwards25519.unPointCompressed point
        sig = throwCryptoError $ Ed25519.signature $ signature
     in Ed25519.verify pub ba sig
