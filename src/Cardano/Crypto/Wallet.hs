-- |
-- Module      : Cardano.Crypto.Wallet
-- Description : HD wallet routines over versioned encrypted root keys.
-- Maintainer  : vincent@typed.io
--
-- This provides similar functionality to BIP32 but using
-- Ed25519 arithmetic instead of P256K1 arithmethic.
--
-- Persisted extended private keys are serialized encrypted envelopes. New
-- writes use an authenticated @v2@ format while legacy @v1@ values remain
-- readable for migration.
--
-- Key can be hierarchically derived from private key in two
-- fashions: Hardened or Normal.
--
-- In the hardened scheme, the child secret key is not linearly
-- derived, so that the child public key has no way
-- to be efficiently computed from the parent public key.
--
-- The normal scheme allows anyone to derive public keys from
-- public key.
--
{-# LANGUAGE GADTs               #-}
{-# LANGUAGE OverloadedStrings   #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeOperators       #-}
{-# LANGUAGE DeriveGeneric       #-}
{-# LANGUAGE PatternSynonyms     #-}

module Cardano.Crypto.Wallet
    ( ChainCode(..)
    , DerivationScheme(..)
    , DerivationIndex
    , pattern LatestScheme
    -- * Extended Private & Public types
    , XPrv
    , XPrvError(..)
    , XPrvFormat(..)
    , XPub(..)
    , XSignature
    , generate
    , generateNew
    , xprv
    , xpub
    , xsignature
    , unXPrv
    , unXPub
    , unXSignature
    , toXPub
    , xPubGetPublicKey
    , xPrvFormat
    , validateXPrvPassphrase
    , upgradeXPrvToV2
    , rewrapXPrvToV2
    , xPrvChangePass
    -- * Derivation function
    , deriveXPrv
    , deriveXPub
    -- * Signature & Verification from extended types
    , sign
    , verify
    ) where

import           Basement.Compat.Typeable
import           Control.DeepSeq                 (NFData)
import           Control.Arrow                   (second)
import           Crypto.Error                    (throwCryptoError)
import qualified Crypto.MAC.HMAC                 as HMAC
import qualified Crypto.PubKey.Ed25519           as Ed25519
import           Crypto.KDF.PBKDF2               (fastPBKDF2_SHA512, Parameters(..))
import           Data.ByteArray                  (ByteArrayAccess, convert)
import qualified Data.ByteArray                  as B (append, length, splitAt)
import           Data.ByteString                 (ByteString)
import qualified Data.ByteString.Char8           as BC
import           Data.Hashable                   (Hashable)
import           Data.Word
import           GHC.Generics                    (Generic)

import           Cardano.Crypto.Wallet.Encrypted
import           Cardano.Crypto.Wallet.Pure      ({-XPub (..),-} hFinalize,
                                                  hInitSeed)
import           Cardano.Crypto.Wallet.Types

import           GHC.Stack

newtype XPrv = XPrv EncryptedKey
    deriving (NFData, Typeable)

data XPub = XPub
    { xpubPublicKey :: !ByteString
    , xpubChaincode :: !ChainCode
    } deriving (Eq, Show, Ord, Typeable, Generic)

instance NFData XPub
instance Hashable XPub

newtype XSignature = XSignature
    { unXSignature :: ByteString
    } deriving (Show, Eq, Ord, NFData, Hashable, ByteArrayAccess)

-- | Generate a new XPrv
--
-- The seed needs to be at least 32 bytes, otherwise an asynchronous error is thrown
generate :: (ByteArrayAccess passPhrase, ByteArrayAccess seed)
         => seed
         -> passPhrase
         -> Either XPrvError XPrv
generate seed passPhrase
    | B.length seed < 32 = Left XPrvInvalidSecretKey
    | otherwise          = loop 1
  where
    phrase :: Int -> ByteString
    phrase i = "Root Seed Chain " `B.append` BC.pack (show i)

    -- repeatdly try to generate from a seed, if we reach 1000th iteration we just bail
    -- this should find a candidate after 2 tries on average
    loop i
        | i > 1000  = error "internal error: Wallet.generate looping forever"
        | otherwise =
            case encryptedCreate iL passPhrase iR of
                    Right k               -> Right (XPrv k)
                    Left XPrvInvalidSecretKey -> loop (i+1)
                    Left err              -> Left err
      where (iL, iR) = hFinalize
                     $ flip HMAC.update (phrase i)
                     $ hInitSeed seed

-- | Generate a new XPrv from an entropy seed
--
-- The seed should be at least 16 bytes, although it is not enforced
--
-- The passphrase encrypt the secret key in memory
generateNew :: (ByteArrayAccess keyPassPhrase, ByteArrayAccess generationPassPhrase, ByteArrayAccess seed)
            => seed                 -- ^ Raw entropy used as source of randomness for this algorithm
            -> generationPassPhrase -- ^ User chosen passphrase for the generation phase
            -> keyPassPhrase        -- ^ Symmetric encryption key passphrase used for the in-memory security
            -> Either XPrvError XPrv
generateNew seed genPassPhrase memPassPhrase =
    XPrv <$> encryptedCreateDirectWithTweak out memPassPhrase
  where
    out :: ByteString
    out = fastPBKDF2_SHA512 (Parameters 4096 96) genPassPhrase seed

-- | Simple constructor
xprv :: ByteArrayAccess bin => bin -> Either XPrvError XPrv
xprv bs =
    XPrv <$> encryptedKey (convert bs)

unXPrv :: XPrv -> ByteString
unXPrv (XPrv e) = unEncryptedKey e

xPrvFormat :: XPrv -> XPrvFormat
xPrvFormat (XPrv e) = encryptedKeyFormat e

xpub :: ByteString -> Either String XPub
xpub bs
    | B.length bs /= 64 = Left ("error: xprv needs to be 64 bytes: got " ++ show (B.length bs) ++ " bytes")
    | otherwise         =
        let (b1, b2) = B.splitAt 32 bs
         in Right $ XPub b1 (ChainCode $ convert b2)

unXPub :: XPub -> ByteString
unXPub (XPub pub (ChainCode cc)) = B.append pub cc

xsignature :: ByteString -> Either String XSignature
xsignature bs
    | B.length bs /= 64 = Left ("error: xsignature needs to be 64 bytes: got " ++ show (B.length bs) ++ " bytes")
    | otherwise         = Right $ XSignature bs

-- | Generate extended public key from private key
toXPub :: HasCallStack => XPrv -> XPub
toXPub (XPrv ekey) = XPub pub (ChainCode cc)
  where
    pub = encryptedPublic ekey
    cc = encryptedChainCode ekey

-- | Return the Ed25519 public key associated with a XPub context
xPubGetPublicKey :: XPub -> Ed25519.PublicKey
xPubGetPublicKey (XPub pub _) =
    throwCryptoError $ Ed25519.publicKey pub

xPrvChangePass :: (ByteArrayAccess oldPassPhrase, ByteArrayAccess newPassPhrase)
               => oldPassPhrase -- ^ passphrase to decrypt the current encrypted key
               -> newPassPhrase -- ^ new passphrase to use for the new encrypted key
               -> XPrv
               -> Either XPrvError XPrv
xPrvChangePass oldPass newPass (XPrv ekey) =
    XPrv <$> encryptedChangePass oldPass newPass ekey

validateXPrvPassphrase :: ByteArrayAccess passPhrase => passPhrase -> XPrv -> Either XPrvError ()
validateXPrvPassphrase passPhrase (XPrv ekey) = encryptedValidatePassphrase ekey passPhrase

upgradeXPrvToV2 :: ByteArrayAccess passPhrase => passPhrase -> XPrv -> Either XPrvError XPrv
upgradeXPrvToV2 passPhrase (XPrv ekey) = XPrv <$> encryptedUpgradeToV2 passPhrase ekey

rewrapXPrvToV2 :: ByteArrayAccess passPhrase => passPhrase -> XPrv -> Either XPrvError XPrv
rewrapXPrvToV2 passPhrase (XPrv ekey) = XPrv <$> encryptedRewrapToV2 passPhrase ekey

-- | Derive a child extended private key from an extended private key
deriveXPrv :: ByteArrayAccess passPhrase => DerivationScheme -> passPhrase -> XPrv -> Word32 -> Either XPrvError XPrv
deriveXPrv ds passPhrase (XPrv ekey) n =
    XPrv <$> encryptedDerivePrivate ds ekey passPhrase n

-- | Derive a child extended public key from an extended public key
deriveXPub :: DerivationScheme -> XPub -> Word32 -> Maybe XPub
deriveXPub ds (XPub pub (ChainCode cc)) n
    | n >= 0x80000000 = Nothing
    | otherwise       = Just $ uncurry XPub $ second ChainCode $ encryptedDerivePublic ds (pub,cc) n

sign :: (ByteArrayAccess passPhrase, ByteArrayAccess msg)
     => passPhrase
     -> XPrv
     -> msg
     -> Either XPrvError XSignature
sign passphrase (XPrv ekey) ba =
    (\(Signature sig) -> XSignature sig) <$> encryptedSign ekey passphrase ba

verify :: ByteArrayAccess msg => XPub -> msg -> XSignature -> Bool
verify (XPub point _) ba (XSignature signature) =
    let pub = throwCryptoError $ Ed25519.publicKey point
        sig = throwCryptoError $ Ed25519.signature signature
     in Ed25519.verify pub ba sig
