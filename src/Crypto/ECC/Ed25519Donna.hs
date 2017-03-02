-- |
-- Module      : Crypto.PubKey.Ed25519
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- Ed25519 support
--
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE BangPatterns #-}
module Crypto.ECC.Ed25519Donna
    ( SecretKey(..)
    , PublicKey(..)
    , Signature
    -- * Smart constructors
    , signature
    , publicKey
    , secretKey
    -- * methods
    , toPublic
    , sign
    , verify
    , publicAdd
    , secretAdd
    ) where

import           Control.DeepSeq
import           Data.Word
import           Foreign.Ptr
import           Foreign.C.Types

import           Data.ByteArray (ByteArrayAccess, withByteArray, ScrubbedBytes, Bytes)
import qualified Data.ByteArray as B
import           Crypto.Error
import           System.IO.Unsafe

unsafeDoIO = unsafeDupablePerformIO

-- | An Ed25519 Secret key
newtype SecretKey = SecretKey ScrubbedBytes
    deriving (Eq,ByteArrayAccess,NFData)

-- | An Ed25519 public key
newtype PublicKey = PublicKey Bytes
    deriving (Show,Eq,ByteArrayAccess,NFData)

-- | An Ed25519 signature
newtype Signature = Signature Bytes
    deriving (Show,Eq,ByteArrayAccess,NFData)

-- | Try to build a public key from a bytearray
publicKey :: ByteArrayAccess ba => ba -> CryptoFailable PublicKey
publicKey bs
    | B.length bs == publicKeySize =
        CryptoPassed $ PublicKey $ B.copyAndFreeze bs (\_ -> return ())
    | otherwise =
        CryptoFailed $ CryptoError_PublicKeySizeInvalid

-- | Try to build a secret key from a bytearray
secretKey :: ByteArrayAccess ba => ba -> CryptoFailable SecretKey
secretKey bs
    | B.length bs == secretKeySize = unsafePerformIO $ withByteArray bs initialize
    | otherwise                    = CryptoFailed CryptoError_SecretKeyStructureInvalid
  where
        initialize inp = CryptoPassed . SecretKey <$> B.copy bs (\_ -> return ())
{-# NOINLINE secretKey #-}

-- | Try to build a signature from a bytearray
signature :: ByteArrayAccess ba => ba -> CryptoFailable Signature
signature bs
    | B.length bs == signatureSize =
        CryptoPassed $ Signature $ B.copyAndFreeze bs (\_ -> return ())
    | otherwise =
        CryptoFailed CryptoError_SecretKeyStructureInvalid

-- | Create a public key from a secret key
toPublic :: SecretKey -> PublicKey
toPublic (SecretKey sec) = PublicKey $
    B.allocAndFreeze publicKeySize $ \result ->
    withByteArray sec              $ \psec   ->
        ccryptonite_ed25519_publickey psec result
{-# NOINLINE toPublic #-}

publicAdd :: PublicKey -> PublicKey -> PublicKey
publicAdd p1 p2 =
    PublicKey $ B.allocAndFreeze publicKeySize $ \result ->
        withByteArray p1 $ \v1 ->
        withByteArray p2 $ \v2 ->
            ccryptonite_ed25519_point_add v1 v2 result

secretAdd :: SecretKey -> SecretKey -> SecretKey
secretAdd p1 p2 =
    SecretKey $ B.allocAndFreeze secretKeySize $ \result ->
        withByteArray p1 $ \v1 ->
        withByteArray p2 $ \v2 ->
            ccryptonite_ed25519_scalar_add v1 v2 result

-- | Sign a message using the key pair
sign :: (ByteArrayAccess msg, ByteArrayAccess salt) => SecretKey -> salt -> PublicKey -> msg -> Signature
sign secret salt public message =
    Signature $ B.allocAndFreeze signatureSize $ \sig ->
        withByteArray secret  $ \sec   ->
        withByteArray public  $ \pub   ->
        withByteArray salt    $ \saltP ->
        withByteArray message $ \msg   ->
             ccryptonite_ed25519_sign msg (fromIntegral msgLen) saltP (fromIntegral saltLen) sec pub sig
  where
    !msgLen  = B.length message
    !saltLen = B.length salt

-- | Verify a message
verify :: ByteArrayAccess ba => PublicKey -> ba -> Signature -> Bool
verify public message signatureVal = unsafeDoIO $
    withByteArray signatureVal $ \sig ->
    withByteArray public       $ \pub ->
    withByteArray message      $ \msg -> do
      r <- ccryptonite_ed25519_sign_open msg (fromIntegral msgLen) pub sig
      return (r == 0)
  where
    !msgLen = B.length message

publicKeySize :: Int
publicKeySize = 32

secretKeySize :: Int
secretKeySize = 32

signatureSize :: Int
signatureSize = 64

foreign import ccall "cardano_crypto_ed25519_publickey"
    ccryptonite_ed25519_publickey :: Ptr SecretKey -- secret key
                                  -> Ptr PublicKey -- public key
                                  -> IO ()

foreign import ccall "cardano_crypto_ed25519_sign_open"
    ccryptonite_ed25519_sign_open :: Ptr Word8     -- message
                                  -> CSize         -- message len
                                  -> Ptr PublicKey -- public
                                  -> Ptr Signature -- signature
                                  -> IO CInt

foreign import ccall "cardano_crypto_ed25519_sign"
    ccryptonite_ed25519_sign :: Ptr Word8     -- message
                             -> CSize         -- message len
                             -> Ptr Word8     -- salt
                             -> CSize         -- salt len
                             -> Ptr SecretKey -- secret
                             -> Ptr PublicKey -- public
                             -> Ptr Signature -- signature
                             -> IO ()

foreign import ccall "cardano_crypto_ed25519_point_add"
    ccryptonite_ed25519_point_add :: Ptr PublicKey -- p1
                                  -> Ptr PublicKey -- p2
                                  -> Ptr PublicKey -- p1 + p2
                                  -> IO ()

foreign import ccall "cardano_crypto_ed25519_scalar_add"
    ccryptonite_ed25519_scalar_add :: Ptr SecretKey -- s1
                                   -> Ptr SecretKey -- s2
                                   -> Ptr SecretKey -- s1 + s2
                                   -> IO ()
