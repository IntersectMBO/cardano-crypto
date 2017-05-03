module Cardano.Crypto.Wallet.Encrypted
    ( EncryptedKey
    , encryptedKey
    , unEncryptedKey
    , Signature(..)
    -- * Methods
    , encryptedCreate
    , encryptedChangePass
    , encryptedSign
    , encryptedPublic
    , encryptedChainCode
    , encryptedDeriveNormal
    , encryptedDeriveHardened
    ) where

import           Control.DeepSeq
import           Data.Word
import           Foreign.C.Types
import           Foreign.Ptr

import           Crypto.Error
import           Data.ByteArray   (ByteArrayAccess, Bytes, ScrubbedBytes, withByteArray)
import qualified Data.ByteArray   as B
import           Data.ByteString  (ByteString)
import           System.IO.Unsafe

totalKeySize :: Int
totalKeySize = 32 + 32 + 32

encryptedKeySize :: Int
encryptedKeySize = 32

publicKeySize :: Int
publicKeySize = 32

signatureSize :: Int
signatureSize = 64

ccSize :: Int
ccSize = 32

publicKeyOffset :: Int
publicKeyOffset = encryptedKeySize

ccOffset :: Int
ccOffset = publicKeyOffset + publicKeySize

newtype Signature = Signature ByteString
    deriving (NFData)

newtype EncryptedKey = EncryptedKey ByteString
    deriving (NFData)

data PassPhrase

-- | Create an encryped key from binary representation.
--
-- If the binary is not of the right size, Nothing is returned
encryptedKey :: ByteString -> Maybe EncryptedKey
encryptedKey ba
    | B.length ba == totalKeySize = Just $ EncryptedKey ba
    | otherwise                   = Nothing

unEncryptedKey :: EncryptedKey -> ByteString
unEncryptedKey (EncryptedKey e) = e

-- | Create a new encrypted key from the secret, encrypting the secret in memory
-- using the passphrase.
encryptedCreate :: (ByteArrayAccess passphrase, ByteArrayAccess secret, ByteArrayAccess cc)
                => secret
                -> passphrase
                -> cc
                -> EncryptedKey
encryptedCreate sec pass cc = EncryptedKey $ B.allocAndFreeze totalKeySize $ \ekey ->
    withByteArray sec  $ \psec  ->
    withByteArray pass $ \ppass ->
    withByteArray cc   $ \pcc   ->
        wallet_encrypted_from_secret ppass (fromIntegral $ B.length pass) psec pcc ekey

-- | Create a new encrypted that use a different passphrase
encryptedChangePass :: (ByteArrayAccess oldPassPhrase, ByteArrayAccess newPassPhrase)
                    => oldPassPhrase -- ^ passphrase to decrypt the current encrypted key
                    -> newPassPhrase -- ^ new passphrase to use for the new encrypted key
                    -> EncryptedKey  -- ^ Key using the old pass phrase
                    -> EncryptedKey  -- ^ Key using the new pass phrase
encryptedChangePass oldPass newPass (EncryptedKey okey) =
    EncryptedKey $ B.allocAndFreeze totalKeySize $ \ekey ->
        withByteArray oldPass $ \opass  ->
        withByteArray newPass $ \npass  ->
        withByteArray okey    $ \oldkey ->
            wallet_encrypted_change_pass oldkey
                         opass (fromIntegral $ B.length oldPass)
                         npass (fromIntegral $ B.length newPass)
                         ekey

-- | Sign using the encrypted keys and temporarly decrypting the secret in memory
-- with a minimal memory footprint.
encryptedSign :: (ByteArrayAccess passphrase, ByteArrayAccess msg)
              => EncryptedKey
              -> passphrase
              -> msg
              -> Signature
encryptedSign (EncryptedKey ekey) pass msg =
    Signature $ B.allocAndFreeze signatureSize $ \sig ->
        withByteArray ekey $ \k ->
        withByteArray pass $ \p ->
        withByteArray msg  $ \m ->
            wallet_encrypted_sign k p (fromIntegral $ B.length pass) m (fromIntegral $ B.length msg) sig

encryptedDeriveNormal :: (ByteArrayAccess passphrase)
                      => EncryptedKey
                      -> passphrase
                      -> Word32
                      -> EncryptedKey
encryptedDeriveNormal (EncryptedKey parent) pass childIndex =
    EncryptedKey $ B.allocAndFreeze totalKeySize $ \ekey ->
        withByteArray pass   $ \ppass   ->
        withByteArray parent $ \pparent ->
            wallet_encrypted_derive_normal pparent ppass (fromIntegral $ B.length pass) childIndex ekey

encryptedDeriveHardened :: ByteArrayAccess passphrase
                        => EncryptedKey
                        -> passphrase
                        -> Word32
                        -> EncryptedKey
encryptedDeriveHardened (EncryptedKey parent) pass childIndex =
    EncryptedKey $ B.allocAndFreeze totalKeySize $ \ekey ->
        withByteArray pass   $ \ppass   ->
        withByteArray parent $ \pparent ->
            wallet_encrypted_derive_hardened pparent ppass (fromIntegral $ B.length pass) childIndex ekey

-- | Get the public part of a encrypted key
encryptedPublic :: EncryptedKey -> ByteString
encryptedPublic (EncryptedKey ekey) = sub publicKeyOffset publicKeySize ekey

-- | Get the chain code part of a encrypted key
encryptedChainCode :: EncryptedKey -> ByteString
encryptedChainCode (EncryptedKey ekey) = sub ccOffset ccSize ekey

sub ofs sz = B.take sz . B.drop ofs

foreign import ccall "wallet_encrypted_from_secret"
    wallet_encrypted_from_secret :: Ptr PassPhrase -> Word32
                                 -> Ptr Word8 -- 32 bytes secret key / scalar
                                 -> Ptr Word8 -- 32 bytes ChainCode
                                 -> Ptr EncryptedKey
                                 -> IO ()

foreign import ccall "wallet_encrypted_sign"
    wallet_encrypted_sign :: Ptr EncryptedKey
                          -> Ptr PassPhrase -> Word32
                          -> Ptr Word8 -> Word32
                          -> Ptr Signature
                          -> IO ()

foreign import ccall "wallet_encrypted_derive_normal"
    wallet_encrypted_derive_normal :: Ptr EncryptedKey
                                   -> Ptr PassPhrase -> Word32
                                   -> Word32 -- index
                                   -> Ptr EncryptedKey
                                   -> IO ()

foreign import ccall "wallet_encrypted_derive_hardened"
    wallet_encrypted_derive_hardened :: Ptr EncryptedKey
                                     -> Ptr PassPhrase -> Word32
                                     -> Word32
                                     -> Ptr EncryptedKey
                                     -> IO ()

foreign import ccall "wallet_encrypted_change_pass"
    wallet_encrypted_change_pass :: Ptr EncryptedKey
                                 -> Ptr PassPhrase -> Word32
                                 -> Ptr PassPhrase -> Word32
                                 -> Ptr EncryptedKey
                                 -> IO ()

