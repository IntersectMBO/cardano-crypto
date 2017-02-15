module Cardano.Crypto.Wallet.Encrypted
    (
    ) where

import           Control.DeepSeq
import           Data.Word
import           Foreign.Ptr
import           Foreign.C.Types

import           Data.ByteString (ByteString)
import           Data.ByteArray (ByteArrayAccess, withByteArray, ScrubbedBytes, Bytes)
import qualified Data.ByteArray as B
import           Crypto.Error
import           System.IO.Unsafe

encryptedKeySize :: Int
encryptedKeySize = 32 + 32 + 32

signatureSize :: Int
signatureSize = 64

newtype Signature = Signature ByteString

newtype EncryptedKey = EncryptedKey ByteString

data PassPhrase

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

foreign import ccall "wallet_encrypted_sign"
    wallet_encrypted_sign :: Ptr EncryptedKey
                          -> Ptr PassPhrase -> Word32
                          -> Ptr Word8 -> Word32
                          -> Ptr Signature
                          -> IO ()
