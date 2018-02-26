{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE NoImplicitPrelude #-}

module Cardano.Crypto.Praos.VRF
    ( -- * Key
      SecretKey
    , toPublic
    , PublicKey
    , KeyPair(..)
    , generateKeyPair

    , -- ** generate
      generateKey
    , -- ** Serialisation
      secretKeyToBytes
    , publicKeyToBytes
    , secretKeyFromBytes
    , publicKeyFromBytes

    , -- * Proof
      Proof
    , generate
    , verify
    ) where

import Foundation
import Basement.NormalForm
import Foundation.Check (Arbitrary(..))

import Data.ByteArray (ByteArrayAccess, ByteArray, Bytes)

import           Crypto.ECC.P256 (Point, Scalar, (.*))
import qualified Crypto.ECC.P256 as P256
import           Crypto.DLEQ (DLEQ(..))
import qualified Crypto.DLEQ as DLEQ
import           Crypto.Random
import           Crypto.Hash (SHA256, Digest)
import qualified Crypto.Hash as Hash
import           Crypto.MAC.HMAC (HMAC)
import qualified Crypto.MAC.HMAC as HMAC

data KeyPair = KeyPair
    { toPublicKey :: !PublicKey
    , toSecretKey :: !SecretKey
    }
  deriving (Show, Eq, Typeable)
instance Arbitrary KeyPair where
    arbitrary = arbitrary >>= \s -> pure (KeyPair (toPublic s) s)
instance NormalForm KeyPair where
    toNormalForm (KeyPair pk sk) = toNormalForm pk `seq` toNormalForm sk

newtype SecretKey = SecretKey { toScalar :: Scalar }
  deriving (Eq, Show, Typeable, NormalForm, Arbitrary)

newtype PublicKey = PublicKey { toPoint :: Point }
  deriving (Eq, Show, Typeable, NormalForm, Arbitrary)

-- | generate a new secret key
generateKey :: MonadRandom randomly => randomly SecretKey
generateKey = SecretKey <$> P256.keyGenerate

-- | generate a new secret key
generateKeyPair :: MonadRandom randomly => randomly KeyPair
generateKeyPair = generateKey >>= \s -> pure (KeyPair (toPublic s) s)

-- | get the public key associated to the given secret key
toPublic :: SecretKey -> PublicKey
toPublic = PublicKey . P256.pointFromSecret . toScalar

-- | serialise a public key into a binary representation
publicKeyToBytes :: ByteArray b => PublicKey -> b
publicKeyToBytes = P256.pointToBinary . toPoint

-- | get a public key from a binary representation
--
-- this function may fail due to the nature of the underlying types of a
-- public key.
publicKeyFromBytes :: ByteArrayAccess ba => ba -> Either LString PublicKey
publicKeyFromBytes b = PublicKey <$> P256.pointFromBytes b

-- | serialise a secret key into a binary representation
secretKeyToBytes :: ByteArray b => SecretKey -> b
secretKeyToBytes = P256.scalarToBytes . toScalar

-- | get a secret key from the given bytes
secretKeyFromBytes :: ByteArrayAccess ba => ba -> SecretKey
secretKeyFromBytes = SecretKey . P256.keyFromBytes

hash' :: ByteArrayAccess ba => ba -> PublicKey
hash' = toPublic . SecretKey . P256.keyFromBytes . hashSHA256
  where
    hashSHA256 :: ByteArrayAccess ba => ba -> Digest SHA256
    hashSHA256 = Hash.hash
    {-# INLINABLE hashSHA256 #-}

type Output = HMAC SHA256

hash :: ByteArrayAccess ba => ba -> PublicKey -> Output
hash message key = HMAC.hmac message k
  where
    k = publicKeyToBytes key :: Bytes
-- hash =? pbkdf2

data Proof = Proof PublicKey DLEQ.Proof
  deriving (Eq, Show, Typeable)

-- | Generate a Deterministicaly _random_ 'Output' and an associated 'Proof'
--
-- At any time, with the associated 'PublicKey' one is able to 'verify' the
-- 'Output' of 'generate' with the returned 'Output' and 'Proof'.
--
generate :: (ByteArrayAccess ba, MonadRandom randomly)
         => ba
         -> SecretKey
         -> randomly (Output, Proof)
generate m k = do
    r <- toScalar <$> generateKey
    let proof = DLEQ.generate r (toScalar k) (DLEQ P256.curveGenerator h1 g2 h2)
    pure (y, Proof u proof)
  where
    u = hash' m .^ k
    y = hash m u
    v = toPublic k

    h1 = toPoint v
    g2 = toPoint (hash' m)
    h2 = toPoint u

    (.^) (PublicKey a) (SecretKey b) = PublicKey $ a .* b

-- | verify that the given message and the 'SecretKey' associated to the given
-- 'PublicKey' generated the given 'Output'.
--
verify :: ByteArrayAccess ba
       => ba
       -> PublicKey
       -> (Output, Proof)
       -> Bool
verify m v (y, Proof u proof) =
    y == hash m u && DLEQ.verify dleq proof
  where
    dleq = DLEQ P256.curveGenerator (toPoint v) (toPoint $ hash' m) (toPoint u)
