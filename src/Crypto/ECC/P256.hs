{-# LANGUAGE CPP #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE NoImplicitPrelude #-}
{-# LANGUAGE BangPatterns #-}
module Crypto.ECC.P256
    ( Point(..)
    , Scalar(..)
    , PublicKey(..)
    , PrivateKey(..)
    , KeyPair(..)
    , DhSecret(..)
    , secretToPublicKey
    , curveGenerator
    , pointToDhSecret
    , pointFromSecret
    , pointToBinary
    , pointFromBytes
    , pointIdentity
    , keyPairGenerate
    , keyGenerate
    , keyFromBytes
    , keyFromNum
    , keyInverse
    , scalarToBytes
    , (#+)
    , (#-)
    , (#*)
    , (#^)
    , (.+)
    , (.-)
    , (.*)
    , (*.)
    , mulAndSum
    , mulPowerAndSum
    , hashPoints
    , hashPointsToKey
    ) where

#define OPENSSL

import Prelude (Show(..))

import Foundation hiding (show)
import Foundation.Check (Arbitrary(..))
import Basement.NormalForm

import qualified Data.ByteArray as B
import           Data.ByteArray (ScrubbedBytes, ByteArrayAccess, Bytes, ByteArray)
import           Data.Bits

import           Crypto.Hash (hash, SHA256, Digest)
import           Crypto.Number.Serialize
import           Crypto.Number.ModArithmetic (expFast)
import           Crypto.Random

#ifdef OPENSSL
import qualified Crypto.OpenSSL.ECC as SSL
import GHC.Integer.GMP.Internals (recipModInteger)
import Crypto.Number.Generate
#else
import qualified Crypto.PubKey.ECC.P256 as P256
#endif

data KeyPair = KeyPair
    { toPrivateKey :: PrivateKey
    , toPublicKey  :: PublicKey
    }
    deriving (Show,Eq,Typeable)
instance Arbitrary KeyPair where
    arbitrary = do
        drg <- drgNewTest <$> arbitrary
        pure $ fst $ withDRG drg keyPairGenerate

newtype DhSecret = DhSecret ScrubbedBytes
    deriving (Show,Eq,Typeable)
instance Arbitrary DhSecret where
    arbitrary = pointToDhSecret <$> arbitrary

keyFromBytes :: ByteArrayAccess ba => ba -> Scalar
keyFromBytes = keyFromNum . os2ip'
  where os2ip' :: ByteArrayAccess ba => ba -> Integer
        os2ip' = foldl' (\a b -> 256 * a .|. fromIntegral b) 0 . B.unpack

-- | Private Key
newtype PrivateKey = PrivateKey Scalar
    deriving (Show,Eq,Typeable,NormalForm)
instance Arbitrary PrivateKey where
    arbitrary = toPrivateKey <$> arbitrary

-- | Public Key
newtype PublicKey = PublicKey Point
    deriving (Show,Eq,Typeable,NormalForm)
instance Arbitrary PublicKey where
    arbitrary = toPublicKey <$> arbitrary

#ifdef OPENSSL

p256 :: SSL.EcGroup
p256 = fromMaybe (error "p256 curve") $ SSL.ecGroupFromCurveOID "1.2.840.10045.3.1.7"

newtype Point = Point { unPoint :: SSL.EcPoint }
    deriving (Typeable)
instance NormalForm Point where
    toNormalForm (Point !_) = ()
instance Arbitrary Point where
    arbitrary = pointFromSecret <$> arbitrary

pointFromBytes :: ByteArrayAccess ba => ba -> Either LString Point
pointFromBytes b = Point <$> SSL.ecPointFromOct p256 b

instance Show Point where
    show (Point p) =
        let (x,y) = SSL.ecPointToAffineGFp p256 p
         in ("Point " <> show x <> " " <> show y)
instance Eq Point where
    (Point a) == (Point b) = SSL.ecPointEq p256 a b

newtype Scalar = Scalar { unScalar :: Integer }
    deriving (Show,Eq,Typeable,NormalForm)
instance Arbitrary Scalar where
    arbitrary = do
        drg <- drgNewTest <$> arbitrary
        pure $ fst $ withDRG drg keyGenerate

scalarToBytes :: ByteArray b => Scalar -> b
scalarToBytes = i2ospOf_ 32 . unScalar

keyFromNum :: Integer -> Scalar
keyFromNum n = Scalar (n `mod` SSL.ecGroupGetOrder p256)

keyInverse :: Scalar -> Scalar
keyInverse (Scalar 0) = Scalar 0
keyInverse (Scalar a) = Scalar $ recipModInteger a order
  where
    order = SSL.ecGroupGetOrder p256

keyGenerate :: MonadRandom randomly => randomly Scalar
keyGenerate = Scalar <$> generateMax order
  where
    order = SSL.ecGroupGetOrder p256

secretToPublicKey :: PrivateKey -> PublicKey
secretToPublicKey (PrivateKey k) = PublicKey $ pointFromSecret k

keyPairGenerate :: MonadRandom randomly => randomly KeyPair
keyPairGenerate = do
    k <- PrivateKey <$> keyGenerate
    return $ KeyPair k (secretToPublicKey k)

pointToDhSecret :: Point -> DhSecret
pointToDhSecret (Point p) =
    let (x, _) = SSL.ecPointToAffineGFp p256 p
     in DhSecret $ B.convert $ hashSHA256 (i2ospOf_ 32 x :: Bytes)

pointToBinary :: ByteArray b => Point -> b
pointToBinary = flip (SSL.ecPointToOct p256) SSL.PointConversion_Compressed . unPoint

pointFromSecret :: Scalar -> Point
pointFromSecret (Scalar s) = Point $ SSL.ecPointGeneratorMul p256 s

pointIdentity :: Point
pointIdentity = Point $ SSL.ecPointInfinity p256

hashPoints :: [Point] -> Bytes
hashPoints elements =
    B.convert $ hashSHA256 $ (mconcat :: [Bytes] -> Bytes)
              $ fmap (flip (SSL.ecPointToOct p256) SSL.PointConversion_Compressed . unPoint) elements

hashPointsToKey :: [Point] -> Scalar
hashPointsToKey elements =
    keyFromBytes $ hashSHA256 $ (mconcat :: [Bytes] -> Bytes)
                 $ fmap (flip (SSL.ecPointToOct p256) SSL.PointConversion_Compressed . unPoint) elements

curveGenerator :: Point
curveGenerator = Point $ SSL.ecGroupGetGenerator p256

-- | Point adding
(.+) :: Point -> Point -> Point
(.+) (Point a) (Point b) = Point (SSL.ecPointAdd p256 a b)

-- | Point subtraction
(.-) :: Point -> Point -> Point
(.-) (Point a) (Point b) = Point (SSL.ecPointAdd p256 a $ SSL.ecPointInvert p256 b)

-- | Point scaling
(.*) :: Point -> Scalar -> Point
(.*) (Point a) (Scalar s) = Point (SSL.ecPointMul p256 a s)

-- | Point scaling, flip (*.)
(*.) :: Scalar -> Point -> Point
(*.) (Scalar s) (Point a) = Point (SSL.ecPointMul p256 a s)

(#+) :: Scalar -> Scalar -> Scalar
(#+) (Scalar a) (Scalar b) = keyFromNum (a + b)

(#-) :: Scalar -> Scalar -> Scalar
(#-) (Scalar a) (Scalar b) = keyFromNum (a - b)

(#*) :: Scalar -> Scalar -> Scalar
(#*) (Scalar a) (Scalar b) = keyFromNum (a * b)

(#^) :: Scalar -> Integer -> Scalar
(#^) (Scalar a) n =
    Scalar $ expFast a n order
  where
    order = SSL.ecGroupGetOrder p256

mulAndSum :: [(Point,Scalar)] -> Point
mulAndSum l = Point $ SSL.ecPointsMulAndSum p256 (fmap (\(Point p, Scalar s) -> (p, s)) l)

mulPowerAndSum :: [Point] -> Integer -> Point
mulPowerAndSum l n = Point $ SSL.ecPointsMulOfPowerAndSum p256 (fmap unPoint l) n

#else
newtype Point = Point { unPoint :: P256.Point }
    deriving (Show,Eq)

newtype Scalar = Scalar P256.Scalar
    deriving (Eq)

instance Show Scalar where
    show (Scalar p) = show (P256.scalarToInteger p)

p256Mod :: Integer
p256Mod = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551

curveGenerator :: Point
curveGenerator = pointIdentity

pointFromSecret :: Scalar -> Point
pointFromSecret (Scalar s) = Point $ P256.toPoint s

pointToDhSecret :: Point -> DhSecret
pointToDhSecret (Point p) = DhSecret $ B.convert $ hashSHA256 $ P256.pointToBinary p

-- | Point adding
(.+) :: Point -> Point -> Point
(.+) (Point a) (Point b) = Point (P256.pointAdd a b)

-- | Point scaling
(.*) :: Point -> Scalar -> Point
(.*) (Point a) (Scalar s) = Point (P256.pointMul s a)

-- | Point scaling, flip (*.)
(*.) :: Scalar -> Point -> Point
(*.) (Scalar s) (Point a) = Point (P256.pointMul s a)

(#+) :: Scalar -> Scalar -> Scalar
(#+) (Scalar a) (Scalar b) = Scalar (P256.scalarAdd a b)

(#-) :: Scalar -> Scalar -> Scalar
(#-) (Scalar a) (Scalar b) = Scalar (P256.scalarSub a b)

(#*) :: Scalar -> Scalar -> Scalar
(#*) (Scalar a) (Scalar b) =
    Scalar $ throwCryptoError $ P256.scalarFromInteger ((an * bn) `mod` p256Mod)
  where
    an = P256.scalarToInteger a
    bn = P256.scalarToInteger b

(#^) :: Scalar -> Integer -> Scalar
(#^) (Scalar a) n =
    Scalar $ throwCryptoError
           $ P256.scalarFromInteger
           $ expSafe (P256.scalarToInteger a) n p256Mod

pointIdentity :: Point
pointIdentity = Point $ P256.pointFromIntegers 0 0

keyFromNum :: Integer -> Scalar
keyFromNum = Scalar . throwCryptoError . P256.scalarFromInteger

keyInverse :: Scalar -> Scalar
keyInverse (Scalar s) = Scalar (P256.scalarInv s)

keyGenerate :: MonadRandom randomly => randomly Scalar
keyGenerate = Scalar <$> P256.scalarGenerate

keyPairGenerate :: MonadRandom randomly => randomly KeyPair
keyPairGenerate = do
    k <- keyGenerate
    return $ KeyPair k (pointFromSecret k)
hashPointsToKey :: [Point] -> Scalar
hashPointsToKey elements =
    keyFromBytes $ B.convert $ hashSHA256 $ mconcat $ fmap (P256.pointToBinary . unPoint) elements

#endif

hashSHA256 :: ByteArrayAccess ba => ba -> Digest SHA256
hashSHA256 = hash
{-# INLINABLE hashSHA256 #-}
