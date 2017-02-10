-- |
-- Module      : Crypto.ECC.Edwards25519
-- Description : Edwards 25519 arithmetics
-- Maintainer  : vincent@typed.io
--
-- Simple module to play with the arithmetics of the twisted edwards curve Ed25519
-- using Extended Twisted Edwards Coordinates. Compared to the normal implementation
-- this allow to use standard DH property:
--
-- for all valid s1 and s2 scalar:
--
-- > scalarToPoint (s1 + s2) = pointAdd (scalarToPoint s1) (scalarToPoint s2)
--
-- For further useful references about Ed25519:
--
-- * RFC 8032
-- * <http://ed25519.cr.yp.to/>
-- * <http://ed25519.cr.yp.to/ed25519-20110926.pdf>
-- * <http://eprint.iacr.org/2008/522.pdf>
--
{-# LANGUAGE BangPatterns #-}
module Crypto.ECC.Edwards25519
    (
    -- * Basic types
      Scalar
    , PointCompressed
    -- * smart constructor & destructor
    , scalar
    , unScalar
    , pointCompressed
    , unPointCompressed
    -- * Arithmetic
    , scalarFromInteger
    , scalarAdd
    , scalarToPoint
    , pointAdd
    ) where

import           Data.Bits
import           Crypto.Hash
import           Crypto.Number.Serialize
import           Crypto.Number.ModArithmetic
import           Data.ByteString (ByteString)
import qualified Data.ByteString as B (reverse)
import qualified Data.ByteArray as B

-- | Represent a scalar in the base field
newtype Scalar = Scalar { unScalar :: ByteString }

-- | Represent a point on the Edwards 25519 curve
newtype PointCompressed = PointCompressed { unPointCompressed :: ByteString }
    deriving (Show,Eq)

-- Create a Ed25519 scalar
--
-- Only check that the length is of expected size (32 bytes), no effort is made for the scalar
-- to be in the right base field range on purpose.
scalar :: ByteString -> Scalar
scalar bs
    | B.length bs /= 32 = error "invalid scalar"
    | otherwise         = Scalar bs

-- | Smart constructor to create a compress point binary
--
-- Check if the length is of expected size
pointCompressed :: ByteString -> PointCompressed
pointCompressed bs
    | B.length bs /= 32 = error "invalid compressed point"
    | otherwise         = PointCompressed bs

-- | Add 2 scalar in the base field together
scalarAdd :: Scalar -> Scalar -> Scalar
scalarAdd (Scalar s1) (Scalar s2) = Scalar $ toBytes ((fromBytes s1 + fromBytes s2) `mod` p)

-- | Create a scalar from integer. mainly for debugging purpose.
scalarFromInteger :: Integer -> Scalar
scalarFromInteger n = Scalar $ toBytes (n `mod` p)

-- | Add 2 points together
pointAdd :: PointCompressed -> PointCompressed -> PointCompressed
pointAdd p1 p2 = ePointCompress $ ePointAdd (ePointDecompress p1) (ePointDecompress p2)

-- | Lift a scalar to the curve, and returning a compressed point
scalarToPoint :: Scalar -> PointCompressed
scalarToPoint (Scalar sec) = ePointCompress $ ePointMul (fromBytes sec) pG

-- | Point represented by (X, Y, Z, T) in extended twisted edward coordinates.
--
--   x = X/Z
--   y = Y/Z
-- x*y = T/Z
data ExtendedPoint = ExtendedPoint !Integer !Integer !Integer !Integer
    deriving (Show,Eq)

ePointAdd :: ExtendedPoint -> ExtendedPoint -> ExtendedPoint
ePointAdd (ExtendedPoint pX pY pZ pT) (ExtendedPoint qX qY qZ qT) =
    ExtendedPoint (e*f) (g*h) (f*g) (e*h)
  where
    a = ((pY-pX) * (qY-qX)) `mod` p
    b = ((pY+pX) * (qY+qX)) `mod` p
    c = (2 * pT * qT * curveD) `mod` p
    d = (2 * pZ * qZ) `mod` p
    e = b-a
    f = d-c
    g = d+c
    h = b+a

ePointMul :: Integer -> ExtendedPoint -> ExtendedPoint
ePointMul = loop (ExtendedPoint 0 1 1 0)
  where
    loop acc 0 _ = acc
    loop acc s pP =
        let acc' = if odd s then ePointAdd acc pP else acc
            pP' = ePointAdd pP pP
         in loop acc' (s `shiftR` 1) pP'

ePointCompress :: ExtendedPoint -> PointCompressed
ePointCompress (ExtendedPoint pX pY pZ _) =
    PointCompressed $ toBytes (y .|. ((x .&. 0x1) `shiftL` 255))
  where
    zinv = modp_inv pZ
    x = (pX * zinv) `mod` p
    y = (pY * zinv) `mod` p

ePointDecompress :: PointCompressed -> ExtendedPoint
ePointDecompress (PointCompressed bs) =
    let cy    = fromBytes bs
        xSign = testBit cy 255
        y     = clearBit cy 255
        x     = recoverX y xSign
     in ExtendedPoint x y 1 ((x*y) `mod` p)

-- | Given y and the sign of x, recover x
recoverX :: Integer -> Bool -> Integer
recoverX y xSign = x''
  where
    x2 = (y*y-1) * modp_inv (curveD*y*y+1)
    x = expFast x2 ((p+3) `div` 8) p

    x'
        | (x*x - x2) `mod` p /= 0 = (x * modp_sqrt_m1) `mod` p
        | otherwise               = x

    x''
        | odd x' /= xSign = p - x'
        | otherwise       = x'

    modp_sqrt_m1 :: Integer
    !modp_sqrt_m1 = expFast 2 ((p-1) `div` 4) p

-- | Unserialize little endian
fromBytes :: ByteString -> Integer
fromBytes = os2ip . B.reverse

-- | Serialize little endian of a given size (32 bytes)
toBytes :: Integer -> ByteString
toBytes = B.reverse . i2ospOf_ 32

-- | Inverse modular p
modp_inv :: Integer -> Integer
modp_inv x = expFast x (p-2) p

-- | Base field 2^255-19 => 25519
p :: Integer
!p = 2^(255 ::Int) - 19

-- | Curve constant d
curveD :: Integer
!curveD = (-121665 * modp_inv 121666) `mod` p

-- | Group order
q :: Integer
!q = 2^(252 ::Int) + 27742317777372353535851937790883648493

-- | Base Point in extended form
pG :: ExtendedPoint
!pG = ExtendedPoint g_x g_y 1 ((g_x * g_y) `mod` p)
  where
    !g_y = (4 * modp_inv 5) `mod` p
    !g_x = recoverX g_y False
