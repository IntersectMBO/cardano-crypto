module Main where

import           Control.Monad

import           Test.Tasty
import           Test.Tasty.QuickCheck

import qualified Crypto.ECC.Edwards25519 as Edwards25519

data Ed = Ed Integer Edwards25519.Scalar

instance Show Ed where
    show (Ed i _) = show i
instance Eq Ed where
    (Ed x _) == (Ed y _) = x == y
instance Arbitrary Ed where
    arbitrary = do
        (Positive n) <- arbitrary
        return (Ed n (Edwards25519.scalarFromInteger n))

testEdwards25519 =
    [ testProperty "add" $ \(Ed _ a) (Ed _ b) -> (ltc a .+ ltc b) == ltc (Edwards25519.scalarAdd a b)
    ]
  where
    (.+) = Edwards25519.pointAdd
    ltc = Edwards25519.scalarToPoint

main :: IO ()
main = defaultMain $ testGroup "cardano-crypto"
    [ testGroup "edwards25519-arithmetic" testEdwards25519
    ]
