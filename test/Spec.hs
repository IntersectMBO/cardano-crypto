module Main where

import           Control.Monad

import           Test.Tasty
import           Test.Tasty.QuickCheck

import qualified Crypto.ECC.Edwards25519 as Edwards25519
import           Cardano.Crypto.Wallet
import qualified Data.ByteString as B

data Ed = Ed Integer Edwards25519.Scalar

instance Show Ed where
    show (Ed i _) = "Edwards25519.Scalar " ++ show i
instance Eq Ed where
    (Ed x _) == (Ed y _) = x == y
instance Arbitrary Ed where
    arbitrary = do
        (Positive n) <- arbitrary `suchThat` (\(Positive i) -> i > 2)
        return (Ed n (Edwards25519.scalarFromInteger n))

testEdwards25519 =
    [ testProperty "add" $ \(Ed _ a) (Ed _ b) -> (ltc a .+ ltc b) == ltc (Edwards25519.scalarAdd a b)
    ]
  where
    (.+) = Edwards25519.pointAdd
    ltc = Edwards25519.scalarToPoint

testHdDerivation =
    [ testProperty "pub . sec-derivation = pub-derivation . pub" normalDerive ]
  where
    dummyChainCode = B.replicate 32 38
    normalDerive (Ed _ s) n =
        let prv = either error id $ xprv (Edwards25519.unScalar s `B.append` dummyChainCode)
            pub = toXPub prv
            cPrv = deriveXPrv prv DeriveNormal n
            cPub = deriveXPub pub n
         in unXPub (toXPub cPrv) === unXPub cPub


main :: IO ()
main = defaultMain $ testGroup "cardano-crypto"
    [ testGroup "edwards25519-arithmetic" testEdwards25519
    , testGroup "hd-derivation" testHdDerivation
    ]
