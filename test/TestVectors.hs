{-# LANGUAGE QuasiQuotes #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
module Main where

import Data.String.Conv
import Data.Bifunctor
import Data.Monoid
import Data.Word
import qualified Data.Text as T
import qualified Data.Text.IO as T
import qualified Data.ByteString.Base16 as Hex
import qualified Data.ByteString.Char8 as C8
import Cardano.Crypto.Wallet
import Data.ByteString (ByteString)
import Data.ByteArray ()
import NeatInterpolation

type Path = T.Text

data TestVector = TestVector {
    seed  :: ByteString
  , pass  :: C8.ByteString
  , path  :: Path
  }

runTest :: TestVector -> XPrv
runTest TestVector{..} = case (T.splitOn "/" path) of
  ["m"]    -> generate (fst $ Hex.decode seed) pass
  ("m":xs) -> go (generate (fst $ Hex.decode seed) pass) xs
  where
    go prv []     = prv
    go prv (x:xs) =
      let chainCode = toChaincode x
          prv'      = deriveXPrv pass prv chainCode
      in go prv' xs

    toChaincode :: T.Text -> Word32
    toChaincode = read . toS . T.replace "'" mempty

renderXprv :: XPrv -> T.Text
renderXprv = toS . Hex.encode . unXPrv

renderXpub :: XPub -> T.Text
renderXpub = toS . Hex.encode . unXPub

renderPath :: Path -> T.Text
renderPath p = (T.intercalate "/" $ map render' (T.splitOn "/" p)) <> " (" <> p <> ")"
  where
    render' x
      | "'" `T.isInfixOf` x = T.replace "'" "<sub>H</sub>" x
      | otherwise  = x

def :: TestVector
def = TestVector {
    seed = "000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f"
  , pass = "secret"
  , path = "m"
  }

--
-- Test Vectors
--

testVectors :: [TestVector]
testVectors = [
    def
  , def { path = "m/0'" }
  , def { path = "m/0'/1'" }
  , def { path = "m/0'/1'/2'" }
  , def { path = "m/0'/1'/2'/2'" }
  , def { path = "m/0'/1'/2'/2'/1000000000'" }
  , noPwd
  , noPwd { path = "m/0'" }
  , noPwd { path = "m/0'/1'" }
  , noPwd { path = "m/0'/1'/2'" }
  , noPwd { path = "m/0'/1'/2'/2'" }
  , noPwd { path = "m/0'/1'/2'/2'/1000000000'" }
  ]
  where
    noPwd           = def { pass = mempty }


{-
Test Vector 2:

Seed:

-}

bip44 :: [TestVector]
bip44 = [
  -- m/44'/1815'/0'
    bip44 { path = bip44Path "0'" }
  -- m/44'/1815'/0'/0
  , bip44 { path = bip44Path "0'/0'" }
  -- m/44'/1815'/0'/1
  , bip44 { path = bip44Path "0'/1'" }
  -- m/44'/1815'/0'/2
  , bip44 { path = bip44Path "0'/2'" }
  -- m/44'/1815'/0'/0/0
  , bip44 { path = bip44Path "0'/0'/0'" }
  -- m/44'/1815'/0'/0/1
  , bip44 { path = bip44Path "0'/0'/1'" }
  -- m/44'/1815'/0'/0/2
  , bip44 { path = bip44Path "0'/0'/2'" }
  -- With empty pwds
  -- m/44'/1815'/0'
  , bip44NoPwd { path = bip44Path "0'" }
  -- m/44'/1815'/1'
  , bip44NoPwd { path = bip44Path "1'" }
  -- m/44'/1815'/2'/1'
  , bip44NoPwd { path = bip44Path "2'/1'" }
  -- m/44'/1815'/3'/2147483647'
  , bip44NoPwd { path = bip44Path "3'/2147483647'" }
  -- m/44'/1815'/4'/2147483647'/1'
  , bip44NoPwd { path = bip44Path "4'/2147483647'/1" }
  -- m/44'/1815'/5'/2147483647'/2147483646'
  , bip44NoPwd { path = bip44Path "5'/2147483647'/2147483646'" }
  ]
  where
    coinType        = (1815 :: Word32) -- Year Ada Lovelace was born
    -- BIP-44-style: m / purpose' / coin_type' / account' / change / address_index
    bip44PathPrefix = "m/44'/" <> toS (show coinType) <> "'"
    bip44           = def { path = bip44PathPrefix }
    bip44Path rest  = bip44PathPrefix <> "/" <> rest
    bip44NoPwd      = bip44 { pass = mempty }

testVector :: TestVector -> T.Text
testVector tv =
  let test_path = renderPath (path tv)
      test_seed = toS (seed tv)
      test_pass = let p = toS (pass tv) in if p == mempty then "(empty)" else p
      (test_xprv, test_xpub) = let p = (runTest tv) in (renderXprv p, renderXpub (toXPub p))
  in [text|

```
Seed (hex):  $test_seed
Pwd (ASCII): $test_pass
```

* *Chain* $test_path
  * *xPub*: `$test_xpub`
  * *xPrv*: `$test_xprv`

|]

template :: T.Text
template = T.unlines (header : map testVector testVectors <>
                     (bip44Header : map testVector bip44))
  where
    header = [text|
This test vectors uses the `Cardano.Crypto.Wallet` primitives to produce extended
private keys which are _encrypted_ with a passphrase. A passphrase can be empty as well.
Under this schema, we support only hardened key derivation.
    |]

    bip44Header  = [text|
## A note on BIP-44 derivation

BIP-44 proposes the following path for addresses:

```
m / purpose' / coin_type' / account' / change / address_index
```

Where the last 2 levels are composed by non-hardened keys, but currently we don't
support non-hardened derivation for private keys, only for public keys.
    |]


main :: IO ()
main = do
  T.writeFile "test-vectors.md" template
