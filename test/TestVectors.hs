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
import qualified Data.Map.Strict as M
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

runTest :: TestVector -> (XPrv, XPub)
runTest TestVector{..} = case (T.splitOn "/" path) of
  ["m"]  -> let priv = generate (fst $ Hex.decode seed) pass
            in (priv, toXPub priv)
  ("m":xs) -> go (generate (fst $ Hex.decode seed) pass) xs
  where
    go prv []     = (prv, toXPub prv)
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
    noPwd = def { pass = mempty }

main :: IO ()
main = T.writeFile "test-vectors.md" template

testVector :: TestVector -> T.Text
testVector tv =
  let test_path = renderPath (path tv)
      test_seed = toS (seed tv)
      test_pass = let p = toS (pass tv) in if p == mempty then "(empty)" else p
      (test_xprv, test_xpub) = bimap renderXprv renderXpub (runTest tv)
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
template = T.unlines (map testVector testVectors)
