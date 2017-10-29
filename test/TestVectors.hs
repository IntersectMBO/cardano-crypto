{-# LANGUAGE QuasiQuotes #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
module Main where

import Control.Arrow
import Data.String.Conv
import Data.Bifunctor
import Data.Maybe (fromJust)
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

type TestVectors = M.Map Path TestVector

data TestVector = TestVector {
    seed  :: ByteString
  , pass  :: C8.ByteString
  }

runTest :: TestVector -> (XPrv, XPub)
runTest TestVector{..} =
  let priv = generate (fst $ Hex.decode seed) pass
  in (priv, toXPub priv)

renderXprv :: XPrv -> T.Text
renderXprv = toS . Hex.encode . unXPrv

renderXpub :: XPub -> T.Text
renderXpub = toS . Hex.encode . unXPub

test1 :: TestVector
test1 = TestVector {
    seed = "000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f"
  , pass = "secret"
  }

main :: IO ()
main = do
  -- Write the markdown file on disk.
  T.writeFile "test-vectors.md" template


template :: T.Text
template =
  let test1_path = "m"
      test1_seed = toS $ seed test1
      test1_pass = toS $ pass test1
      (test1_xprv, test1_xpub) = bimap renderXprv renderXpub (runTest test1)
  in [text|
==Test Vectors==

===Test vector 1===

Seed (hex):  $test1_seed
Pwd (ASCII): $test1_pass

* Chain $test1_path
** ext pub: $test1_xpub
** ext prv: $test1_xprv

* Chain m/0<sub>H</sub>
** ext pub: _
** ext prv: _

* Chain m/0<sub>H</sub>/1
** ext pub: _
** ext prv: _

* Chain m/0<sub>H</sub>/1/2<sub>H</sub>
** ext pub: _
** ext prv: _

* Chain m/0<sub>H</sub>/1/2<sub>H</sub>/2
** ext pub: _
** ext prv: _

* Chain m/0<sub>H</sub>/1/2<sub>H</sub>/2/1000000000
** ext pub: _
** ext prv: _

|]
