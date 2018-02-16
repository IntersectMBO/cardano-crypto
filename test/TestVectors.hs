{-# LANGUAGE QuasiQuotes #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE DataKinds #-}
module Main where

import Data.String.Conv
import Data.Bifunctor
import Data.Bits
import Data.Monoid
import Data.Word
import Data.List (findIndex)
import GHC.Exts
import qualified Basement.Sized.List as ListN
import qualified Data.Text as T
import qualified Data.Text.IO as T
import qualified Data.ByteString.Base16 as Hex
import qualified Data.ByteString.Char8 as C8
import Cardano.Crypto.Wallet
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import Data.ByteArray ()
import NeatInterpolation

import qualified Crypto.Encoding.BIP39 as BIP39
import qualified Crypto.Encoding.BIP39.English as BIP39English

type Path = T.Text

tvBIP39_24 = ( words "void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold"
             , maybe (error "listN") id
                $ ListN.toListN
                $ map BIP39.wordIndex [1964,368,565,1733,262,1749,1978,851,1588,1365,356,424,1241,62,1548,1289,823,1666,1338,1783,638,1634,945,1897])

data TestVectorType =
      TestVectorRaw ByteString
    | TestVectorBIP39 ([String], BIP39.MnemonicSentence 24)

data TestVector = TestVector
    { seed  :: TestVectorType
    , pass  :: C8.ByteString
    , path  :: Path
    , signedData :: C8.ByteString
    }

seedToMaster seed pass = generate (fst $ Hex.decode seed) pass

runTest :: TestVector -> XPrv
runTest tv@TestVector{..} = case (T.splitOn "/" path) of
  ["m"]    -> m
  ("m":xs) -> go m xs
  where
    (_,_,_,m) = getInfo tv

    go prv []     = prv
    go prv (x:xs) =
      let chainCode = toChaincode x
          prv'      = deriveXPrv DerivationScheme1 pass prv chainCode
      in go prv' xs

    toChaincode :: T.Text -> Word32
    toChaincode t
        | "'" `T.isInfixOf` t = toHard . read . toS . T.replace "'" mempty $ t
        | otherwise           = toSoft . read . toS . T.replace "'" mempty $ t

    toHard :: Word32 -> Word32
    toHard w
        | w >= 0x80000000 = error ("invalid harden index: " ++ show w)
        | otherwise       = (w .|. 0x80000000)

    toSoft :: Word32 -> Word32
    toSoft w
        | w >= 0x80000000 = error ("invalid harden index: " ++ show w)
        | otherwise       = w

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
def = TestVector
    { seed  = TestVectorBIP39 tvBIP39_24
    , pass = mempty
    , path = "m"
    , signedData = "Hello World"
    }

def2 = TestVector
    { seed  = TestVectorRaw "e35524a518034ddc1192e1dacd32c1ed3eaa3c3b131c88ed8e7e54c49a5d0998"
    , pass = mempty
    , path = "m"
    , signedData = "Hello World"
    }

--
-- Test Vectors
--

testVectors :: [TestVector]
testVectors =
  [ def
  , def { path = "m/0'" }
  , def { path = "m/1'" }
  , def { path = "m/0'/1'" }
  , def { path = "m/0'/1'/2'" }
  , def { path = "m/0'/1'/2'/2'" }
  , def { path = "m/0'/1'/2'/2'/10000'" }
  , def2
  , def2 { path = "m/0'" }
  ]


{-
Test Vector 2:

Seed:

-}

bip44 :: [TestVector]
bip44 = [
{-
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
  -}
  -- With empty pwds
  -- m/44'/1815'/0'
    bip44NoPwd { path = bip44Path "0'" }
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

englishDict = BIP39.Dictionary
                (\w -> BIP39English.words !! fromIntegral (BIP39.unWordIndex w))
                (undefined)
                " "

getInfo :: TestVector -> (T.Text, T.Text, T.Text, XPrv)
getInfo tv =
    case seed tv of
        TestVectorBIP39 (w, indexes) ->
            let seed64        = BIP39.sentenceToSeed @24 indexes englishDict "TREZOR"
                seedTruncated = B.drop 32 seed64
                m             = seedToMaster (Hex.encode seedTruncated) (pass tv)
             in (toS (unwords w), toS (Hex.encode seed64), toS (Hex.encode seedTruncated), m)
        TestVectorRaw seedRaw ->
             ("", "", toS seedRaw, seedToMaster seedRaw (pass tv))

testVector :: TestVector -> T.Text
testVector tv =
    let (test_words, test_seed64, test_seed, m) = getInfo tv
        test_path = renderPath (path tv)
        test_signdata = toS (signedData tv)
        test_master = renderXprv m
      -- test_pass = let p = toS (pass tv) in if p == mempty then "(empty)" else p
        p = runTest tv
        (test_xprv, test_xpub) = (renderXprv p, renderXpub (toXPub p))
        test_signature = toS (Hex.encode $ unXSignature $ sign (pass tv) p (signedData tv))
     in [text|

```
Words       : `"$test_words"`
Seed64 (hex): `$test_seed64`
Seed (hex):  `$test_seed`
Master (hex): `$test_master`
Signed Data: `"$test_signdata"`
```

* *Chain* $test_path
  * *xPub*: `$test_xpub`
  * *xPrv*: `$test_xprv`
  * *signature*: `$test_signature`

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
