{-# LANGUAGE GADTs                #-}
{-# LANGUAGE DataKinds            #-}
{-# LANGUAGE KindSignatures       #-}
{-# LANGUAGE TypeFamilies         #-}
{-# LANGUAGE TypeOperators        #-}
{-# LANGUAGE TypeApplications     #-}
{-# LANGUAGE NoImplicitPrelude    #-}
{-# LANGUAGE ConstraintKinds      #-}
{-# LANGUAGE ScopedTypeVariables  #-}
{-# LANGUAGE UndecidableInstances #-}
{-# LANGUAGE OverloadedStrings    #-}
{-# LANGUAGE RecordWildCards      #-}
module Crypto.Encoding.BIP39
    ( Entropy
    , MnemonicSentence
    , Dictionary(..)
    , WordIndex
    , wordIndex
    , unWordIndex
    , Seed
    , Passphrase
    , entropyRaw
    , toEntropy
    , entropyToWords
    , sentenceToSeed
    -- * Tests
    , tests
    ) where

import           Basement.String (String)
import qualified Basement.String as String
import           Basement.Nat
import qualified Basement.Sized.List as ListN

import           Foundation.Check

import           Data.Bits
import           Data.Monoid
import           Data.Word
import           Data.List (intersperse, elemIndex)
import qualified Data.ByteArray as BA (index)
import           Data.ByteString (ByteString)
import qualified Data.ByteString as BS

import           Data.Proxy
import           Data.Kind (Constraint)

import           GHC.TypeLits
import           GHC.Exts (IsList(..))

import           Crypto.Hash (hashWith, SHA256(..), SHA512(..))
import           Crypto.Number.Serialize (os2ip)
import qualified Crypto.KDF.PBKDF2 as PBKDF2

import           Prelude hiding (String)

import qualified Crypto.Encoding.BIP39.English as English (words)

------------------------------------------------------------------------
-- Basic Definitions
------------------------------------------------------------------------

data Dictionary = Dictionary
    { dictionaryIndexToWord :: WordIndex -> String
    , dictionaryWordToIndex :: String -> WordIndex
    , dictionaryWordSeparator :: String
        -- ^ joining string (e.g. space for english)
    }

type MnemonicSentence (mw :: Nat) = ListN.ListN mw WordIndex

type Passphrase = String

type Seed = ByteString

newtype WordIndex = WordIndex { unWordIndex :: Word16 } -- 2048 max
    deriving (Show,Eq)

wordIndex :: Word16 -> WordIndex
wordIndex w
    | w > 2047  = error ("internal error: word index should be between 0 to 2047. " ++ show w)
    | otherwise = WordIndex w

type ValidEntropySize (n :: Nat) = Elem n '[128,160,192,224,256]

type family Elem (e :: Nat) (l :: [Nat]) :: Constraint where
    Elem e '[] = TypeError ('Text "offset: field "
             ':<>: 'ShowType e
             ':<>: 'Text " not elements of valids values")
    Elem e (e ': _) = ()
    Elem e (_ ': xs) = Elem e xs

------------------------------------------------------------------------
-- Converting to binary seed
------------------------------------------------------------------------

-- | Number of Words related to a specific entropy size in bits
type family MnemonicWords (n :: Nat) :: Nat where
    MnemonicWords 128 = 12 
    MnemonicWords 160 = 15
    MnemonicWords 192 = 18
    MnemonicWords 224 = 21
    MnemonicWords 256 = 24

-- | Number of bits of checksum related to a specific entropy size in bits
type family CheckSumBits (n :: Nat) :: Nat where
    CheckSumBits 128 = 4
    CheckSumBits 160 = 5
    CheckSumBits 192 = 6
    CheckSumBits 224 = 7
    CheckSumBits 256 = 8

checksum :: forall csz . KnownNat csz => ByteString -> Checksum csz
checksum bs = Checksum (hashWith SHA256 bs `BA.index` 0)
  --where
  --  csz = natVal (Proxy @csz)

data Entropy (n :: Nat) = Entropy ByteString (Checksum (CheckSumBits n))
    deriving (Show,Eq)

-- | Get the raw binary associated with the entropy
entropyRaw :: Entropy n -> ByteString
entropyRaw (Entropy bs _) = bs

newtype Checksum (bits :: Nat) = Checksum Word8
    deriving (Show,Eq)

-- | Create a specific entropy type of known size from a raw bytestring
toEntropy :: forall n csz
           . (KnownNat n, KnownNat csz, NatWithinBound Int n, ValidEntropySize n, CheckSumBits n ~ csz)
          => ByteString
          -> Maybe (Entropy n)
toEntropy bs
    | BS.length bs*8 == natValInt (Proxy @n) = Just $ Entropy bs (checksum @csz bs)
    | otherwise                              = Nothing

-- | Given an entropy of size n, Create a list 
entropyToWords :: forall n csz mw
                . (KnownNat n, KnownNat csz, KnownNat mw, NatWithinBound Int n, NatWithinBound Int mw, ValidEntropySize n, CheckSumBits n ~ csz, MnemonicWords n ~ mw)
               => Entropy n
               -> MnemonicSentence mw
entropyToWords (Entropy bs (Checksum w)) =
    maybe (error "toListN_") id $ ListN.toListN $ reverse $ loop mw g
  where
    g = (os2ip (BS.reverse bs) `shiftL` fromIntegral csz) .|. (fromIntegral w `shiftR` (8 - fromIntegral csz))
    csz = natVal (Proxy @csz)
    mw  = natVal (Proxy @mw)
    loop nbWords acc
        | nbWords == 0 = []
        | otherwise    =
            let (acc', d) = acc `divMod` 2048
             in wordIndex (fromIntegral d) : loop (nbWords - 1) acc'

-- | Create a seed from mmemonic sentence and passphrase using the BIP39 algorithm 
sentenceToSeed :: MnemonicSentence mw -- ^ Mmenomic sentence of mw words
               -> Dictionary          -- ^ Dictionary of words/indexes
               -> Passphrase          -- ^ Binary Passphrase used to generate
               -> Seed
sentenceToSeed mw Dictionary{..} passphrase =
    PBKDF2.generate (PBKDF2.prfHMAC SHA512)
                    (PBKDF2.Parameters 2048 64)
                    sentence
                    (toData ("mnemonic" `mappend` passphrase))
  where
    sentence = toData $ mconcat $ intersperse dictionaryWordSeparator $ map dictionaryIndexToWord $ ListN.unListN mw
    toData = String.toBytes String.UTF8

tests :: Test
tests = Group "BIP39" $ map runTest testVectors

data TestVector = TestVector
    { testVectorInput  :: ByteString
    , testVectorWords  :: ByteString
    , testVectorWIndex :: [Word16]
    , testVectorSeed   :: ByteString
    , testVectorXprv   :: ByteString
    }

runTest :: TestVector -> Test
runTest tv =
    case BS.length (testVectorInput tv) * 8 of
        128 -> go (Proxy @128)
        160 -> go (Proxy @160)
        192 -> go (Proxy @192)
        224 -> go (Proxy @224)
        256 -> go (Proxy @256)
        _   -> error "invalid size"
  where
    testVectorWIndex' = map wordIndex . testVectorWIndex

    go :: forall n csz mw
        . (KnownNat n, KnownNat csz, KnownNat mw, NatWithinBound Int mw, NatWithinBound Int n, ValidEntropySize n, CheckSumBits n ~ csz, MnemonicWords n ~ mw)
       => Proxy n -> Test
    go proxyN = CheckPlan ("test " <> fromList (show $ natVal proxyN)) $ do
        case toEntropy @n (testVectorInput tv) of
            Nothing -> error "entropy generation error" 
            Just e -> do
                let w = entropyToWords e
                    dictLookup (WordIndex x) = English.words !! fromIntegral x
                    dictRevLookup x = maybe (error $ "word not in the english dictionary: " <> toList x) (wordIndex . fromIntegral) $ x `elemIndex` English.words
                    seed = sentenceToSeed w (Dictionary dictLookup dictRevLookup " ") "TREZOR"
                validate "words equal" (ListN.unListN w === testVectorWIndex' tv)
                validate "seed equal" (seed === testVectorSeed tv)

testVectors :: [TestVector]
testVectors = 
    [ TestVector
        "\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f"
        "legal winner thank year wave sausage worth useful legal winner thank yellow"
        [1019,2015,1790,2039,1983,1533,2031,1919,1019,2015,1790,2040]
        "\x2e\x89\x05\x81\x9b\x87\x23\xfe\x2c\x1d\x16\x18\x60\xe5\xee\x18\x30\x31\x8d\xbf\x49\xa8\x3b\xd4\x51\xcf\xb8\x44\x0c\x28\xbd\x6f\xa4\x57\xfe\x12\x96\x10\x65\x59\xa3\xc8\x09\x37\xa1\xc1\x06\x9b\xe3\xa3\xa5\xbd\x38\x1e\xe6\x26\x0e\x8d\x97\x39\xfc\xe1\xf6\x07"
        "xprv9s21ZrQH143K2gA81bYFHqU68xz1cX2APaSq5tt6MFSLeXnCKV1RVUJt9FWNTbrrryem4ZckN8k4Ls1H6nwdvDTvnV7zEXs2HgPezuVccsq"
    , TestVector
        "\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80"
        "letter advice cage absurd amount doctor acoustic avoid letter advice cage above"
        [1028,32,257,8,64,514,16,128,1028,32,257,4]
        "\xd7\x1d\xe8\x56\xf8\x1a\x8a\xcc\x65\xe6\xfc\x85\x1a\x38\xd4\xd7\xec\x21\x6f\xd0\x79\x6d\x0a\x68\x27\xa3\xad\x6e\xd5\x51\x1a\x30\xfa\x28\x0f\x12\xeb\x2e\x47\xed\x2a\xc0\x3b\x5c\x46\x2a\x03\x58\xd1\x8d\x69\xfe\x4f\x98\x5e\xc8\x17\x78\xc1\xb3\x70\xb6\x52\xa8"
        "xprv9s21ZrQH143K2shfP28KM3nr5Ap1SXjz8gc2rAqqMEynmjt6o1qboCDpxckqXavCwdnYds6yBHZGKHv7ef2eTXy461PXUjBFQg6PrwY4Gzq"
    , TestVector
        "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong"
        [2047,2047,2047,2047,2047,2047,2047,2047,2047,2047,2047,2037]
        "\xac\x27\x49\x54\x80\x22\x52\x22\x07\x9d\x7b\xe1\x81\x58\x37\x51\xe8\x6f\x57\x10\x27\xb0\x49\x7b\x5b\x5d\x11\x21\x8e\x0a\x8a\x13\x33\x25\x72\x91\x7f\x0f\x8e\x5a\x58\x96\x20\xc6\xf1\x5b\x11\xc6\x1d\xee\x32\x76\x51\xa1\x4c\x34\xe1\x82\x31\x05\x2e\x48\xc0\x69"
        "xprv9s21ZrQH143K2V4oox4M8Zmhi2Fjx5XK4Lf7GKRvPSgydU3mjZuKGCTg7UPiBUD7ydVPvSLtg9hjp7MQTYsW67rZHAXeccqYqrsx8LcXnyd"
    , TestVector
        "\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f"
        "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal will"
        [1019,2015,1790,2039,1983,1533,2031,1919,1019,2015,1790,2039,1983,1533,2031,1919,1019,2009]
        "\xf2\xb9\x45\x08\x73\x2b\xcb\xac\xbc\xc0\x20\xfa\xef\xec\xfc\x89\xfe\xaf\xa6\x64\x9a\x54\x91\xb8\xc9\x52\xce\xde\x49\x6c\x21\x4a\x0c\x7b\x3c\x39\x2d\x16\x87\x48\xf2\xd4\xa6\x12\xba\xda\x07\x53\xb5\x2a\x1c\x7a\xc5\x3c\x1e\x93\xab\xd5\xc6\x32\x0b\x9e\x95\xdd"
        "xprv9s21ZrQH143K3Lv9MZLj16np5GzLe7tDKQfVusBni7toqJGcnKRtHSxUwbKUyUWiwpK55g1DUSsw76TF1T93VT4gz4wt5RM23pkaQLnvBh7"
{-
    , TestVector
        "\xf5\x85\xc1\x1a\xec\x52\x0d\xb5\x7d\xd3\x53\xc6\x95\x54\xb2\x1a\x89\xb2\x0f\xb0\x65\x09\x66\xfa\x0a\x9d\x6f\x74\xfd\x98\x9d\x8f"
        "void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold"
        [1964,368,565,1733,262,1749,1978,851,1588,1365,356,424,1241,62,1548,1289,823,1666,1338,1783,638,1634,945,1897]
        "\x01\xf5\xbc\xed\x59\xde\xc4\x8e\x36\x2f\x2c\x45\xb5\xde\x68\xb9\xfd\x6c\x92\xc6\x63\x4f\x44\xd6\xd4\x0a\xab\x69\x05\x65\x06\xf0\xe3\x55\x24\xa5\x18\x03\x4d\xdc\x11\x92\xe1\xda\xcd\x32\xc1\xed\x3e\xaa\x3c\x3b\x13\x1c\x88\xed\x8e\x7e\x54\xc4\x9a\x5d\x09\x98"
        "xprv9s21ZrQH143K39rnQJknpH1WEPFJrzmAqqasiDcVrNuk926oizzJDDQkdiTvNPr2FYDYzWgiMiC63YmfPAa2oPyNB23r2g7d1yiK6WpqaQS"
-}
    ]
