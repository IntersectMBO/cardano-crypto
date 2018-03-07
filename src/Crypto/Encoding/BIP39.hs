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
{-# LANGUAGE BangPatterns         #-}
{-# LANGUAGE FlexibleInstances    #-}
{-# LANGUAGE MultiParamTypeClasses #-}
module Crypto.Encoding.BIP39
    ( -- * Entropy
      Entropy
    , ValidEntropySize
    , Checksum
    , ValidChecksumSize
    , MnemonicWords
    , toEntropy
    , entropyRaw
    , entropyChecksum

    , entropyToWords
    , wordsToEntropy

    , -- * Seed
      Seed
    , Passphrase
    , sentenceToSeed
    , phraseToSeed

    , -- * Mnemonic Sentence
      MnemonicSentence
    , MnemonicPhrase
    , ValidMnemonicSentence
    , mnemonicPhrase
    , checkMnemonicPhrase
    , mnemonicPhraseToMnemonicSentence
    , mnemonicSentenceToMnemonicPhrase
    , mnemonicSentenceToString
    , mnemonicPhraseToString
    , translateTo
    , -- ** Dictionary
      Dictionary(..)
    , WordIndex
    , wordIndex
    , unWordIndex

    , -- * helpers
      ConsistentEntropy
    , CheckSumBits
    , Elem
    ) where

import Prelude ((-), (*), (+), div, divMod, (^), fromIntegral)

import           Basement.String (String)
import qualified Basement.String as String
import           Basement.Nat
import qualified Basement.Sized.List as ListN
import           Basement.NormalForm
import           Basement.Compat.Typeable
import           Basement.Numerical.Number (IsIntegral(..))
import           Basement.Imports

import           Foundation.Check

import           Control.Monad (replicateM)
import           Data.Bits
import           Data.Maybe (fromMaybe)
import           Data.List (reverse)
import           Data.ByteArray (ByteArrayAccess, ByteArray)
import qualified Data.ByteArray as BA
import           Data.ByteString (ByteString)
import qualified Data.ByteString as BS

import           Data.Proxy

import           GHC.Exts (IsList(..), IsString)

import           Crypto.Hash (hashWith, SHA256(..))
import           Crypto.Number.Serialize (os2ip, i2ospOf_)
import qualified Crypto.KDF.PBKDF2 as PBKDF2

import           Crypto.Encoding.BIP39.Dictionary

-- -------------------------------------------------------------------------- --
-- Entropy
-- -------------------------------------------------------------------------- --

-- | this is the `Checksum` of a given 'Entropy'
--
-- the 'Nat' type parameter represent the size, in bits, of this checksum.
newtype Checksum (bits :: Nat) = Checksum Word8
    deriving (Show, Eq, Typeable, NormalForm)

checksum :: forall csz ba . (KnownNat csz, ByteArrayAccess ba)
         => ba -> Checksum csz
checksum bs = Checksum $ (hashWith SHA256 bs `BA.index` 0) `shiftR` (8 - csz)
  where
    csz = fromInteger $ natVal (Proxy @csz)

type ValidChecksumSize (ent :: Nat) (csz :: Nat) =
    ( KnownNat csz, NatWithinBound Int csz
    , Elem csz '[4, 5, 6, 7, 8]
    , CheckSumBits ent ~ csz
    )

-- | Number of bits of checksum related to a specific entropy size in bits
type family CheckSumBits (n :: Nat) :: Nat where
    CheckSumBits 128 = 4
    CheckSumBits 160 = 5
    CheckSumBits 192 = 6
    CheckSumBits 224 = 7
    CheckSumBits 256 = 8

-- | BIP39's entropy is a byte array of a given size (in bits, see
-- 'ValidEntropySize' for the valid size).
--
-- To it is associated
data Entropy (n :: Nat) = Entropy
     { entropyRaw :: !ByteString
        -- ^ Get the raw binary associated with the entropy
     , entropyChecksum :: !(Checksum (CheckSumBits n))
        -- ^ Get the checksum of the Entropy
     }
  deriving (Show, Eq, Typeable)
instance NormalForm (Entropy n) where
    toNormalForm (Entropy !_ cs) = toNormalForm cs
instance Arbitrary (Entropy 128) where
    arbitrary = fromMaybe (error "arbitrary (Entropy 128)") . toEntropy . BS.pack <$> replicateM 16 arbitrary
instance Arbitrary (Entropy 160) where
    arbitrary = fromMaybe (error "arbitrary (Entropy 160)") . toEntropy . BS.pack <$> replicateM 20 arbitrary
instance Arbitrary (Entropy 192) where
    arbitrary = fromMaybe (error "arbitrary (Entropy 192)") . toEntropy . BS.pack <$> replicateM 24 arbitrary
instance Arbitrary (Entropy 224) where
    arbitrary = fromMaybe (error "arbitrary (Entropy 224)") . toEntropy . BS.pack <$> replicateM 28 arbitrary
instance Arbitrary (Entropy 256) where
    arbitrary = fromMaybe (error "arbitrary (Entropy 256)") . toEntropy . BS.pack <$> replicateM 32 arbitrary

-- | Type Constraint Alias to check a given 'Nat' is valid for an entropy size
--
-- i.e. it must be one of the following: 128, 160, 192, 224, 256.
--
type ValidEntropySize (n :: Nat) =
    ( KnownNat n, NatWithinBound Int n
    , Elem n '[128, 160, 192, 224, 256]
    )

-- | Create a specific entropy type of known size from a raw bytestring
toEntropy :: forall n csz ba
           . (ValidEntropySize n, ValidChecksumSize n csz, ByteArrayAccess ba)
          => ba
          -> Maybe (Entropy n)
toEntropy bs
    | BA.length bs*8 == natValInt (Proxy @n) = Just $ Entropy (BA.convert bs) (checksum @csz bs)
    | otherwise                              = Nothing

toEntropyCheck :: forall n csz ba
                . (ValidEntropySize n, ValidChecksumSize n csz, ByteArrayAccess ba)
               => ba
               -> Checksum csz
               -> Maybe (Entropy n)
toEntropyCheck bs s = case toEntropy bs of
    Nothing -> Nothing
    Just e@(Entropy _ cs) | cs == s   -> Just e
                          | otherwise -> Nothing

-- | Number of Words related to a specific entropy size in bits
type family MnemonicWords (n :: Nat) :: Nat where
    MnemonicWords 128 = 12
    MnemonicWords 160 = 15
    MnemonicWords 192 = 18
    MnemonicWords 224 = 21
    MnemonicWords 256 = 24

-- | Type Constraint Alias to check the entropy size, the number of mnemonic
-- words and the checksum size is consistent. i.e. that the following is true:
--
-- |  entropysize  | checksumsize | entropysize + checksumsize | mnemonicsize |
-- +---------------+--------------+----------------------------+--------------+
-- |          128  |            4 |                       132  |          12  |
-- |          160  |            5 |                       165  |          15  |
-- |          192  |            6 |                       198  |          18  |
-- |          224  |            7 |                       231  |          21  |
-- |          256  |            8 |                       264  |          24  |
--
-- This type constraint alias also perform all the GHC's cumbersome type level
-- literal handling.
--
type ConsistentEntropy ent mw csz =
    ( ValidEntropySize ent
    , ValidChecksumSize ent csz
    , ValidMnemonicSentence mw
    , MnemonicWords ent ~ mw
    )

-- | retrieve the initial entropy from a given 'MnemonicSentence'
--
-- This function validate the retrieved 'Entropy' is valid, i.e. that the
-- checksum is correct.
-- This means you should not create a new 'Entropy' from a 'MnemonicSentence',
-- instead, you should use a Random Number Generator to create a new 'Entropy'.
--
wordsToEntropy :: forall ent csz mw
                . ConsistentEntropy ent mw csz
               => MnemonicSentence mw
               -> Maybe (Entropy ent)
wordsToEntropy (MnemonicSentence ms) =
    let -- we don't revese the list here, we know that the first word index
        -- is the highest first 11 bits of the entropy.
        entropy         = ListN.foldl' (\acc x -> acc `shiftL` 11 + toInteger (unWordIndex x)) 0 ms
        initialEntropy :: ByteString
        initialEntropy = i2ospOf_ nb (entropy `shiftR` fromInteger checksumsize)
        cs = Checksum $ fromInteger (entropy .&. mask)
     in toEntropyCheck initialEntropy cs
  where
    checksumsize = natVal (Proxy @csz)
    entropysize  = natVal (Proxy @ent)
    nb  = fromInteger entropysize `div` 8
    mask = 2 ^ checksumsize - 1

-- | Given an entropy of size n, Create a list
--
entropyToWords :: forall n csz mw . ConsistentEntropy n mw csz
               => Entropy n
               -> MnemonicSentence mw
entropyToWords (Entropy bs (Checksum w)) =
    fromList $ reverse $ loop mw g
  where
    g = (os2ip bs `shiftL` fromIntegral csz) .|. fromIntegral w
    csz = natVal (Proxy @csz)
    mw  = natVal (Proxy @mw)
    loop nbWords acc
        | nbWords == 0 = []
        | otherwise    =
            let (acc', d) = acc `divMod` 2048
             in wordIndex (fromIntegral d) : loop (nbWords - 1) acc'

-- -------------------------------------------------------------------------- --
-- Seed
-- -------------------------------------------------------------------------- --

newtype Seed = Seed ByteString
  deriving (Show, Eq, Ord, Typeable, Semigroup, Monoid, ByteArrayAccess, ByteArray, IsString)

type Passphrase = String

-- | Create a seed from 'MmemonicSentence' and 'Passphrase' using the BIP39
-- algorithm.
sentenceToSeed :: ValidMnemonicSentence mw
               => MnemonicSentence mw -- ^ 'MmenomicPhrase' of mw words
               -> Dictionary          -- ^  Dictionary' of words/indexes
               -> Passphrase          -- ^ 'Passphrase' used to generate
               -> Seed
sentenceToSeed mw dic =
    phraseToSeed (mnemonicSentenceToMnemonicPhrase dic mw) dic

-- | Create a seed from 'MmemonicPhrase' and 'Passphrase' using the BIP39
-- algorithm.
phraseToSeed :: ValidMnemonicSentence mw
             => MnemonicPhrase mw -- ^ 'MmenomicPhrase' of mw words
             -> Dictionary        -- ^  Dictionary' of words/indexes
             -> Passphrase        -- ^ 'Passphrase' used to generate
             -> Seed
phraseToSeed mw dic passphrase =
    PBKDF2.fastPBKDF2_SHA512
                    (PBKDF2.Parameters 2048 64)
                    sentence
                    (toData ("mnemonic" `mappend` passphrase))
  where
    sentence = toData $ mnemonicPhraseToString dic mw
    toData = String.toBytes String.UTF8
