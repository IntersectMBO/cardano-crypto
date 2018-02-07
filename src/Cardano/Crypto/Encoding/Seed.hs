-- |
-- Module      : Cardano.Crypto.Encoding.Seed
-- Description : tools relating to Paper Wallet
-- Maintainer  : nicolas.diprima@iohk.io
--
-- implementation of the proposal specification for Paper Wallet
-- see https://github.com/input-output-hk/cardano-specs/blob/master/proposals/0001-PaperWallet.md
--
-- however we took allow more genericity in the implementation and to allow
-- not only 12 mnemonic words to freeze but also 15, 18 and 21.
--
-- because the output mnemonic words is always 3 words longer (for the IV)
-- we cannot use 24 words long mnemonic sentence.
--
-- assumption:
--
-- * we use 'PBKDF2' with 'HMAC 512' to generap the OTP.
-- * we use 10000 iteration for the PBKDF2
-- * we use the 4 bytes "IOHK" for the CONSTANT
--

{-# LANGUAGE Rank2Types           #-}
{-# LANGUAGE DataKinds            #-}
{-# LANGUAGE TypeFamilies         #-}
{-# LANGUAGE TypeOperators        #-}
{-# LANGUAGE TypeApplications     #-}
{-# LANGUAGE NoImplicitPrelude    #-}
{-# LANGUAGE ConstraintKinds      #-}
{-# LANGUAGE OverloadedStrings    #-}
{-# LANGUAGE ScopedTypeVariables  #-}

module Cardano.Crypto.Encoding.Seed
    ( Entropy
    , Passphrase
    , MnemonicSentence
    , ConsistentEntropy
    , scramble
    , unscramble

    , IVSizeWords
    , IVSizeBits
    ) where

import Foundation
import Basement.Nat

import           Data.Bits (xor)
import           Data.List (zip)
import Crypto.Encoding.BIP39
import qualified Crypto.KDF.PBKDF2 as PBKDF2
import Crypto.Random (MonadRandom (..))

import Data.ByteString (ByteString)
import qualified Data.ByteString as B

type IVSizeWords = 3
type IVSizeBits  = 32

ivSizeBytes :: Int
ivSizeBytes = 4

constant :: ByteString
constant = "IOHK"

-- | Number of iteration of the PBKDF2
iterations :: Int
iterations = 10000

-- | scamble the given entropy into an entropy slighly larger.
--
-- This entropy can then be used to be converted to a mnemonic sentence:
--
-- @
-- freeze mnemonics passphrase = entropyToWords <$> scramble entropy passphrase
--   where
--     entropy = case wordsToEntropy mnemonics of
--         Nothing -> error "mnemonic to entropy failed"
--         Just e  -> e
-- @
scramble :: forall entropysizeI entropysizeO mnemonicsize scramblesize csI csO randomly
         . ( ConsistentEntropy entropysizeI mnemonicsize csI
           , ConsistentEntropy entropysizeO scramblesize csO
           , (mnemonicsize + IVSizeWords) ~ scramblesize
           , (entropysizeI + IVSizeBits)  ~ entropysizeO
           , MonadRandom randomly
           )
         => Entropy entropysizeI -> Passphrase -> randomly (Entropy entropysizeO)
scramble e passphrase = do
    iv <- getRandomBytes ivSizeBytes
    let salt = iv <> constant
    let otp = PBKDF2.fastPBKDF2_SHA512
                    (PBKDF2.Parameters iterations entropySize)
                    passphrase
                    salt
    let ee = B.pack $ fmap (uncurry xor) $ zip (B.unpack otp) (B.unpack $ entropyRaw e)
    pure $ case toEntropy @entropysizeO (iv <> ee) of
        Nothing -> error "scramble: the function BIP39.toEntropy returned an unexpected error"
        Just e' -> e'
  where
    entropySize = fromIntegral (natVal (Proxy @entropysizeI)) `div` 8

-- |
-- The reverse operation of 'scramble'
--
-- This function recover the original entropy from the given scrambled entropy
-- and the associated password.
--
-- @
-- recover scrambled passphrase = entropyToWords @entropysizeO .
--     unscramble @entropysizeI @entropysizeO entropyScrambled passphrase
--   where
--     entropyScrambled = case wordsToEntropy @entropysizeI scrambled of
--         Nothing -> error "mnemonic to entropy failed"
--         Just e  -> e
-- @
--
unscramble :: forall entropysizeI entropysizeO mnemonicsize scramblesize csI csO
           . ( ConsistentEntropy entropysizeI scramblesize csI
             , ConsistentEntropy entropysizeO mnemonicsize csO
             , (mnemonicsize + IVSizeWords) ~ scramblesize
             , (entropysizeO + IVSizeBits)  ~ entropysizeI
             )
          => Entropy entropysizeI
          -> Passphrase
          -> Entropy entropysizeO
unscramble e passphrase =
    let ee = B.pack $ fmap (uncurry xor) $ zip (B.unpack otp) (B.unpack eraw)
     in case toEntropy @entropysizeO ee of
         Nothing -> error "unscramble: the function BIP39.toEntropy returned an unexpected error"
         Just e' -> e'
  where
    (iv, eraw) = B.splitAt ivSizeBytes (entropyRaw e)
    salt = iv <> constant
    otp = PBKDF2.fastPBKDF2_SHA512
                  (PBKDF2.Parameters iterations entropySize)
                  passphrase
                  salt
    entropySize = fromIntegral (natVal (Proxy @entropysizeO)) `div` 8
