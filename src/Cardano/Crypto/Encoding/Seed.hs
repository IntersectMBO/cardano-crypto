{-# LANGUAGE Rank2Types           #-}
{-# LANGUAGE DataKinds            #-}
{-# LANGUAGE KindSignatures       #-}
{-# LANGUAGE TypeFamilies         #-}
{-# LANGUAGE TypeOperators        #-}
{-# LANGUAGE TypeApplications     #-}
{-# LANGUAGE NoImplicitPrelude    #-}
{-# LANGUAGE ConstraintKinds      #-}
{-# LANGUAGE OverloadedStrings    #-}
{-# LANGUAGE ScopedTypeVariables  #-}

{-# LANGUAGE AllowAmbiguousTypes  #-}

-- | implementation of the proposal specification for Paper Wallet
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
module Cardano.Crypto.Encoding.Seed
    ( Entropy
    , Passphrase
    , MnemonicSentence
    , freeze
    , recover
    ) where

import Foundation
import Basement.Nat

import           Data.Bits (xor)
import           Data.List (zip)
import Crypto.Encoding.BIP39
import           Crypto.Hash (SHA512(..))
import qualified Crypto.KDF.PBKDF2 as PBKDF2
import Crypto.Random (MonadRandom (..))

import Data.ByteString (ByteString)
import qualified Data.ByteString as B

type IVSize = 3
ivSizeBytes :: Int
ivSizeBytes = 4

constant :: ByteString
constant = "IOHK"

iterations :: Int
iterations = 10000

-- | freeze the given mnemonic word with the given passphrase into a slightly
-- longer mnemonic sentence called _scramble words_.
--
-- The function is called 'freeze
freeze :: forall entropysizeI entropysizeO mnemonicsize scramblesize csI csO randomly
        . ( ConsistentEntropy entropysizeI mnemonicsize csI
          , ConsistentEntropy entropysizeO scramblesize csO
          , (mnemonicsize + IVSize) ~ scramblesize
          , MonadRandom randomly
          )
       => MnemonicSentence mnemonicsize
       -> Passphrase
       -> randomly (MnemonicSentence scramblesize)
freeze mnemonics passphrase = do
    iv <- getRandomBytes ivSizeBytes
    let salt = iv <> constant
    let otp = PBKDF2.generate (PBKDF2.prfHMAC SHA512)
                    (PBKDF2.Parameters iterations entropySize)
                    passphrase
                    salt
    let ee = B.pack $ fmap f $ zip (B.unpack otp) (B.unpack entropy)
    pure $ case toEntropy @entropysizeO (iv <> ee) of
        Nothing -> error "entropy generated error"
        Just e' -> entropyToWords @entropysizeO e'
  where
    f (a,b) = a `xor` b
    entropy = entropyRaw $ case wordsToEntropy @entropysizeI mnemonics of
        Nothing -> error "mnemonic to entropy failed"
        Just e  -> e
    entropySize = fromIntegral (natVal (Proxy @entropysizeI)) `div` 8

-- | recover the original mnemonic words from the scramble words (the input)
-- and the passphrase.
--
recover :: forall entropysizeI entropysizeO mnemonicsize scramblesize csI csO
         . ( ConsistentEntropy entropysizeI scramblesize csI
           , ConsistentEntropy entropysizeO mnemonicsize csO
           , (mnemonicsize + IVSize) ~ scramblesize
           )
        => MnemonicSentence scramblesize
        -> Passphrase
        -> MnemonicSentence mnemonicsize
recover scramble passphrase =
    let ee = B.pack $ fmap f $ zip (B.unpack otp) (B.unpack entropy)
     in case toEntropy @entropysizeO (iv <> ee) of
          Nothing -> error "entropy generated error"
          Just e' -> entropyToWords @entropysizeO e'
  where
    f (a,b) = a `xor` b
    (iv, entropy) = B.splitAt ivSizeBytes $ entropyRaw $ case wordsToEntropy @entropysizeI scramble of
        Nothing -> error "mnemonic to entropy failed"
        Just e  -> e
    salt = iv <> constant
    otp = PBKDF2.generate (PBKDF2.prfHMAC SHA512)
                  (PBKDF2.Parameters iterations entropySize)
                  passphrase
                  salt
    entropySize = fromIntegral (natVal (Proxy @entropysizeO)) `div` 8
