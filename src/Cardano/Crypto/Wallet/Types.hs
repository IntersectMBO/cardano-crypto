{-# LANGUAGE PatternSynonyms #-}
{-# LANGUAGE OverloadedStrings #-}
module Cardano.Crypto.Wallet.Types
    ( ChainCode(..)
    , DerivationScheme(..)
    , pattern LatestScheme
    ) where

import           Control.DeepSeq (NFData)
import           Data.ByteArray  (ByteArrayAccess)
import           Data.ByteString (ByteString)
import           Data.Hashable   (Hashable)

import Foundation
import Foundation.Collection (nonEmpty_)
import Foundation.Check (Arbitrary(..), frequency)
import Inspector.Display
import Inspector.Parser

data DerivationScheme = DerivationScheme1 | DerivationScheme2
    deriving (Show, Eq, Ord, Enum, Bounded, Typeable)
instance Arbitrary DerivationScheme where
    arbitrary = frequency $ nonEmpty_ [ (1, pure DerivationScheme1), (1, pure DerivationScheme2) ]
instance Display DerivationScheme where
    encoding _ = "string \"derivation-scheme1\""
    display DerivationScheme1 = "\"derivation-scheme1\""
    display DerivationScheme2 = "\"derivation-scheme2\""
    comment _ = Just "valid values are: \"derivation-scheme1\" or \"derivation-scheme2\""
instance HasParser DerivationScheme where
    getParser = do
        str <- strParser
        case str of
            "derivation-scheme1" -> pure DerivationScheme1
            "derivation-scheme2" -> pure DerivationScheme2
            s                    -> reportError (Expected "derivation-scheme1 or derivation-scheme2" s)

pattern LatestScheme :: DerivationScheme
pattern LatestScheme = DerivationScheme2

newtype ChainCode = ChainCode ByteString
    deriving (Show, Eq, Ord, ByteArrayAccess, NFData, Hashable)
