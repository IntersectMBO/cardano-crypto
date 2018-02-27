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
import Foundation.Check (Arbitrary(..))
import Inspector.Display
import Inspector.Parser

data DerivationScheme = DerivationScheme1
    deriving (Show, Eq, Ord, Enum, Bounded, Typeable)
instance Arbitrary DerivationScheme where
    arbitrary = pure DerivationScheme1
instance Display DerivationScheme where
    encoding _ = "string \"derivation-scheme1\""
    display DerivationScheme1 = "\"derivation-scheme1\""
    comment _ = Just "valid values are: \"derivation-scheme1\""
instance HasParser DerivationScheme where
    getParser = do
        str <- strParser
        case str of
            "derivation-scheme1" -> pure DerivationScheme1
            _                    -> reportError (Expected "DerivationScheme" "")

pattern LatestScheme :: DerivationScheme
pattern LatestScheme = DerivationScheme1

newtype ChainCode = ChainCode ByteString
    deriving (Show, Eq, Ord, ByteArrayAccess, NFData, Hashable)
